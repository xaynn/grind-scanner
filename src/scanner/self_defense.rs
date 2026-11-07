use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};

/// Sprawdza czy krytyczne funkcje WinAPI w procesie skanera nie zostały spatchowane (Inline Hook / JMP)
/// przez złośliwe oprogramowanie, cheat lub injector wstrzyknięty w tle.
pub fn check_scanner_integrity(report: &mut ScanReport) {
    // Sprawdź czy ktoś nie podpiął debugera
    crate::security::anti_analysis::crash_if_debugged();
    check_winapi_inline_hooks(report);
    check_timing_anomalies(report);
}

struct ApiHookTarget {
    dll_name: &'static str,
    fn_name: &'static str,
    is_ntdll_syscall: bool,
}

fn check_winapi_inline_hooks(report: &mut ScanReport) {
    let targets = [
        // NTDLL krytyczne syscalls
        ApiHookTarget { dll_name: "ntdll.dll", fn_name: "NtReadVirtualMemory", is_ntdll_syscall: true },
        ApiHookTarget { dll_name: "ntdll.dll", fn_name: "NtQueryVirtualMemory", is_ntdll_syscall: true },
        ApiHookTarget { dll_name: "ntdll.dll", fn_name: "NtOpenProcess", is_ntdll_syscall: true },
        ApiHookTarget { dll_name: "ntdll.dll", fn_name: "NtQueryInformationProcess", is_ntdll_syscall: true },
        // KERNEL32 / KERNELBASE
        ApiHookTarget { dll_name: "kernel32.dll", fn_name: "ReadProcessMemory", is_ntdll_syscall: false },
        ApiHookTarget { dll_name: "kernel32.dll", fn_name: "VirtualQueryEx", is_ntdll_syscall: false },
        ApiHookTarget { dll_name: "kernel32.dll", fn_name: "OpenProcess", is_ntdll_syscall: false },
        // ADVAPI32
        ApiHookTarget { dll_name: "advapi32.dll", fn_name: "RegOpenKeyExW", is_ntdll_syscall: false },
        ApiHookTarget { dll_name: "advapi32.dll", fn_name: "RegQueryValueExW", is_ntdll_syscall: false },
    ];

    for target in &targets {
        let dll_w = format!("{}\0", target.dll_name);
        let fn_w = format!("{}\0", target.fn_name);

        unsafe {
            let mut h_mod = GetModuleHandleA(dll_w.as_ptr());
            if h_mod.is_null() {
                h_mod = LoadLibraryA(dll_w.as_ptr());
            }
            if h_mod.is_null() {
                continue;
            }

            let proc_addr = GetProcAddress(h_mod, fn_w.as_ptr());
            if let Some(proc_ptr) = proc_addr {
                let code_ptr = proc_ptr as *const u8;
                let mut bytes = [0u8; 16];
                std::ptr::copy_nonoverlapping(code_ptr, bytes.as_mut_ptr(), 16);

                let is_hooked = detect_hook_instructions(&bytes, target.is_ntdll_syscall);
                if is_hooked {
                    let hex_bytes = bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
                    report.add(
                        ScanFinding::new(
                            format!("Scanner Self-Defense Alert: Inline Hook Detected ({})", target.fn_name),
                            FindingCategory::TamperingAndAntiForensics,
                            VerdictLevel::Detection,
                            format!(
                                "Wykryto nieautoryzowaną modyfikację pamięci procesu skanera (Inline JMP Hook) w funkcji {}!{}. Oprogramowanie cheatujące lub zewnętrzny moduł próbuje ukryć dowody i fałszować odczyty pamięci/rejestru (Anti-Analysis / Bypass).",
                                target.fn_name, target.dll_name
                            ),
                        )
                        .with_evidence("Funkcja docelowa", format!("{}!{}", target.dll_name, target.fn_name))
                        .with_evidence("Adres funkcji w pamięci", format!("0x{:X}", proc_ptr as usize))
                        .with_evidence("Pierwsze bajty instrukcji (Prolog)", hex_bytes)
                        .with_evidence("Wektor zagrożenia", "User-Mode API Detour Hook (Anti-Scanner)".to_string()),
                    );
                }
            }
        }
    }
}

/// Analizuje bajty prologu funkcji x86_64 pod kątem instrukcji skoku (JMP detour)
pub fn detect_hook_instructions(bytes: &[u8; 16], is_ntdll_syscall: bool) -> bool {
    let b0 = bytes[0];
    let b1 = bytes[1];

    // 1. Bezpośredni JMP rel32 (0xE9)
    if b0 == 0xE9 {
        return true;
    }

    // 2. Krótki JMP rel8 (0xEB)
    if b0 == 0xEB {
        return true;
    }

    // 3. Pośredni skok JMP QWORD PTR [rip + disp32] (0xFF 0x25) - standard MinHook / Detours x64
    if b0 == 0xFF && b1 == 0x25 {
        return true;
    }

    // 4. MOV RAX, imm64; JMP RAX (48 B8 xx xx xx xx xx xx xx xx FF E0)
    if b0 == 0x48 && b1 == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0 {
        return true;
    }

    // 5. MOV R11, imm64; JMP R11 (49 BB xx xx xx xx xx xx xx xx 41 FF E3)
    if b0 == 0x49 && b1 == 0xBB && bytes[10] == 0x41 && bytes[11] == 0xFF && bytes[12] == 0xE3 {
        return true;
    }

    // 6. Breakpoint INT 3 (0xCC) w prologu
    if b0 == 0xCC {
        return true;
    }

    // 7. W ntdll syscall stub x64 standardowy kod to:
    //    4C 8B D1          mov r10, rcx
    //    B8 xx xx 00 00    mov eax, <syscall_number>
    // Jeśli ntdll zaczyna się od czegokolwiek innego, jest to modyfikacja
    if is_ntdll_syscall {
        let is_standard_syscall = (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8)
            || (bytes[0] == 0xB8 && bytes[3] == 0x00 && bytes[4] == 0x00); // Niektóre wersje Win11
        if !is_standard_syscall {
            return true;
        }
    }

    false
}

/// Sprawdza czy nie występują drastyczne rozbieżności pomiędzy zegarami systemowymi a licznikiem sprzętowym QPC
fn check_timing_anomalies(report: &mut ScanReport) {
    unsafe {
        let tick1 = windows_sys::Win32::System::SystemInformation::GetTickCount64();
        let mut qpc1 = 0i64;
        let mut qpc_freq = 0i64;
        windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut qpc_freq);
        windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut qpc1);

        // Krótkie opóźnienie CPU
        std::thread::sleep(std::time::Duration::from_millis(15));

        let tick2 = windows_sys::Win32::System::SystemInformation::GetTickCount64();
        let mut qpc2 = 0i64;
        windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut qpc2);

        if qpc_freq > 0 {
            let qpc_elapsed_ms = ((qpc2 - qpc1) * 1000) / qpc_freq;
            let tick_elapsed_ms = tick2.saturating_sub(tick1) as i64;

            // Jeśli różnica przekracza 500 ms przy 15 ms uśpieniu, zegar jest sztucznie manipulowany
            let diff = (qpc_elapsed_ms - tick_elapsed_ms).abs();
            if diff > 500 {
                report.add(
                    ScanFinding::new(
                        "Timing Anomaly / Clock Manipulation Detected",
                        FindingCategory::TamperingAndAntiForensics,
                        VerdictLevel::Warning,
                        format!(
                            "Wykryto nienaturalną dysproporcję między licznikiem wydajności (QPC: {} ms) a zegarem systemowym (GetTickCount: {} ms). Wskazuje to na zamrażanie wątków lub manipulację czasem procesu.",
                            qpc_elapsed_ms, tick_elapsed_ms
                        ),
                    )
                    .with_evidence("Czas QPC", format!("{} ms", qpc_elapsed_ms))
                    .with_evidence("Czas GetTickCount", format!("{} ms", tick_elapsed_ms)),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_hook_instructions() {
        // Zwykły syscall ntdll (4C 8B D1 B8 18 00 00 00)
        let normal_ntdll = [0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90];
        assert!(!detect_hook_instructions(&normal_ntdll, true));

        // JMP rel32 (E9 40 12 00 00)
        let jmp_hook = [0xE9, 0x40, 0x12, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        assert!(detect_hook_instructions(&jmp_hook, false));
        assert!(detect_hook_instructions(&jmp_hook, true));

        // MinHook indirect JMP (FF 25 00 00 00 00)
        let minhook = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x90, 0x90];
        assert!(detect_hook_instructions(&minhook, false));
        assert!(detect_hook_instructions(&minhook, true));

        // INT 3 Breakpoint
        let breakpoint = [0xCC, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90];
        assert!(detect_hook_instructions(&breakpoint, false));
    }
}
