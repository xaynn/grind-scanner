use std::ffi::c_void;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Threading::GetCurrentThread;

type NtSetInformationThreadFn = unsafe extern "system" fn(
    thread_handle: HANDLE,
    thread_information_class: u32,
    thread_information: *const c_void,
    thread_information_length: u32,
) -> i32;

type SetProcessMitigationPolicyFn = unsafe extern "system" fn(
    mitigation_policy: i32,
    lp_buffer: *const c_void,
    dw_length: usize,
) -> i32;

const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11;
const PROCESS_SIGNATURE_POLICY: i32 = 8;

#[repr(C)]
struct ProcessMitigationBinarySignaturePolicy {
    flags: u32,
}

/// Aktywuje zabezpieczenia anti-tampering i anti-bypass dla procesu skanera
pub fn apply_all_hardening() {
    // 0. Natychmiastowe sprawdzenie obecności debugera (jeśli wykryto -> natychmiastowy crash)
    crate::security::anti_analysis::crash_if_debugged();

    // 1. Ukryj bieżący wątek przed debugerami jądra i usermode
    hide_current_thread_from_debugger();

    // 2. Pułapka Anti-Attach: podmień DbgUiRemoteBreakin i DbgBreakPoint na UD2 (Crash przy próbie dołączenia debugera)
    neutralize_debugger_attach();

    // 3. Włącz politykę bezpieczeństwa procesu (blokada wstrzykiwania obcych niepodpisanych DLL)
    enable_process_mitigation();

    // 4. Uruchom wątek strażnika (Watchdog) weryfikujący obecność debugera co 200ms
    crate::security::anti_analysis::start_anti_debug_watchdog();
}

/// Neutralizuje próby podpięcia zewnętrznych debugerów (x64dbg, Cheat Engine, Visual Studio) do działającego procesu.
/// Kiedy debuger wywołuje DebugActiveProcess, jądro Windows wstrzykuje do naszego procesu wątek
/// wykonujący ntdll!DbgUiRemoteBreakin / ntdll!DbgBreakPoint.
/// Zastępujemy początek tych funkcji instrukcją UD2 (0x0F 0x0B - Invalid Opcode).
/// Każda próba podpięcia debugera natychmiast wywoła crash procesu (STATUS_ILLEGAL_INSTRUCTION),
/// uniemożliwiając zrzut pamięci i inspekcję skanera.
pub fn neutralize_debugger_attach() {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return;
        }

        let targets = [
            b"DbgUiRemoteBreakin\0".as_ptr(),
            b"DbgBreakPoint\0".as_ptr(),
        ];

        for &target in &targets {
            let func_ptr = GetProcAddress(ntdll, target);
            if let Some(proc) = func_ptr {
                let mut old_protect = 0u32;
                if windows_sys::Win32::System::Memory::VirtualProtect(
                    proc as *const c_void,
                    2,
                    windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                ) != 0
                {
                    let code = proc as *mut u8;
                    // UD2: 0x0F 0x0B (nieobsługiwany rozkaz procesora x86/x64 -> unrecoverable crash)
                    *code = 0x0F;
                    *code.add(1) = 0x0B;

                    let mut dummy = 0u32;
                    windows_sys::Win32::System::Memory::VirtualProtect(
                        proc as *const c_void,
                        2,
                        old_protect,
                        &mut dummy,
                    );
                }
            }
        }
    }
}

/// Wywołuje nieudokumentowane NtSetInformationThread(ThreadHideFromDebugger),
/// powodując, że debugery (x64dbg, Cheat Engine) nie są w stanie przechwycić wątku skanera.
pub fn hide_current_thread_from_debugger() -> bool {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return false;
        }

        let func_ptr = GetProcAddress(ntdll, b"NtSetInformationThread\0".as_ptr());
        if let Some(func) = func_ptr {
            let nt_set_info: NtSetInformationThreadFn = std::mem::transmute(func);
            let status = nt_set_info(
                GetCurrentThread(),
                THREAD_HIDE_FROM_DEBUGGER,
                std::ptr::null(),
                0,
            );
            status == 0
        } else {
            false
        }
    }
}

/// Wymusza podpisywanie ładowanych bibliotek DLL (MicrosoftSignedOnly),
/// uniemożliwiając wstrzyknięcie złośliwej DLL do skanera w celu sfałszowania wyników.
pub fn enable_process_mitigation() -> bool {
    unsafe {
        let kernel32 = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if kernel32.is_null() {
            return false;
        }

        let func_ptr = GetProcAddress(kernel32, b"SetProcessMitigationPolicy\0".as_ptr());
        if let Some(func) = func_ptr {
            let set_policy: SetProcessMitigationPolicyFn = std::mem::transmute(func);

            // MicrosoftSignedOnly = 1 (bit 0)
            let policy = ProcessMitigationBinarySignaturePolicy { flags: 1 };
            let result = set_policy(
                PROCESS_SIGNATURE_POLICY,
                &policy as *const _ as *const c_void,
                std::mem::size_of::<ProcessMitigationBinarySignaturePolicy>(),
            );
            result != 0
        } else {
            false
        }
    }
}

/// Sprawdza czy funkcja w pamięci procesu nie została spatchowana instrukcją skoku (0xE9 JMP)
/// lub pułapką debugera (0xCC INT 3).
#[allow(dead_code)]
pub fn is_function_hooked(func_ptr: *const ()) -> bool {
    if func_ptr.is_null() {
        return false;
    }
    unsafe {
        let byte = *(func_ptr as *const u8);
        byte == 0xCC || byte == 0xE9
    }
}
