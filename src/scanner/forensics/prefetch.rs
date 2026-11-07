use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use std::fs;
use std::path::Path;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD,
};

pub fn scan_prefetch(report: &mut ScanReport) {
    let prefetch_dir = Path::new("C:\\Windows\\Prefetch");

    // 1. Sprawdzanie czy katalog Prefetch istnieje
    if !prefetch_dir.exists() {
        report.add(
            ScanFinding::new(
                "Missing Windows Prefetch Directory",
                FindingCategory::TamperingAndAntiForensics,
                VerdictLevel::Detection,
                "C:\\Windows\\Prefetch folder does not exist. Prefetch has been deleted or purged.",
            ),
        );
        return;
    }

    // 2. Sprawdzanie klucza rejestru EnablePrefetcher
    check_prefetch_registry(report);

    // 3. Odczyt plików Prefetch
    let entries = match fs::read_dir(prefetch_dir) {
        Ok(e) => e,
        Err(err) => {
            report.add(
                ScanFinding::new(
                    "Prefetch Read Access Denied",
                    FindingCategory::WindowsForensics,
                    VerdictLevel::Information,
                    format!("Access to C:\\Windows\\Prefetch was denied ({}) - run as Admin.", err),
                ),
            );
            return;
        }
    };

    let mut pf_count = 0;
    let suspicious_triggers = [
        "vape", "drip", "ravenbplus", "raven_b", "ravenclient", "slinky", "kura", "autoclicker",
        "dopeclicker", "vroomclicker", "inject", "cheat", "processhacker", "cheatengine",
        "string_cleaner", "vape_cleaner", "cheat_cleaner",
        "doomsday", "prestige", "imnotcheatingyouare", "marlow",
        "liquidbounce", "grimclient", "grim_client", "riseclient", "rise_client",
        "pulsarclient", "solarclient", "solar_client", "vengeance",
        "astralclient", "astral_client", "epstein", "calcium", "dclient", "dqrkis", "darkis", "trillium",
        "argonclient", "argon_client", "lvstrng", "noxx", "pulseclient", "pulse_client", "pulse-client",
        "22qq", "22qqclient", "22qq_client",
        "meraclient", "mera_client", "mera-client",
        "loader", "cleaner", "destruct", "wipe",
    ];

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("pf") {
            pf_count += 1;
            if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                let lower = file_name.to_lowercase();

                // Detekcja użycia narzędzia TASKKILL w bieżącej sesji (używane przez Clear Explorer do ubijania procesów)
                if lower.starts_with("taskkill.exe-") {
                    if let Ok(metadata) = entry.metadata() {
                        if let Ok(mtime) = metadata.modified() {
                            if super::is_system_time_in_current_session(mtime) {
                                let modified = super::format_system_time(mtime);
                                report.add(
                                    ScanFinding::new(
                                        "Taskkill Executed in Current Session (Clear Explorer / Kill Process Trace)",
                                        FindingCategory::TamperingAndAntiForensics,
                                        VerdictLevel::Detection,
                                        format!(
                                            "W pamięci Windows Prefetch odnotowano wykonanie narzędzia taskkill.exe w bieżącej sesji systemu ({}). W połączeniu z restartem powłoki stanowi to dowód na procedurę 'Clear explorer' lub ubijanie procesów loadera.",
                                            modified
                                        ),
                                    )
                                    .with_evidence("Plik Prefetch", file_name.to_string())
                                    .with_evidence("Data wykonania", modified)
                                    .with_evidence("Zastosowanie", "Ubicie procesów (np. taskkill /f /im explorer.exe)".to_string()),
                                );
                            }
                        }
                    }
                }

                // Detekcja wstrzyknięcia biblioteki sieciowej Winsock do cmd.exe / notepad.exe / calc.exe w historii Prefetch (TYLKO w bieżącej sesji systemu)
                let is_injected_host_candidate = lower.starts_with("cmd.exe-")
                    || lower.starts_with("notepad.exe-")
                    || lower.starts_with("calc.exe-");

                if is_injected_host_candidate {
                    let (modified, in_current_session) = if let Ok(metadata) = entry.metadata() {
                        if let Ok(mtime) = metadata.modified() {
                            (super::format_system_time(mtime), super::is_system_time_in_current_session(mtime))
                        } else {
                            ("Unknown".to_string(), false)
                        }
                    } else {
                        ("Unknown".to_string(), false)
                    };

                    if in_current_session && check_prefetch_for_winsock(&path) {
                        let proc_name = if lower.starts_with("cmd.exe-") {
                            "cmd.exe"
                        } else if lower.starts_with("notepad.exe-") {
                            "notepad.exe"
                        } else {
                            "calc.exe"
                        };
                        report.add(
                            ScanFinding::new(
                                format!("App Has Suspicious Data Usage (Possible PE Injection/Bypass Related): {}", proc_name),
                                FindingCategory::WindowsForensics,
                                VerdictLevel::Detection,
                                format!(
                                    "W pamięci podręcznej Windows Prefetch dla pliku {} w bieżącej sesji odnotowano załadowanie biblioteki sieciowej WS2_32.DLL. Czysty proces {} nie korzysta z sieci – stanowi to dowód na PE Injection / Process Hollowing.",
                                    file_name, proc_name
                                ),
                            )
                            .with_evidence("Prefetch File", file_name.to_string())
                            .with_evidence("Wskaźnik PE Injection", format!("Załadowany moduł sieciowy WS2_32.DLL w procesie {}", proc_name))
                            .with_evidence("Data wykonania w bieżącej sesji", modified),
                        );
                    }
                }

                // Pomiń zaufane procesy i instalatory antycheatów (np. EasyAntiCheat, BattlEye)
                if super::is_whitelisted_executable(&lower) {
                    continue;
                }

                for trigger in &suspicious_triggers {
                    if super::is_cheat_keyword_match(&lower, trigger) {
                        let (modified, in_current_session) = if let Ok(metadata) = entry.metadata() {
                            if let Ok(mtime) = metadata.modified() {
                                (super::format_system_time(mtime), super::is_system_time_in_current_session(mtime))
                            } else {
                                ("Unknown".to_string(), false)
                            }
                        } else {
                            ("Unknown".to_string(), false)
                        };

                        // Ignoruj historyczne pliki Prefetch sprzed restartu PC
                        if !in_current_session {
                            break;
                        }

                        let title = "Active Cheat Executable in Current Session (Prefetch)";
                        let verdict = VerdictLevel::Detection;
                        let scope_desc = "Bieżąca sesja systemu (uruchomiony PO starcie PC)";

                        report.add(
                            ScanFinding::new(
                                title,
                                FindingCategory::WindowsForensics,
                                verdict,
                                format!("Windows Prefetch recorded execution of: {}", file_name),
                            )
                            .with_evidence("Prefetch File", file_name.to_string())
                            .with_evidence("Session Scope", scope_desc.to_string())
                            .with_evidence("Last Run / Modified", modified),
                        );
                        break;
                    }
                }
            }
        }
    }

    if pf_count < 10 {
        report.add(
            ScanFinding::new(
                "Prefetch Wiped or Abnormally Empty",
                FindingCategory::TamperingAndAntiForensics,
                VerdictLevel::Detection,
                format!("Only {} prefetch files found. Windows typically maintains hundreds. Likely recently cleared.", pf_count),
            )
            .with_evidence("Prefetch File Count", pf_count.to_string()),
        );
    }
}

fn check_prefetch_registry(report: &mut ScanReport) {
    let subkey: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters\0"
        .encode_utf16()
        .collect();

    unsafe {
        let mut hkey = std::ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        ) == 0
        {
            let val_name: Vec<u16> = "EnablePrefetcher\0".encode_utf16().collect();
            let mut val_type = 0u32;
            let mut val_data = 0u32;
            let mut val_size = std::mem::size_of::<u32>() as u32;

            if RegQueryValueExW(
                hkey,
                val_name.as_ptr(),
                std::ptr::null_mut(),
                &mut val_type,
                &mut val_data as *mut _ as *mut u8,
                &mut val_size,
            ) == 0
            {
                if val_type == REG_DWORD && val_data == 0 {
                    report.add(
                        ScanFinding::new(
                            "EnablePrefetcher Disabled in Registry",
                            FindingCategory::TamperingAndAntiForensics,
                            VerdictLevel::Detection,
                            "EnablePrefetcher value is set to 0. Windows prefetching has been disabled to prevent execution tracking.",
                        )
                        .with_evidence("Registry Value", val_data.to_string()),
                    );
                }
            }
            RegCloseKey(hkey);
        }
    }
}

fn check_prefetch_for_winsock(path: &Path) -> bool {
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(_) => return false,
    };

    if data.starts_with(b"MAM\x04") {
        if let Some(decompressed) = decompress_mam_prefetch(&data) {
            return contains_winsock_needle(&decompressed);
        }
    }
    contains_winsock_needle(&data)
}

fn contains_winsock_needle(data: &[u8]) -> bool {
    let needle_ascii = b"ws2_32.dll";
    let needle_utf16: [u8; 20] = [
        b'w', 0, b's', 0, b'2', 0, b'_', 0, b'3', 0, b'2', 0, b'.', 0, b'd', 0, b'l', 0, b'l', 0,
    ];
    let lower_data: Vec<u8> = data.iter().map(|b| b.to_ascii_lowercase()).collect();
    lower_data.windows(needle_ascii.len()).any(|w| w == needle_ascii)
        || lower_data.windows(needle_utf16.len()).any(|w| w == needle_utf16)
}

type RtlDecompressBufferFn = unsafe extern "system" fn(
    compression_format: u16,
    uncompressed_buffer: *mut u8,
    uncompressed_buffer_size: u32,
    compressed_buffer: *const u8,
    compressed_buffer_size: u32,
    final_uncompressed_size: *mut u32,
) -> i32;

fn decompress_mam_prefetch(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 || &data[..4] != b"MAM\x04" {
        return None;
    }
    let uncompressed_size = u32::from_le_bytes(data[4..8].try_into().ok()?);
    if uncompressed_size == 0 || uncompressed_size > 5 * 1024 * 1024 {
        return None;
    }

    unsafe {
        let ntdll = windows_sys::Win32::System::LibraryLoader::LoadLibraryA(b"ntdll.dll\0".as_ptr());
        if ntdll.is_null() {
            return None;
        }

        let p_decomp = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            ntdll,
            b"RtlDecompressBuffer\0".as_ptr(),
        );

        let mut output = vec![0u8; uncompressed_size as usize];
        let mut final_size = 0u32;
        let mut success = false;

        if let Some(func) = p_decomp {
            let rtl_decompress: RtlDecompressBufferFn = std::mem::transmute(func);
            let res = rtl_decompress(
                0x0104, // COMPRESSION_FORMAT_XPRESS_HUFF | COMPRESSION_ENGINE_STANDARD
                output.as_mut_ptr(),
                uncompressed_size,
                data[8..].as_ptr(),
                (data.len() - 8) as u32,
                &mut final_size,
            );
            if res == 0 {
                success = true;
            } else {
                let res2 = rtl_decompress(
                    4, // COMPRESSION_FORMAT_XPRESS_HUFF
                    output.as_mut_ptr(),
                    uncompressed_size,
                    data[8..].as_ptr(),
                    (data.len() - 8) as u32,
                    &mut final_size,
                );
                if res2 == 0 {
                    success = true;
                }
            }
        }

        windows_sys::Win32::Foundation::FreeLibrary(ntdll);

        if success {
            Some(output)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_winsock_needle() {
        let ascii_data = b"Some loaded modules: KERNEL32.DLL, WS2_32.DLL, NTDLL.DLL";
        assert!(contains_winsock_needle(ascii_data));

        let mut utf16_data = Vec::new();
        for &b in b"\\Device\\HarddiskVolume3\\Windows\\System32\\ws2_32.dll" {
            utf16_data.push(b);
            utf16_data.push(0);
        }
        assert!(contains_winsock_needle(&utf16_data));

        let clean_data = b"\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe";
        assert!(!contains_winsock_needle(clean_data));
    }
}
