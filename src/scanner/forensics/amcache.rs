use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn scan_amcache(report: &mut ScanReport) {
    let amcache_path = r"C:\Windows\appcompat\Programs\Amcache.hve";

    // Attempt to open the file with sharing flags
    let file_result = open_amcache_file(amcache_path);

    let mut file = match file_result {
        Ok(f) => f,
        Err(_) => {
            report.add(
                ScanFinding::new(
                    "Amcache.hve Forensics (Requires Administrator)",
                    FindingCategory::WindowsForensics,
                    VerdictLevel::Information,
                    "Odczyt bazy Amcache.hve (rejestr kompatybilności aplikacji) wymaga uruchomienia skanera z uprawnieniami administratora (SeBackupPrivilege).",
                )
                .with_evidence("Ścieżka pliku", amcache_path.to_string()),
            );
            return;
        }
    };

    // Odczytujemy do 64 MB bazy Amcache
    let mut buffer = Vec::new();
    let mut chunk = vec![0u8; 1024 * 1024]; // 1MB bloki
    let mut total_read = 0usize;
    const MAX_READ: usize = 64 * 1024 * 1024;

    while total_read < MAX_READ {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buffer.extend_from_slice(&chunk[..n]);
                total_read += n;
            }
            Err(_) => break,
        }
    }

    if buffer.len() < 4 || &buffer[0..4] != b"regf" {
        return;
    }

    let cheat_keywords = [
        "vape", "drip", "doomsday", "slinky", "cleaner", "selfdestruct", "destruct",
        "loader", "injector", "bypass", "hitbox", "autoclicker", "reach",
        "clicker", "kura", "mera", "raven", "liquidbounce", "ghostclient",
    ];

    let mut reported_paths = HashSet::new();
    let mut findings_count = 0usize;

        // Scan extracted UTF-16LE and UTF-8 strings from Amcache registry cells
    let extracted_paths = extract_amcache_paths(&buffer);

    for path_str in extracted_paths {
        let lower = path_str.to_lowercase();

            // Check if this is an .exe or .jar file
        let is_executable = lower.ends_with(".exe") || lower.ends_with(".jar");
        if !is_executable {
            continue;
        }

        let file_path = Path::new(&path_str);
        let file_name = match file_path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => continue,
        };
        let lower_file_name = file_name.to_lowercase();

                // 1. Check if the filename matches cheat keywords
        let mut matched_keyword = None;
        for kw in &cheat_keywords {
            if super::is_cheat_keyword_match(&lower_file_name, kw) {
                matched_keyword = Some(*kw);
                break;
            }
        }

                // 2. Check if an .jar file was executed from Temp / Downloads / Desktop
        let is_suspicious_jar = lower.ends_with(".jar")
            && (lower.contains(r"\appdata\local\temp\") || lower.contains(r"\downloads\") || lower.contains(r"\desktop\"));

                    // Check if the file or its Prefetch trace was active in the CURRENT system session (since last PC boot)
        let file_exists = file_path.exists();
        let mut in_current_session = false;
        let mut time_str = None;

        if file_exists {
            if let Ok(meta) = std::fs::metadata(file_path) {
                for t in [meta.modified().ok(), meta.accessed().ok(), meta.created().ok()].into_iter().flatten() {
                    if super::is_system_time_in_current_session(t) {
                        in_current_session = true;
                        time_str = Some(super::format_system_time(t));
                        break;
                    }
                }
            }
        }

                    // Correlate with Windows Prefetch cache
        if !in_current_session {
            if let Some((pf_ft, is_curr_sess)) = super::check_prefetch_for_executable(file_name) {
                if is_curr_sess {
                    in_current_session = true;
                    time_str = super::format_filetime(pf_ft);
                }
            }
        }

        // Ignore historical Amcache entries from before the last PC reboot
        if !in_current_session {
            continue;
        }

                // Check for system process masquerading (e.g. Desktop\svchost.exe) in Amcache
        if let Some(fake_name) = super::is_fake_system_executable(&path_str) {
            if reported_paths.insert(path_str.clone()) {
                report.add(
                    ScanFinding::new(
                        "Masqueraded System Process in Current Session (Amcache)",
                        FindingCategory::WindowsForensics,
                        VerdictLevel::Detection,
                        format!("Baza Amcache.hve zarejestrowała wykonanie sfałszowanego procesu systemowego '{}' w bieżącej sesji: {}", fake_name, path_str),
                    )
                    .with_evidence("Ścieżka pliku (Amcache)", path_str.clone())
                    .with_evidence("Podszywanie pod proces", fake_name.to_string())
                    .with_evidence("Czas aktywności w bieżącej sesji", time_str.clone().unwrap_or_else(|| "Bieżąca sesja".to_string())),
                );
            }
            continue;
        }

        if let Some(kw) = matched_keyword {
            if reported_paths.insert(path_str.clone()) {
                let status_disk = if file_exists {
                    "Plik nadal obecny na dysku"
                } else {
                    "Plik USUNIĘTY z dysku po wykonaniu w bieżącej sesji (Anti-Forensics / Self-Destruct)"
                };

                let mut finding = ScanFinding::new(
                    format!("Cheat Traced in Amcache.hve Forensics (Current Session): {}", file_name),
                    FindingCategory::WindowsForensics,
                    VerdictLevel::Detection,
                    format!(
                        "Baza kompatybilności Windows Amcache.hve zarejestrowała wykonanie narzędzia/cheata w bieżącej sesji systemu: {}. {}",
                        path_str, status_disk
                    ),
                )
                .with_evidence("Ścieżka pliku (Amcache)", path_str.clone())
                .with_evidence("Nazwa pliku", file_name.to_string())
                .with_evidence("Dopasowany wzorzec", kw.to_string())
                .with_evidence("Status na dysku", status_disk.to_string())
                .with_evidence("Sesja", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
                .with_evidence("Baza dowodowa", "C:\\Windows\\appcompat\\Programs\\Amcache.hve".to_string());

                if let Some(ref t) = time_str {
                    finding = finding.with_evidence("Czas aktywności", t.clone());
                }

                report.add(finding);
                findings_count += 1;
            }
        } else if is_suspicious_jar && reported_paths.insert(path_str.clone()) {
            if !file_exists {
                let mut finding = ScanFinding::new(
                    format!("Deleted Loader JAR Traced in Amcache.hve (Current Session): {}", file_name),
                    FindingCategory::WindowsForensics,
                    VerdictLevel::Detection,
                    format!(
                        "Baza Amcache.hve zarejestrowała wykonanie pliku .jar w bieżącej sesji z katalogu tymczasowego/użytkownika, który został usunięty z dysku: {}.",
                        path_str
                    ),
                )
                .with_evidence("Ścieżka pliku (Amcache)", path_str.clone())
                .with_evidence("Nazwa pliku", file_name.to_string())
                .with_evidence("Status", "Usunięty plik .jar w bieżącej sesji (Self-Destruct)".to_string())
                .with_evidence("Sesja", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
                .with_evidence("Baza dowodowa", "C:\\Windows\\appcompat\\Programs\\Amcache.hve".to_string());

                if let Some(ref t) = time_str {
                    finding = finding.with_evidence("Czas aktywności", t.clone());
                }

                report.add(finding);
                findings_count += 1;
            }
        }

        if findings_count >= 50 {
            break;
        }
    }
}

/// Safely opens Amcache.hve using WinAPI CreateFileW with BACKUP_SEMANTICS flags
fn open_amcache_file(path_str: &str) -> std::io::Result<File> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let path_w: Vec<u16> = format!("{}\0", path_str).encode_utf16().collect();
    unsafe {
        let handle = CreateFileW(
            path_w.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        );

        if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        Ok(File::from_raw_handle(handle as *mut std::ffi::c_void))
    }
}

/// Extracts Windows file paths from raw bytes of the Amcache.hve registry file
pub fn extract_amcache_paths(buffer: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    // 1. Extract UTF-16LE strings starting with a drive letter (e.g. C:\)
    let len = buffer.len();
    let mut i = 0;
    while i + 8 < len {
        // Check if this is "C:\" in UTF-16LE: [b'C', 0, b':', 0, b'\\', 0]
        let b0 = buffer[i];
        let b1 = buffer[i + 1];
        let b2 = buffer[i + 2];
        let b3 = buffer[i + 3];
        let b4 = buffer[i + 4];
        let b5 = buffer[i + 5];

        let is_drive_start = b0.is_ascii_alphabetic()
            && b1 == 0
            && b2 == b':'
            && b3 == 0
            && b4 == b'\\'
            && b5 == 0;

        if is_drive_start {
        // Read UTF-16LE string until null terminator or non-printable character
            let mut u16_chars = Vec::new();
            let mut j = i;
            while j + 1 < len {
                let lo = buffer[j];
                let hi = buffer[j + 1];
                let ch = (hi as u16) << 8 | (lo as u16);
                if ch == 0 || ch < 0x20 || ch > 0x7E {
                    break;
                }
                u16_chars.push(ch);
                j += 2;
                if u16_chars.len() >= 260 {
                    break;
                }
            }

            if u16_chars.len() >= 6 {
                let path = String::from_utf16_lossy(&u16_chars);
                let lower = path.to_lowercase();
                if (lower.ends_with(".exe") || lower.ends_with(".jar")) && seen.insert(path.clone()) {
                    results.push(path);
                }
            }
            i = j;
        } else {
            i += 2;
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_amcache_paths_utf16() {
        let sample = "C:\\Users\\dzony\\Downloads\\vape_v4.exe\0";
        let u16_bytes: Vec<u8> = sample.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();

        let mut buf = vec![0u8; 16];
        buf.extend_from_slice(&u16_bytes);
        buf.extend_from_slice(&[0u8; 16]);

        let paths = extract_amcache_paths(&buf);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "C:\\Users\\dzony\\Downloads\\vape_v4.exe");
    }
}
