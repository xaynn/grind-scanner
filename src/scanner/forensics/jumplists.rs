use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use crate::scanner::forensics::{
    format_system_time, is_cheat_keyword_match, is_fake_system_executable,
    is_system_time_in_current_session, is_whitelisted_executable,
};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Scans Windows Shell Jump List databases (AutomaticDestinations and CustomDestinations)
/// for traces of cheat, cleaner, and loader executions.
pub fn scan_jump_lists(report: &mut ScanReport) {
    let appdata = match std::env::var("APPDATA") {
        Ok(v) => v,
        Err(_) => return,
    };

    let base_recent = PathBuf::from(&appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Recent");

    let target_dirs = [
        base_recent.join("AutomaticDestinations"),
        base_recent.join("CustomDestinations"),
    ];

    let cheat_keywords = [
        "vape", "slinky", "drip", "kura", "entropy", "doomsday", "prestige",
        "liquidbounce", "grimclient", "pulsarclient", "solarclient", "vengeance",
        "astralclient", "epstein", "calcium", "dclient", "dqrkis", "argonclient",
        "noxx", "pulseclient", "22qq", "meraclient", "autoclicker", "destruct",
        "selfdestruct", "stringcleaner",
    ];

    let mut reported_paths = std::collections::HashSet::new();

    for dir in &target_dirs {
        if !dir.exists() {
            continue;
        }

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let is_dest = path.extension().and_then(|e| e.to_str()).map_or(false, |ext| {
                ext.eq_ignore_ascii_case("automaticDestinations-ms")
                    || ext.eq_ignore_ascii_case("customDestinations-ms")
            });

            if !is_dest {
                continue;
            }

    // Read binary OLE JumpList file contents (up to 8 MB)
            let mut file = match File::open(&path) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let mut buffer = Vec::new();
            if file.read_to_end(&mut buffer).is_err() || buffer.len() < 16 {
                continue;
            }

            let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
            let db_mtime_formatted = entry.metadata().ok().and_then(|m| m.modified().ok()).map(format_system_time);

    // Extract paths from UTF-16LE and ASCII bytes
            let extracted_paths = extract_jump_list_paths(&buffer);

            for extracted in extracted_paths {
                let lower = extracted.to_lowercase();

                if is_whitelisted_executable(&lower) {
                    continue;
                }

                if let Some(fake_name) = is_fake_system_executable(&extracted) {
                    if reported_paths.insert(lower.clone()) {
                        report.add(
                            ScanFinding::new(
                                "Masqueraded System Process in Jump Lists",
                                FindingCategory::WindowsForensics,
                                VerdictLevel::Detection,
                                format!("Baza Jump Lists zarejestrowała dostęp do sfałszowanego procesu systemowego '{}': {}", fake_name, extracted),
                            )
                            .with_evidence("Zarejestrowana ścieżka", extracted.clone())
                            .with_evidence("Podszywanie pod proces", fake_name.to_string())
                            .with_evidence("Plik bazy JumpList", file_name.clone()),
                        );
                    }
                    continue;
                }

                for kw in &cheat_keywords {
                    // Token boundary verification (prevents false-positives e.g. "weedclient" -> "dclient")
                    if is_cheat_keyword_match(&lower, kw) {
                        if !reported_paths.insert(lower.clone()) {
                            break;
                        }

                        let target_path = Path::new(&extracted);
                        let file_exists = target_path.exists();

                        if file_exists {
                            // File PHYSICALLY EXISTS on disk
                            let mut in_current_session = false;
                            let mut file_time_formatted = None;

                            if let Ok(meta) = fs::metadata(target_path) {
                                for t in [meta.modified().ok(), meta.accessed().ok(), meta.created().ok()].into_iter().flatten() {
                                    if is_system_time_in_current_session(t) {
                                        in_current_session = true;
                                        file_time_formatted = Some(format_system_time(t));
                                        break;
                                    }
                                }
                            }

                            if in_current_session {
                                report.add(
                                    ScanFinding::new(
                                        format!("Active Cheat File on Disk (Jump List Trace): {}", kw),
                                        FindingCategory::WindowsForensics,
                                        VerdictLevel::Detection,
                                        format!(
                                            "Baza list szybkiego dostępu (Jump Lists) oraz system plików potwierdziły obecność i aktywność pliku cheata na dysku w bieżącej sesji: {}.",
                                            extracted
                                        ),
                                    )
                                    .with_evidence("Zarejestrowana ścieżka", extracted.clone())
                                    .with_evidence("Status pliku na dysku", "Istnieje na dysku (aktywny w bieżącej sesji)".to_string())
                                    .with_evidence("Czas aktywności pliku", file_time_formatted.unwrap_or_else(|| "Bieżąca sesja".to_string()))
                                    .with_evidence("Plik bazy JumpList", file_name.clone())
                                    .with_evidence("Wykryte słowo kluczowe", kw.to_string()),
                                );
                            } else {
                                report.add(
                                    ScanFinding::new(
                                        format!("Historical Cheat File Found on Disk (Jump List Reference): {}", kw),
                                        FindingCategory::WindowsForensics,
                                        VerdictLevel::Warning,
                                        format!(
                                            "Plik powiązany z cheatem został odnaleziony na dysku i widnieje w listach szybkiego dostępu (Jump Lists), lecz nie wykazuje aktywności w bieżącej sesji: {}.",
                                            extracted
                                        ),
                                    )
                                    .with_evidence("Zarejestrowana ścieżka", extracted.clone())
                                    .with_evidence("Status pliku na dysku", "Istnieje na dysku (brak aktywności w bieżącej sesji)".to_string())
                                    .with_evidence("Plik bazy JumpList", file_name.clone())
                                    .with_evidence("Wykryte słowo kluczowe", kw.to_string()),
                                );
                            }
                        } else {
            // File DOES NOT EXIST ON DISK (previously deleted).
            // Jump Lists retain MRU entries for weeks. This entry is historical and cannot be qualified as Detection in current session.
                            report.add(
                                ScanFinding::new(
                                    format!("Historical Reference to Deleted Cheat in Windows Jump Lists: {}", kw),
                                    FindingCategory::WindowsForensics,
                                    VerdictLevel::Warning,
                                    format!(
                                        "Baza list szybkiego dostępu powłoki (Windows Jump Lists) zawiera historyczne odwołanie do pliku cheata, który został wcześniej usunięty z dysku: {}.",
                                        extracted
                                    ),
                                )
                                .with_evidence("Zarejestrowana ścieżka", extracted.clone())
                                .with_evidence("Status pliku na dysku", "Usunięty (brak pliku na dysku)".to_string())
                                .with_evidence("Kwalifikacja", "Historyczny artefakt powłoki Windows (plik usunięty w przeszłości)".to_string())
                                .with_evidence("Plik bazy JumpList", file_name.clone())
                                .with_evidence(
                                    "Ostatnia modyfikacja bazy JumpList",
                                    db_mtime_formatted.clone().unwrap_or_else(|| "Nieznana".to_string()),
                                )
                                .with_evidence("Wykryte słowo kluczowe", kw.to_string()),
                            );
                        }
                        break;
                    }
                }
            }
        }
    }
}

/// Extracts Windows file path strings (C:\...) encoded in UTF-16LE from a binary Jump List file
fn extract_jump_list_paths(buf: &[u8]) -> Vec<String> {
    let mut results = Vec::new();

    // 1. UTF-16LE scanning: search for sequence [Letter, 0x00, ':', 0x00, '\\', 0x00]
    let mut i = 0;
    while i + 6 <= buf.len() {
        let b0 = buf[i];
        let b1 = buf[i + 1];
        let b2 = buf[i + 2];
        let b3 = buf[i + 3];
        let b4 = buf[i + 4];
        let b5 = buf[i + 5];

        if b0.is_ascii_alphabetic() && b1 == 0 && b2 == b':' && b3 == 0 && b4 == b'\\' && b5 == 0 {
            let mut u16_chars = Vec::new();
            let mut j = i;
            while j + 2 <= buf.len() {
                let c_low = buf[j];
                let c_high = buf[j + 1];
                if c_high != 0 || c_low == 0 || c_low < 32 || c_low > 126 {
                    break;
                }
                u16_chars.push(c_low as u16);
                j += 2;
                if u16_chars.len() >= 260 {
                    break;
                }
            }

            if u16_chars.len() >= 5 {
                let s = String::from_utf16_lossy(&u16_chars);
                if (s.ends_with(".exe") || s.ends_with(".jar") || s.ends_with(".dll") || s.ends_with(".bat") || s.ends_with(".ps1")) && s.contains('\\') {
                    results.push(s);
                    i = j;
                    continue;
                }
            }
        }
        i += 2;
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_jump_list_paths() {
        let path = "C:\\Games\\vape.exe";
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);
        for c in path.encode_utf16() {
            buf.extend_from_slice(&c.to_le_bytes());
        }
        buf.extend_from_slice(&[0x00, 0x00, 0x11, 0x22]);

        let extracted = extract_jump_list_paths(&buf);
        assert_eq!(extracted.len(), 1);
        assert_eq!(extracted[0], "C:\\Games\\vape.exe");
    }

    #[test]
    fn test_jumplist_weedclient_not_flagged_as_dclient() {
        let fake_path = "C:\\Users\\dany\\Desktop\\clients\\weedclient1.21.4.jar";
        assert!(!is_cheat_keyword_match(fake_path, "dclient"), "weedclient must NOT trigger dclient keyword!");

        let real_dclient = "C:\\Users\\dany\\Desktop\\clients\\dclient1.21.4.jar";
        assert!(is_cheat_keyword_match(real_dclient, "dclient"), "dclient1.21.4.jar MUST trigger dclient keyword!");

        let calcium_dclient = "C:\\Users\\dany\\Desktop\\calcium_dclient.jar";
        assert!(is_cheat_keyword_match(calcium_dclient, "dclient"), "calcium_dclient.jar MUST trigger dclient keyword!");

        let sakura = "C:\\Games\\sakura_mod.jar";
        assert!(!is_cheat_keyword_match(sakura, "kura"), "sakura must NOT trigger kura keyword!");

        let fabric_loader = "C:\\Minecraft\\fabric-loader-0.16.0.jar";
        assert!(!is_cheat_keyword_match(fabric_loader, "loader"), "fabric-loader must NOT trigger loader keyword!");
    }
}
