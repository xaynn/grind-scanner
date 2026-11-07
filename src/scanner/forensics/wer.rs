use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use crate::scanner::forensics::{
    format_system_time, is_cheat_keyword_match, is_system_time_in_current_session,
    is_whitelisted_executable,
};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Skanuje raporty błędów i zrzuty awarii systemu Windows (WER - Windows Error Reporting)
/// w poszukiwaniu śladów crashów loaderów cheatów, injectorów oraz procesu gry w bieżącej sesji.
pub fn scan_wer_crash_reports(report: &mut ScanReport) {
    let mut candidate_dirs: Vec<PathBuf> = Vec::new();

    // 1. Ogólnosystemowe archiwum WER
    candidate_dirs.push(PathBuf::from(r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive"));
    candidate_dirs.push(PathBuf::from(r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue"));

    // 2. Lokalne zrzuty awarii aplikacji użytkownika
    if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
        candidate_dirs.push(PathBuf::from(&local_appdata).join("CrashDumps"));
        candidate_dirs.push(PathBuf::from(&local_appdata).join(r"Microsoft\Windows\WER\ReportArchive"));
    }

    let cheat_keywords = [
        "vape", "slinky", "drip", "kura", "entropy", "doomsday", "prestige",
        "liquidbounce", "grimclient", "pulsarclient", "solarclient", "vengeance",
        "astralclient", "epstein", "calcium", "dclient", "dqrkis", "argonclient",
        "noxx", "pulseclient", "22qq", "meraclient", "destruct", "cleaner",
        "loader", "inject", "stringcleaner",
    ];

    let mut reported_entries = std::collections::HashSet::new();

    for dir in &candidate_dirs {
        if !dir.exists() {
            continue;
        }

        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
            let lower_name = file_name.to_lowercase();

            // Sprawdź czas modyfikacji - interesują nas wyłącznie awarie z BIEŻĄCEJ sesji systemu
            let mtime = match entry.metadata().and_then(|m| m.modified()) {
                Ok(t) => t,
                Err(_) => continue,
            };

            if !is_system_time_in_current_session(mtime) {
                continue;
            }

            let time_formatted = format_system_time(mtime);

            // Ignoruj znane zaufane aplikacje
            if is_whitelisted_executable(&lower_name) {
                continue;
            }

            // 1. Sprawdzanie bezpośrednich zrzutów pamięci (.dmp) lub katalogów raportów po nazwie
            let mut matched_kw = None;
            for kw in &cheat_keywords {
                if is_cheat_keyword_match(&lower_name, kw) {
                    matched_kw = Some(*kw);
                    break;
                }
            }

            if let Some(kw) = matched_kw {
                if reported_entries.insert(lower_name.clone()) {
                    report.add(
                        ScanFinding::new(
                            format!("Cheat Crash Artifact in Windows Error Reporting: {}", file_name),
                            FindingCategory::WindowsForensics,
                            VerdictLevel::Detection,
                            format!(
                                "Dziennik Windows Error Reporting zarejestrował awarię (crash) narzędzia powiązanego z cheatem ({}) w bieżącej sesji systemu ({}). Nawet po usunięciu pliku z dysku, system Windows zachował trwały ślad jego wykonania.",
                                kw, time_formatted
                            ),
                        )
                        .with_evidence("Ścieżka raportu WER", path.to_string_lossy().to_string())
                        .with_evidence("Nazwa pliku / katalogu", file_name.clone())
                        .with_evidence("Czas awarii w bieżącej sesji", time_formatted.clone())
                        .with_evidence("Wykryty moduł", kw.to_string()),
                    );
                }
                continue;
            }

            // 2. Jeśli katalog dotyczy awarii javaw.exe w bieżącej sesji, sprawdź zawartość Report.wer pod kątem złośliwego modułu
            if path.is_dir() && lower_name.contains("javaw.exe") {
                let report_wer = path.join("Report.wer");
                if report_wer.exists() {
                    if let Some(content) = read_wer_file(&report_wer) {
                        let lower_content = content.to_lowercase();
                        for kw in &cheat_keywords {
                            if is_cheat_keyword_match(&lower_content, kw) {
                                if reported_entries.insert(format!("javaw_wer_{}", kw)) {
                                    report.add(
                                        ScanFinding::new(
                                            format!("Minecraft Crash Report Linked to Cheat Module ({})", kw),
                                            FindingCategory::MinecraftRuntime,
                                            VerdictLevel::Detection,
                                            format!(
                                                "W pliku raportu awarii Minecrafta (javaw.exe) z bieżącej sesji odnaleziono odwołanie do modułu cheata: {}.",
                                                kw
                                            ),
                                        )
                                        .with_evidence("Ścieżka Report.wer", report_wer.to_string_lossy().to_string())
                                        .with_evidence("Czas zdarzenia", time_formatted.clone())
                                        .with_evidence("Wykryty moduł błędu", kw.to_string()),
                                    );
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Pomocnicza funkcja odczytująca pliki Report.wer kodowane w UTF-16 LE lub UTF-8
fn read_wer_file(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    Some(crate::scanner::tampering::decode_bytes_lossy_utf8_or_utf16(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wer_read_lossy() {
        assert_eq!(read_wer_file(&std::path::PathBuf::from("non_existent_file_test")), None);
        let sample_bytes = "EventType=APPCRASH\nAppName=vape.exe".as_bytes();
        let decoded = crate::scanner::tampering::decode_bytes_lossy_utf8_or_utf16(sample_bytes);
        assert!(decoded.contains("vape.exe"));
    }
}
