use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use crate::scanner::forensics::{
    check_prefetch_for_executable, format_filetime, format_system_time, get_boot_unix_timestamp,
    is_fake_system_executable, is_system_time_in_current_session, is_volatile_directory,
    is_whitelisted_executable,
};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

pub fn scan_pcasvc_logs(report: &mut ScanReport) {
    let pca_dir = PathBuf::from("C:\\Windows\\System32\\LogFiles\\Pca");
    if !pca_dir.exists() {
        return;
    }

    let target_logs = [
        pca_dir.join("PcaAppLaunchDic.txt"),
        pca_dir.join("PcaGeneralDb0.txt"),
    ];

    for log_path in &target_logs {
        if log_path.exists() {
            scan_pca_file(log_path, report);
        }
    }
}

fn is_pca_timestamp_in_current_session(ts_str: &str) -> bool {
    let clean_ts = ts_str.split('.').next().unwrap_or(ts_str).trim();
    if let Ok(ndt) = chrono::NaiveDateTime::parse_from_str(clean_ts, "%Y-%m-%d %H:%M:%S") {
        if let Some(dt) = ndt.and_local_timezone(chrono::Local).single() {
            let unix_secs = dt.timestamp().max(0) as u64;
            let boot_secs = get_boot_unix_timestamp();
            return unix_secs >= boot_secs.saturating_sub(60);
        }
    }
    false
}

fn scan_pca_file(log_path: &Path, report: &mut ScanReport) {
    let file = match File::open(log_path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let reader = BufReader::new(file);

    let known_cheat_keywords = [
        "vape", "slinky", "drip", "kura", "entropy", "doomsday", "prestige",
        "liquidbounce", "grimclient", "pulsarclient", "solarclient", "vengeance",
        "astralclient", "epstein", "calcium", "dclient", "dqrkis", "argonclient",
        "noxx", "pulseclient", "meraclient", "autoclicker", "cleaner.bat",
        "destruct.bat", "stringcleaner", "selfdestruct",
    ];

    let mut reported_paths = std::collections::HashSet::new();

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // PcaAppLaunchDic typically separates fields with vertical pipe '|'
        // Field 0 is usually the full executable path, Field 1 is the timestamp
        let parts: Vec<&str> = trimmed.split('|').collect();
        let raw_path = match parts.first() {
            Some(p) => p.trim(),
            None => trimmed,
        };

        if raw_path.len() < 4 || !raw_path.contains(":\\") {
            continue;
        }

        let clean_path = raw_path.replace('/', "\\");
        let lower = clean_path.to_lowercase();

        if is_whitelisted_executable(&lower) {
            continue;
        }

        if !reported_paths.insert(lower.clone()) {
            continue;
        }

        let path_obj = Path::new(&clean_path);
        let file_exists = path_obj.exists();
        let file_name = path_obj.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Check if the event occurred in the current system session (since last PC boot)
        let mut in_current_session = false;
        let mut time_evidence = None;

        if let Some(ts) = parts.get(1) {
            let ts = ts.trim();
            if is_pca_timestamp_in_current_session(ts) {
                in_current_session = true;
                time_evidence = Some(ts.to_string());
            }
        }

        if !in_current_session && file_exists {
            if let Ok(meta) = path_obj.metadata() {
                for t in [meta.modified().ok(), meta.accessed().ok(), meta.created().ok()].into_iter().flatten() {
                    if is_system_time_in_current_session(t) {
                        in_current_session = true;
                        time_evidence = Some(format_system_time(t));
                        break;
                    }
                }
            }
        }

        if !in_current_session && !file_name.is_empty() {
            if let Some((pf_ft, is_curr)) = check_prefetch_for_executable(file_name) {
                if is_curr {
                    in_current_session = true;
                    time_evidence = format_filetime(pf_ft);
                }
            }
        }

        // Ignore historical executions from before the last PC reboot
        if !in_current_session {
            continue;
        }

        // Check for system process masquerading in PcaSvc
        if let Some(fake_name) = is_fake_system_executable(&clean_path) {
            report.add(
                ScanFinding::new(
                    "Masqueraded System Process in Current Session (PcaSvc)",
                    FindingCategory::WindowsForensics,
                    VerdictLevel::Detection,
                    format!("Dziennik usługi PcaSvc zarejestrował uruchomienie sfałszowanego procesu systemowego '{}' w bieżącej sesji: {}", fake_name, clean_path),
                )
                .with_evidence("Zarejestrowana ścieżka", clean_path.clone())
                .with_evidence("Podszywanie pod proces", fake_name.to_string())
                .with_evidence("Czas uruchomienia", time_evidence.unwrap_or_else(|| "Bieżąca sesja".to_string())),
            );
            continue;
        }

        let is_cheat = known_cheat_keywords.iter().any(|&c| super::is_cheat_keyword_match(&lower, c));

        if is_cheat {
            if !file_exists {
                let mut finding = ScanFinding::new(
                    "Deleted Cheat Executable Recorded in PcaSvc Log (Current Session)",
                    FindingCategory::TamperingAndAntiForensics,
                    VerdictLevel::Detection,
                    "W dzienniku zgodności aplikacji Windows (PcaSvc) zidentyfikowano uruchomienie pliku cheata w bieżącej sesji, który został następnie usunięty z dysku.",
                )
                .with_evidence("Ścieżka pliku", clean_path.clone())
                .with_evidence("Status pliku", "Usunięty z dysku w bieżącej sesji (Ślad anty-forensic)".to_string())
                .with_evidence("Sesja", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
                .with_evidence("Dziennik śledczy", log_path.to_string_lossy().to_string());

                if let Some(ref te) = time_evidence {
                    finding = finding.with_evidence("Czas uruchomienia", te.clone());
                }

                report.add(finding);
            } else {
                let mut finding = ScanFinding::new(
                    "Cheat Executable Recorded in PcaSvc Log (Current Session)",
                    FindingCategory::WindowsForensics,
                    VerdictLevel::Detection,
                    "W dzienniku zgodności aplikacji Windows (PcaSvc) zarejestrowano uruchomienie programu wspomagającego w bieżącej sesji systemu.",
                )
                .with_evidence("Ścieżka pliku", clean_path.clone())
                .with_evidence("Status pliku", "Plik obecny na dysku".to_string())
                .with_evidence("Sesja", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
                .with_evidence("Dziennik śledczy", log_path.to_string_lossy().to_string());

                if let Some(ref te) = time_evidence {
                    finding = finding.with_evidence("Czas uruchomienia", te.clone());
                }

                report.add(finding);
            }
        } else if !file_exists && is_volatile_directory(&lower) && (lower.ends_with(".exe") || lower.ends_with(".bat")) {
            let mut finding = ScanFinding::new(
                "Deleted Volatile Executable in PcaSvc Log (Current Session)",
                FindingCategory::WindowsForensics,
                VerdictLevel::Information,
                "W dzienniku PcaSvc odnotowano uruchomienie pliku z folderu tymczasowego w bieżącej sesji, który został później skasowany.",
            )
            .with_evidence("Ścieżka pliku", clean_path)
            .with_evidence("Status pliku", "Usunięty z dysku w bieżącej sesji".to_string())
            .with_evidence("Sesja", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
            .with_evidence("Dziennik śledczy", log_path.to_string_lossy().to_string());

            if let Some(ref te) = time_evidence {
                finding = finding.with_evidence("Czas uruchomienia", te.clone());
            }

            report.add(finding);
        }
    }
}
