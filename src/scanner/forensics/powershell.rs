use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

pub fn scan_powershell_history(report: &mut ScanReport) {
    let appdata = match std::env::var("APPDATA") {
        Ok(v) => v,
        Err(_) => return,
    };

    let history_path = PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("PowerShell")
        .join("PSReadLine")
        .join("ConsoleHost_history.txt");

    if !history_path.exists() {
        return;
    }

    let meta = match history_path.metadata() {
        Ok(m) => m,
        Err(_) => return,
    };

    let mod_time = match meta.modified() {
        Ok(t) => t,
        Err(_) => return,
    };

    // Ignoruj historię PowerShell jeśli nie było w niej żadnej aktywności w bieżącej sesji (od ostatniego startu PC)
    if !super::is_system_time_in_current_session(mod_time) {
        return;
    }

    let file = match File::open(&history_path) {
        Ok(f) => f,
        Err(_) => return,
    };

    let reader = BufReader::new(file);

    let critical_cleaner_commands = [
        ("fsutil usn deletejournal", "Kasowanie dziennika plików NTFS USN Journal (Zacieranie śladów)"),
        ("wevtutil cl", "Masowe czyszczenie dzienników zdarzeń Windows Event Log"),
        ("clear-eventlog", "Czyszczenie dzienników zdarzeń PowerShell"),
        ("remove-item *prefetch*", "Ręczne kasowanie plików pamięci podręcznej Windows Prefetch"),
        ("del *prefetch*", "Ręczne kasowanie plików Prefetch"),
        ("del /f /q *prefetch*", "Ręczne czyszczenie plików Prefetch"),
        ("clear-history", "Próba wyczyszczenia historii poleceń sesji"),
    ];

    let suspicious_cheat_indicators = [
        "vape", "slinky", "drip", "kura", "entropy", "doomsday", "prestige",
        "liquidbounce", "grimclient", "pulsarclient", "solarclient", "vengeance",
        "astralclient", "epstein", "calcium", "dclient", "dqrkis", "argonclient",
        "noxx", "pulseclient", "22qq", "meraclient", "autoclicker", "selfdestruct",
        "cleaner.bat", "clean.ps1", "destruct.bat", "stringcleaner",
    ];

    let mut reported_commands = std::collections::HashSet::new();

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.len() > 1024 {
            continue;
        }

        let lower = trimmed.to_lowercase();

        // 1. Sprawdzanie krytycznych komend zacierania śladów (Tampering / Cleaners)
        for &(cmd, reason) in &critical_cleaner_commands {
            if lower.contains(cmd) {
                if reported_commands.insert(trimmed.to_string()) {
                    report.add(
                        ScanFinding::new(
                            "Anti-Forensic Command in PowerShell History",
                            FindingCategory::TamperingAndAntiForensics,
                            VerdictLevel::Detection,
                            format!("W historii konsoli PowerShell zidentyfikowano polecenie zacierania śladów: {}", reason),
                        )
                        .with_evidence("Zarejestrowane polecenie", trimmed.to_string())
                        .with_evidence("Ścieżka historii", history_path.to_string_lossy().to_string()),
                    );
                }
                break;
            }
        }

        // 2. Sprawdzanie poleceń związanych z uruchamianiem lub pobieraniem cheatów
        if (lower.starts_with("curl ")
            || lower.starts_with("wget ")
            || lower.starts_with("irm ")
            || lower.starts_with("iwr ")
            || lower.contains("invoke-webrequest")
            || lower.contains("start-process")
            || lower.ends_with(".exe")
            || lower.ends_with(".jar"))
            && suspicious_cheat_indicators.iter().any(|&c| super::is_cheat_keyword_match(&lower, c))
        {
            if reported_commands.insert(trimmed.to_string()) {
                report.add(
                    ScanFinding::new(
                        "Suspicious Execution / Download in PowerShell History",
                        FindingCategory::WindowsForensics,
                        VerdictLevel::Detection,
                        "W historii poleceń PowerShell zarejestrowano wywołanie lub pobranie nieautoryzowanego oprogramowania.",
                    )
                    .with_evidence("Zarejestrowane polecenie", trimmed.to_string())
                    .with_evidence("Ścieżka historii", history_path.to_string_lossy().to_string()),
                );
            }
        }
    }
}
