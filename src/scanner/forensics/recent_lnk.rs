use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;

pub fn scan_recent_and_ads(report: &mut ScanReport) {
    scan_recent_shortcuts(report);
    scan_zone_identifiers(report);
}

/// Skanuje folder %APPDATA%\Microsoft\Windows\Recent w poszukiwaniu skrótów do cheatów
fn scan_recent_shortcuts(report: &mut ScanReport) {
    let appdata = match std::env::var("APPDATA") {
        Ok(v) => v,
        Err(_) => return,
    };

    let recent_dir = PathBuf::from(appdata)
        .join("Microsoft")
        .join("Windows")
        .join("Recent");

    if !recent_dir.exists() {
        return;
    }

    let entries = match fs::read_dir(&recent_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    let known_cheat_keywords = [
        "vape", "slinky", "drip", "kura", "entropy", "doomsday", "prestige",
        "liquidbounce", "grimclient", "pulsarclient", "solarclient", "vengeance",
        "astralclient", "epstein", "calcium", "dclient", "dqrkis", "argonclient",
        "noxx", "pulseclient", "meraclient", "autoclicker", "destruct",
        "loader", "inject", "cleaner", "wipe", "cheat",
    ];

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("lnk")) != Some(true) {
            continue;
        }

        // Sprawdź czy skrót był otwierany lub modyfikowany w bieżącej sesji systemu (od ostatniego startu PC)
        let mut in_current_session = false;
        let mut time_str = None;
        if let Ok(meta) = entry.metadata() {
            for t in [meta.modified().ok(), meta.accessed().ok(), meta.created().ok()].into_iter().flatten() {
                if super::is_system_time_in_current_session(t) {
                    in_current_session = true;
                    time_str = Some(super::format_system_time(t));
                    break;
                }
            }
        }

        // Ignoruj historyczne skróty sprzed ostatniego restartu PC
        if !in_current_session {
            continue;
        }

        let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        let lower_name = file_name.to_lowercase();

        // 1. Sprawdzenie po nazwie samego skrótu LNK
        let mut matched = known_cheat_keywords.iter().any(|&c| super::is_cheat_keyword_match(&lower_name, c));
        let mut target_hint = String::new();

        // 2. Parsowanie zawartości binarnej .lnk w celu wyciągnięcia ścieżki docelowej
        if let Ok(mut file) = File::open(&path) {
            let mut buf = Vec::new();
            if file.read_to_end(&mut buf).is_ok() {
                if let Some(target) = extract_lnk_target_path(&buf) {
                    target_hint = target.clone();
                    let target_lower = target.to_lowercase();
                    if known_cheat_keywords.iter().any(|&c| super::is_cheat_keyword_match(&target_lower, c)) {
                        matched = true;
                    }
                }
            }
        }

        // 3. Sprawdź czy skrót wskazuje na sfałszowany proces systemowy
        if !target_hint.is_empty() {
            if let Some(fake_name) = super::is_fake_system_executable(&target_hint) {
                report.add(
                    ScanFinding::new(
                        "Masqueraded System Process in Recent LNK (Current Session)",
                        FindingCategory::WindowsForensics,
                        VerdictLevel::Detection,
                        format!("W folderze Recent odnaleziono skrót LNK wskazujący na sfałszowany proces systemowy '{}' pod adresem: {}", fake_name, target_hint),
                    )
                    .with_evidence("Nazwa skrótu", file_name.clone())
                    .with_evidence("Ścieżka docelowa", target_hint.clone())
                    .with_evidence("Podszywanie pod proces", fake_name.to_string())
                    .with_evidence("Data modyfikacji w bieżącej sesji", time_str.clone().unwrap_or_else(|| "Bieżąca sesja".to_string())),
                );
                continue;
            }
        }

        if matched {
            let mut finding = ScanFinding::new(
                "Cheat / Loader Shortcut in Windows Recent Artifacts (Current Session)",
                FindingCategory::WindowsForensics,
                VerdictLevel::Detection,
                "W folderze niedawno otwieranych elementów (Recent) w bieżącej sesji zidentyfikowano skrót LNK wskazujący na oprogramowanie cheata lub loadera.",
            )
            .with_evidence("Nazwa skrótu", file_name)
            .with_evidence("Ścieżka skrótu", path.to_string_lossy().to_string())
            .with_evidence("Sesja", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string());

            if let Some(ref ts) = time_str {
                finding = finding.with_evidence("Czas aktywności skrótu", ts.clone());
            }

            if !target_hint.is_empty() {
                let target_exists = std::path::Path::new(&target_hint).exists();
                finding = finding.with_evidence("Ścieżka docelowa skrótu", target_hint);
                if !target_exists {
                    finding = finding.with_evidence(
                        "Stan pliku docelowego",
                        "Plik usunięty z dysku po uruchomieniu (ślad po Self-Destruct / usuniętym loaderze)".to_string(),
                    );
                }
            }

            report.add(finding);
        }
    }
}

/// Wyciąga czytelną ścieżkę dyskową (np. C:\...) z surowych bajtów pliku .lnk
fn extract_lnk_target_path(buf: &[u8]) -> Option<String> {
    // Proste i bezpieczne przeszukiwanie bajtów pod kątem wzorców ścieżek Windows (X:\...)
    let mut i = 0;
    while i + 3 < buf.len() {
        if buf[i].is_ascii_alphabetic() && buf[i + 1] == b':' && buf[i + 2] == b'\\' {
            let start = i;
            let mut end = start + 3;
            while end < buf.len() && buf[end] >= 32 && buf[end] < 127 {
                end += 1;
            }
            if end - start >= 6 {
                if let Ok(path_str) = std::str::from_utf8(&buf[start..end]) {
                    if path_str.ends_with(".exe") || path_str.ends_with(".jar") || path_str.ends_with(".bat") {
                        return Some(path_str.to_string());
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Skanuje alternatywne strumienie danych (:Zone.Identifier) w folderach Downloads i Desktop
fn scan_zone_identifiers(report: &mut ScanReport) {
    let user_profile = match std::env::var("USERPROFILE") {
        Ok(v) => v,
        Err(_) => return,
    };

    let target_dirs = [
        PathBuf::from(&user_profile).join("Downloads"),
        PathBuf::from(&user_profile).join("Desktop"),
    ];

    let cheat_download_domains = [
        "vape.gg", "drip.gg", "slinky.gg", "entropy.club", "doomsday.rip",
        "doomsday.client", "breeze.rip", "prestigeclient.vip", "liquidbounce.net",
        "lithiumclient.wtf", "kura.client", "vengeance", "pulseclient", "meraclient",
    ];

    let cheat_url_keywords = [
        "vape", "slinky", "drip", "kura", "entropy", "doomsday", "prestige",
        "liquidbounce", "grimclient", "pulsarclient", "solarclient", "vengeance",
        "astralclient", "epstein", "dclient", "dqrkis", "argonclient", "pulseclient",
        "meraclient", "autoclicker",
    ];

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
            if path.is_dir() {
                continue;
            }

            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or_default().to_lowercase();
            if ext != "exe" && ext != "jar" && ext != "zip" && ext != "rar" && ext != "bat" && ext != "7z" {
                continue;
            }

            // Sprawdź czy plik został pobrany lub zmodyfikowany w bieżącej sesji systemu (od ostatniego startu PC)
            let mut in_current_session = false;
            let mut time_str = None;
            if let Ok(meta) = path.metadata() {
                for t in [meta.modified().ok(), meta.created().ok()].into_iter().flatten() {
                    if super::is_system_time_in_current_session(t) {
                        in_current_session = true;
                        time_str = Some(super::format_system_time(t));
                        break;
                    }
                }
            }

            // Ignoruj pliki pobrane przed restartem PC
            if !in_current_session {
                continue;
            }

            let ads_path_str = format!("{}:Zone.Identifier", path.to_string_lossy());
            let ads_file = match File::open(&ads_path_str) {
                Ok(f) => f,
                Err(_) => continue,
            };

            let reader = BufReader::new(ads_file);
            let mut host_url = String::new();
            let mut referrer_url = String::new();

            for line_res in reader.lines() {
                let line = match line_res {
                    Ok(l) => l,
                    Err(_) => continue,
                };

                let trimmed = line.trim();
                if let Some(url) = trimmed.strip_prefix("HostUrl=") {
                    host_url = url.trim().to_string();
                } else if let Some(ref_url) = trimmed.strip_prefix("ReferrerUrl=") {
                    referrer_url = ref_url.trim().to_string();
                }
            }

            let host_lower = host_url.to_lowercase();
            let referrer_lower = referrer_url.to_lowercase();

            let matches_cheat_domain = cheat_download_domains.iter().any(|&d| host_lower.contains(d) || referrer_lower.contains(d));
            let matches_cheat_keyword = cheat_url_keywords.iter().any(|&k| host_lower.contains(k) || referrer_lower.contains(k));

            if matches_cheat_domain || matches_cheat_keyword {
                let mut finding = ScanFinding::new(
                    "Cheat Download Origin Recorded in Zone.Identifier Stream (Current Session)",
                    FindingCategory::WindowsForensics,
                    VerdictLevel::Detection,
                    "W metadanych pobierania pliku w bieżącej sesji (strumień NTFS Zone.Identifier) wykryto pobranie cheata z zewnętrznego serwera lub sieci Discord.",
                )
                .with_evidence("Plik lokalny", path.to_string_lossy().to_string())
                .with_evidence("Sesja", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string());

                if let Some(ref ts) = time_str {
                    finding = finding.with_evidence("Czas pobrania / modyfikacji", ts.clone());
                }

                if !host_url.is_empty() {
                    finding = finding.with_evidence("Pobrano z adresu (HostUrl)", host_url);
                }
                if !referrer_url.is_empty() {
                    finding = finding.with_evidence("Strona źródłowa (ReferrerUrl)", referrer_url);
                }

                report.add(finding);
            }
        }
    }
}
