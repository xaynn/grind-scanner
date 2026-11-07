use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use std::collections::HashSet;
use std::path::Path;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, HKEY_CLASSES_ROOT, HKEY_CURRENT_USER,
    HKEY_USERS, KEY_READ,
};

/// Skanuje pamięć podręczną interfejsu powłoki Windows Shell MuiCache
/// pod kątem uruchamianych cheatów, cleanerów oraz narzędzi z rozróżnieniem sesji bieżącej vs historycznej.
pub fn scan_muicache(report: &mut ScanReport) {
    let mut reported_paths = HashSet::new();

    // 1. Sprawdź HKCU (najczęstsza i najbardziej wiarygodna lokalizacja bieżącego użytkownika)
    scan_muicache_at_key(
        HKEY_CURRENT_USER,
        "Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
        "HKEY_CURRENT_USER",
        &mut reported_paths,
        report,
    );

    // 2. Sprawdź HKCR jako fallback / rozszerzenie klas
    scan_muicache_at_key(
        HKEY_CLASSES_ROOT,
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
        "HKEY_CLASSES_ROOT",
        &mut reported_paths,
        report,
    );

    // 3. Jeśli skaner ma uprawnienia, sprawdź profile użytkowników pod HKEY_USERS
    scan_all_users_muicache(&mut reported_paths, report);
}

fn scan_all_users_muicache(reported_paths: &mut HashSet<String>, report: &mut ScanReport) {
    unsafe {
        let mut h_users = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_USERS, [0u16].as_ptr(), 0, KEY_READ, &mut h_users) != 0 {
            return;
        }

        let mut subkey_name = [0u16; 256];
        let mut subkey_len = 256u32;
        let mut index = 0u32;

        while RegEnumKeyExW(
            h_users,
            index,
            subkey_name.as_mut_ptr(),
            &mut subkey_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0 {
            let sid_str = String::from_utf16_lossy(&subkey_name[..subkey_len as usize]);

            // Pomiń wpisy klasowe (_Classes) oraz krótkie systemowe SIDy (.DEFAULT, S-1-5-18)
            if sid_str.starts_with("S-1-5-21-") && !sid_str.ends_with("_Classes") {
                let mui_subpath = format!(
                    "{}\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
                    sid_str
                );
                scan_muicache_at_key(
                    HKEY_USERS,
                    &mui_subpath,
                    &format!("HKEY_USERS\\{}", sid_str),
                    reported_paths,
                    report,
                );
            }

            index += 1;
            subkey_len = 256;
        }

        RegCloseKey(h_users);
    }
}

fn scan_muicache_at_key(
    root: windows_sys::Win32::System::Registry::HKEY,
    subpath: &str,
    location_desc: &str,
    reported_paths: &mut HashSet<String>,
    report: &mut ScanReport,
) {
    let subpath_w: Vec<u16> = format!("{}\0", subpath).encode_utf16().collect();

    unsafe {
        let mut h_key = std::ptr::null_mut();
        if RegOpenKeyExW(root, subpath_w.as_ptr(), 0, KEY_READ, &mut h_key) != 0 {
            return;
        }

        let suspicious_keywords = [
            "vape", "drip", "ravenbplus", "raven_b", "ravenclient", "slinky", "kura", "autoclicker",
            "dopeclicker", "vroomclicker", "inject", "cheat", "processhacker", "doomsday", "prestige",
            "imnotcheatingyouare", "marlow", "liquidbounce", "grimclient", "grim_client", "riseclient",
            "rise_client", "pulsarclient", "solarclient", "solar_client", "vengeance", "astralclient",
            "astral_client", "epstein", "calcium", "dclient", "dqrkis", "darkis", "trillium",
            "argonclient", "argon_client", "lvstrng", "noxx", "pulseclient", "pulse_client",
            "22qq", "meraclient", "cleaner", "wipe", "destruct", "self_destruct", "journal_clean",
        ];

        let mut val_index = 0u32;
        let mut val_name = [0u16; 2048];
        let mut val_len = 2048u32;
        let mut val_type = 0u32;
        let mut val_data = [0u8; 2048];
        let mut val_data_len = 2048u32;

        while RegEnumValueW(
            h_key,
            val_index,
            val_name.as_mut_ptr(),
            &mut val_len,
            std::ptr::null_mut(),
            &mut val_type,
            val_data.as_mut_ptr(),
            &mut val_data_len,
        ) == 0 {
            let raw_name = String::from_utf16_lossy(&val_name[..val_len as usize]);

            // Ekstrakcja czystej ścieżki i typu właściwości (.FriendlyAppName / .ApplicationCompany)
            let (clean_raw_path, prop_kind) = parse_muicache_val_name(&raw_name);
            let normalized_path = super::normalize_device_path(&clean_raw_path);
            let norm_lower = normalized_path.to_lowercase();

            let file_name = Path::new(&clean_raw_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_lowercase();

            // Odczyt zawartości wartości (wyświetlana nazwa aplikacji lub firma)
            let data_str = parse_registry_string(val_type, &val_data[..val_data_len as usize]);
            let data_lower = data_str.to_lowercase();

            // Pomiń zaufane biblioteki, platformy gier i antycheaty (sprawdzanie ścieżki, nazwy pliku i FriendlyAppName)
            let is_whitelisted = super::is_whitelisted_executable(&norm_lower)
                || super::is_whitelisted_executable(&file_name)
                || super::is_whitelisted_executable(&data_lower)
                || norm_lower.is_empty();

            if !is_whitelisted {
                // 1. Sprawdź podszywanie się pod proces systemowy (np. svchost.exe w Temp / Downloads)
                if let Some(fake_name) = super::is_fake_system_executable(&normalized_path) {
                    let file_exists = Path::new(&normalized_path).exists();
                    let mut in_current_session = false;

                    if file_exists {
                        if let Ok(meta) = std::fs::metadata(&normalized_path) {
                            for t in [meta.modified().ok(), meta.accessed().ok(), meta.created().ok()].into_iter().flatten() {
                                if super::is_system_time_in_current_session(t) {
                                    in_current_session = true;
                                    break;
                                }
                            }
                        }
                    }

                    if !in_current_session && !file_name.is_empty() {
                        if let Some((_, is_curr_sess)) = check_prefetch_for_executable(&file_name) {
                            if is_curr_sess {
                                in_current_session = true;
                            }
                        }
                    }

                    // Ignoruj historyczne podszycia sprzed ostatniego restartu PC
                    if in_current_session && reported_paths.insert(normalized_path.clone()) {
                        let status_desc = if file_exists {
                            "Plik wciąż obecny na dysku"
                        } else {
                            "Plik został usunięty z dysku po uruchomieniu (Anti-Forensics)"
                        };

                        let finding = ScanFinding::new(
                            "Masqueraded System Process Recorded in MuiCache",
                            FindingCategory::WindowsForensics,
                            VerdictLevel::Detection,
                            format!(
                                "Windows Shell MuiCache zarejestrował wykonanie pliku podszywającego się pod proces systemowy w bieżącej sesji: {}",
                                normalized_path
                            ),
                        )
                        .with_evidence("Program Path", normalized_path.clone())
                        .with_evidence("Masqueraded As", fake_name.to_string())
                        .with_evidence("Stan pliku", status_desc.to_string())
                        .with_evidence("Lokalizacja rejestru", location_desc.to_string());

                        report.add(finding);
                    }

                    val_index += 1;
                    val_len = 2048;
                    val_data_len = 2048;
                    continue;
                }

                // 2. Sprawdź słowa kluczowe cheatów / cleanerów w ścieżce LUB w nazwie wyświetlanej (FriendlyAppName)
                for trigger in &suspicious_keywords {
                    // Zabezpieczenie przed false-positive: jeśli trigger to "cheat", a nazwa zawiera "anti", pomiń
                    if *trigger == "cheat" && (norm_lower.contains("anti") || data_lower.contains("anti")) {
                        continue;
                    }

                    if super::is_cheat_keyword_match(&norm_lower, trigger) || super::is_cheat_keyword_match(&data_lower, trigger) {
                        if reported_paths.insert(normalized_path.clone()) {
                            let file_exists = Path::new(&normalized_path).exists();

                            // Sprawdź czas wykonania i korelację z bieżącą sesją systemu
                            let mut in_current_session = false;
                            let mut time_evidence = None;

                            if file_exists {
                                if let Ok(meta) = std::fs::metadata(&normalized_path) {
                                    let mod_time = meta.modified().ok();
                                    let acc_time = meta.accessed().ok();
                                    let crt_time = meta.created().ok();

                                    for t in [mod_time, acc_time, crt_time].into_iter().flatten() {
                                        if super::is_system_time_in_current_session(t) {
                                            in_current_session = true;
                                            time_evidence = Some(super::format_system_time(t));
                                            break;
                                        }
                                    }

                                    if time_evidence.is_none() {
                                        if let Some(t) = mod_time.or(crt_time).or(acc_time) {
                                            time_evidence = Some(super::format_system_time(t));
                                        }
                                    }
                                }
                            }

                            // Korelacja z plikiem Prefetch (.pf)
                            if !in_current_session && !file_name.is_empty() {
                                if let Some((pf_ft, is_curr_sess)) = check_prefetch_for_executable(&file_name) {
                                    if is_curr_sess {
                                        in_current_session = true;
                                        time_evidence = super::format_filetime(pf_ft);
                                    } else if time_evidence.is_none() {
                                        time_evidence = super::format_filetime(pf_ft);
                                    }
                                }
                            }

                            // Ignoruj historyczne uruchomienia sprzed restartu PC
                            if !in_current_session {
                                continue;
                            }

                            let status_desc = if file_exists { "Plik obecny na dysku" } else { "Plik usunięty w bieżącej sesji" };
                            let scope_desc = "Bieżąca sesja systemu (uruchomiony lub modyfikowany PO starcie PC)";
                            let title = "Active Unauthorized Tool / Injector Executed in Current Session (MuiCache)";

                            let mut finding = ScanFinding::new(
                                title,
                                FindingCategory::WindowsForensics,
                                VerdictLevel::Detection,
                                format!(
                                    "Windows Shell MuiCache zarejestrował ślad wykonania aplikacji GUI w bieżącej sesji: {}",
                                    normalized_path
                                ),
                            )
                            .with_evidence("Program Path", normalized_path.clone())
                            .with_evidence("Stan na dysku", status_desc.to_string())
                            .with_evidence("Zakres czasowy sesji", scope_desc.to_string())
                            .with_evidence("Lokalizacja rejestru", location_desc.to_string())
                            .with_evidence("Matched Keyword", trigger.to_string());

                            if let Some(ref t_str) = time_evidence {
                                finding = finding.with_evidence("Czas ostatniej aktywności / modyfikacji", t_str.clone());
                            }

                            if !data_str.is_empty() && !data_str.starts_with('@') {
                                finding = finding.with_evidence(
                                    match prop_kind {
                                        MuiPropKind::FriendlyAppName => "Nazwa aplikacji (FriendlyAppName)",
                                        MuiPropKind::ApplicationCompany => "Firma aplikacji (ApplicationCompany)",
                                        MuiPropKind::DirectName => "Opis z rejestru",
                                    },
                                    data_str.clone(),
                                );
                            }

                            report.add(finding);
                        }
                        break;
                    }
                }
            }

            val_index += 1;
            val_len = 2048;
            val_data_len = 2048;
        }

        RegCloseKey(h_key);
    }
}

fn check_prefetch_for_executable(exe_name: &str) -> Option<(u64, bool)> {
    super::check_prefetch_for_executable(exe_name)
}

enum MuiPropKind {
    FriendlyAppName,
    ApplicationCompany,
    DirectName,
}

fn parse_muicache_val_name(val_name: &str) -> (String, MuiPropKind) {
    if let Some(stripped) = val_name.strip_suffix(".FriendlyAppName") {
        (stripped.to_string(), MuiPropKind::FriendlyAppName)
    } else if let Some(stripped) = val_name.strip_suffix(".ApplicationCompany") {
        (stripped.to_string(), MuiPropKind::ApplicationCompany)
    } else {
        (val_name.to_string(), MuiPropKind::DirectName)
    }
}

fn parse_registry_string(val_type: u32, data: &[u8]) -> String {
    // REG_SZ = 1, REG_EXPAND_SZ = 2
    if (val_type == 1 || val_type == 2) && data.len() >= 2 {
        let u16_len = data.len() / 2;
        let mut u16_chars = Vec::with_capacity(u16_len);
        for chunk in data.chunks_exact(2) {
            let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
            if ch == 0 {
                break;
            }
            u16_chars.push(ch);
        }
        String::from_utf16_lossy(&u16_chars).trim().to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_muicache_val_name() {
        let (path, kind) = parse_muicache_val_name("C:\\Tools\\Vape.exe.FriendlyAppName");
        assert_eq!(path, "C:\\Tools\\Vape.exe");
        assert!(matches!(kind, MuiPropKind::FriendlyAppName));

        let (path2, kind2) = parse_muicache_val_name("C:\\Tools\\Test.exe.ApplicationCompany");
        assert_eq!(path2, "C:\\Tools\\Test.exe");
        assert!(matches!(kind2, MuiPropKind::ApplicationCompany));

        let (path3, kind3) = parse_muicache_val_name("C:\\Tools\\Direct.exe");
        assert_eq!(path3, "C:\\Tools\\Direct.exe");
        assert!(matches!(kind3, MuiPropKind::DirectName));
    }

    #[test]
    fn test_parse_registry_string() {
        let utf16_bytes: Vec<u8> = "Vape v4\0".encode_utf16().flat_map(|w| w.to_le_bytes()).collect();
        let parsed = parse_registry_string(1, &utf16_bytes);
        assert_eq!(parsed, "Vape v4");
    }

    #[test]
    fn test_anticheat_not_flagged_by_cheat_keyword() {
        let norm_lower = "c:\\program files\\ea games\\apex\\start_protected_game.exe";
        let data_lower = "easy anti-cheat bootstrapper (eos)";
        let file_name = "start_protected_game.exe";

        // Whitelist check
        let is_whitelisted = super::super::is_whitelisted_executable(norm_lower)
            || super::super::is_whitelisted_executable(file_name)
            || super::super::is_whitelisted_executable(data_lower);

        assert!(is_whitelisted, "Easy Anti-Cheat Bootstrapper should be whitelisted!");
    }
}
