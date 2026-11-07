use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, HKEY_LOCAL_MACHINE, KEY_READ,
};

pub fn scan_bam(report: &mut ScanReport) {
    let candidate_roots = [
        "SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        "SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
    ];

    let mut reported_paths = std::collections::HashSet::new();

    for root_str in &candidate_roots {
        let bam_root: Vec<u16> = format!("{}\0", root_str).encode_utf16().collect();

        unsafe {
            let mut h_root = std::ptr::null_mut();
            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                bam_root.as_ptr(),
                0,
                KEY_READ,
                &mut h_root,
            ) != 0
            {
                continue;
            }

            // Iterate User SIDs under UserSettings
            let mut index = 0u32;
            let mut subkey_name = [0u16; 256];
            let mut subkey_len = 256u32;

            while RegEnumKeyExW(
                h_root,
                index,
                subkey_name.as_mut_ptr(),
                &mut subkey_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) == 0
            {
                let sid_str = String::from_utf16_lossy(&subkey_name[..subkey_len as usize]);
                scan_user_bam(h_root, &sid_str, &mut reported_paths, report);

                index += 1;
                subkey_len = 256;
            }

            RegCloseKey(h_root);
        }
    }
}

unsafe fn scan_user_bam(
    h_root: windows_sys::Win32::System::Registry::HKEY,
    sid: &str,
    reported_paths: &mut std::collections::HashSet<String>,
    report: &mut ScanReport,
) {
    unsafe {
        let sid_w: Vec<u16> = format!("{}\0", sid).encode_utf16().collect();
        let mut h_user = std::ptr::null_mut();

        if RegOpenKeyExW(
            h_root,
            sid_w.as_ptr(),
            0,
            KEY_READ,
            &mut h_user,
        ) != 0
        {
            return;
        }

        let mut val_index = 0u32;
        let mut val_name = [0u16; 1024];
        let mut val_len = 1024u32;
        let mut val_type = 0u32;
        let mut val_data = [0u8; 128];
        let mut val_data_len = 128u32;

        let suspicious_names = [
            "vape", "drip", "ravenbplus", "raven_b", "ravenclient", "slinky", "kura", "autoclicker",
            "dopeclicker", "vroomclicker", "inject", "injector", "cheat", "processhacker", "cheatengine", "doomsday", "prestige",
            "imnotcheatingyouare", "marlow", "liquidbounce", "grimclient", "grim_client", "riseclient",
            "rise_client", "pulsarclient", "solarclient", "solar_client", "vengeance", "astralclient",
            "astral_client", "epstein", "calcium", "dclient", "dqrkis", "darkis", "trillium",
            "argonclient", "argon_client", "lvstrng", "noxx", "pulseclient", "pulse_client", "pulse-client",
            "22qq", "22qqclient", "22qq_client",
            "meraclient", "mera_client", "mera-client",
            "loader", "cleaner", "wipe", "destruct", "selfdestruct", "self_destruct", "bypass", "reach_mod",
        ];

        while RegEnumValueW(
            h_user,
            val_index,
            val_name.as_mut_ptr(),
            &mut val_len,
            std::ptr::null_mut(),
            &mut val_type,
            val_data.as_mut_ptr(),
            &mut val_data_len,
        ) == 0
        {
            let exe_path = String::from_utf16_lossy(&val_name[..val_len as usize]);
            let normalized = super::normalize_device_path(&exe_path);
            let norm_lower = normalized.to_lowercase();

            // Pomiń zaufane procesy i instalatory antycheatów (np. EasyAntiCheat, BattlEye)
            if !super::is_whitelisted_executable(&norm_lower) {
                // Pierwsze 8 bajtów w wartości BAM to czas FILETIME ostatniego wykonania
                let (last_run, in_current_session) = if val_data_len >= 8 {
                    let ft = u64::from_le_bytes(val_data[..8].try_into().unwrap_or([0; 8]));
                    (super::format_filetime(ft), super::was_executed_in_current_session(ft))
                } else {
                    (None, false)
                };

                // 1. Sprawdź podszywanie się pod proces systemowy (TYLKO w bieżącej sesji systemu)
                if let Some(fake_name) = super::is_fake_system_executable(&normalized) {
                    if in_current_session && reported_paths.insert(normalized.clone()) {
                        let mut finding = ScanFinding::new(
                            "Masqueraded System Process in Current Session (BAM)",
                            FindingCategory::WindowsForensics,
                            VerdictLevel::Warning,
                            format!("BAM recorded execution of fake system executable during the current Windows session: {}", normalized),
                        )
                        .with_evidence("Program Path", normalized.clone())
                        .with_evidence("Masqueraded As", fake_name.to_string())
                        .with_evidence("Session Scope", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
                        .with_evidence("User SID", sid.to_string());

                        if let Some(ref lr) = last_run {
                            finding = finding.with_evidence("Last Execution Time", lr.clone());
                        }

                        report.add(finding);
                    }
                    val_index += 1;
                    val_len = 1024;
                    val_data_len = 128;
                    continue;
                }

                // 2. Sprawdź słowa kluczowe cheatów (rozróżnienie sesji bieżącej vs historycznej)
                let mut matched_trigger = false;
                for trigger in &suspicious_names {
                    if *trigger == "cheat" && norm_lower.contains("anti") {
                        continue;
                    }

                    if super::is_cheat_keyword_match(&norm_lower, trigger) {
                        // Ignoruj historyczne uruchomienia sprzed restartu PC
                        if !in_current_session {
                            matched_trigger = true;
                            break;
                        }

                        if reported_paths.insert(normalized.clone()) {
                            let title = "Active Cheat Execution in Current Session (BAM)";
                            let verdict = VerdictLevel::Detection;
                            let scope_desc = "Bieżąca sesja systemu (uruchomiony PO starcie PC)";

                            let mut finding = ScanFinding::new(
                                title,
                                FindingCategory::WindowsForensics,
                                verdict,
                                format!("Background Activity Monitor recorded execution of: {}", normalized),
                            )
                            .with_evidence("Program Path", normalized.clone())
                            .with_evidence("Matched Keyword", trigger.to_string())
                            .with_evidence("Session Scope", scope_desc.to_string())
                            .with_evidence("User SID", sid.to_string());

                            if let Some(ref lr) = last_run {
                                finding = finding.with_evidence("Last Execution Time", lr.clone());
                            }

                            report.add(finding);
                        }
                        matched_trigger = true;
                        break;
                    }
                }

                // 3. Sprawdź katalogi ulotne (Downloads, Temp, Desktop) - TYLKO W BIEŻĄCEJ SESJI SYSTEMU!
                // Ignorujemy pliki niepodpisane/usunięte z poprzednich sesji (przed restartem PC)
                if !matched_trigger && in_current_session && super::is_volatile_directory(&normalized) {
                    let file_path = std::path::Path::new(&normalized);
                    if !file_path.exists() {
                        if reported_paths.insert(normalized.clone()) {
                            let mut finding = ScanFinding::new(
                                "Deleted Executable Record in BAM (Potential Self-Destruct)",
                                FindingCategory::WindowsForensics,
                                VerdictLevel::Warning,
                                format!("BAM recorded execution from volatile directory during current session, but file was deleted: {}", normalized),
                            )
                            .with_evidence("Program Path", normalized.clone())
                            .with_evidence("Disk Status", "File deleted / missing (Self-destruct trace)".to_string())
                            .with_evidence("Session Scope", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
                            .with_evidence("User SID", sid.to_string());

                            if let Some(ref lr) = last_run {
                                finding = finding.with_evidence("Last Execution Time", lr.clone());
                            }

                            report.add(finding);
                        }
                    } else if norm_lower.ends_with(".exe") || norm_lower.ends_with(".dll") {
                        if !super::is_pe_signed(file_path) {
                            if reported_paths.insert(normalized.clone()) {
                                let mut finding = ScanFinding::new(
                                    "Unsigned Executable Run in Current Session (BAM)",
                                    FindingCategory::WindowsForensics,
                                    VerdictLevel::Warning,
                                    format!("BAM records execution of unsigned executable during the current Windows session: {}", normalized),
                                )
                                .with_evidence("Program Path", normalized.clone())
                                .with_evidence("Digital Signature", "None (Unsigned binary)".to_string())
                                .with_evidence("Session Scope", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
                                .with_evidence("User SID", sid.to_string());

                                if let Some(ref lr) = last_run {
                                    finding = finding.with_evidence("Last Execution Time", lr.clone());
                                }

                                report.add(finding);
                            }
                        }
                    }
                }
            }

            val_index += 1;
            val_len = 1024;
            val_data_len = 128;
        }

        RegCloseKey(h_user);
    }
}
