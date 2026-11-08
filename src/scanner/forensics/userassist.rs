use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, HKEY_CURRENT_USER, KEY_READ,
};

/// Decodes ROT-13 encoded string (used by Windows UserAssist)
pub fn decode_rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => ((c as u8) + 13) as char,
            'n'..='z' | 'N'..='Z' => ((c as u8) - 13) as char,
            _ => c,
        })
        .collect()
}

pub fn scan_userassist(report: &mut ScanReport) {
    let base_key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\0"
        .encode_utf16()
        .collect();

    unsafe {
        let mut h_base = std::ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_CURRENT_USER,
            base_key.as_ptr(),
            0,
            KEY_READ,
            &mut h_base,
        ) != 0
        {
            return;
        }

        let mut guid_index = 0u32;
        let mut guid_name = [0u16; 128];
        let mut guid_len = 128u32;

        let mut reported_paths = std::collections::HashSet::new();

        while RegEnumKeyExW(
            h_base,
            guid_index,
            guid_name.as_mut_ptr(),
            &mut guid_len,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            let guid_str = String::from_utf16_lossy(&guid_name[..guid_len as usize]);
            scan_userassist_guid(h_base, &guid_str, &mut reported_paths, report);

            guid_index += 1;
            guid_len = 128;
        }

        RegCloseKey(h_base);
    }
}

unsafe fn scan_userassist_guid(
    h_base: windows_sys::Win32::System::Registry::HKEY,
    guid: &str,
    reported_paths: &mut std::collections::HashSet<String>,
    report: &mut ScanReport,
) {
    let count_subpath: Vec<u16> = format!("{}\\{}\0", guid, "Count")
        .encode_utf16()
        .collect();

    unsafe {
        let mut h_count = std::ptr::null_mut();
        if RegOpenKeyExW(
            h_base,
            count_subpath.as_ptr(),
            0,
            KEY_READ,
            &mut h_count,
        ) != 0
        {
            return;
        }

        let mut val_index = 0u32;
        let mut val_name = [0u16; 1024];
        let mut val_len = 1024u32;
        let mut val_type = 0u32;
        let mut val_data = [0u8; 256];
        let mut val_data_len = 256u32;

        let suspicious_triggers = [
            "vape", "drip", "ravenbplus", "raven_b", "ravenclient", "slinky", "kura", "autoclicker",
            "dopeclicker", "vroomclicker", "inject", "cheat", "processhacker", "string_cleaner",
            "vape_cleaner", "doomsday", "prestige", "imnotcheatingyouare", "marlow",
            "liquidbounce", "grimclient", "grim_client", "riseclient", "rise_client",
            "pulsarclient", "solarclient", "solar_client", "vengeance", "astralclient",
            "astral_client", "epstein", "calcium", "dclient", "dqrkis", "darkis", "trillium",
            "argonclient", "argon_client", "lvstrng", "noxx", "pulseclient", "pulse_client", "pulse-client",
            "22qq", "22qqclient", "22qq_client",
            "meraclient", "mera_client", "mera-client",
        ];

        while RegEnumValueW(
            h_count,
            val_index,
            val_name.as_mut_ptr(),
            &mut val_len,
            std::ptr::null_mut(),
            &mut val_type,
            val_data.as_mut_ptr(),
            &mut val_data_len,
        ) == 0
        {
            let raw_name = String::from_utf16_lossy(&val_name[..val_len as usize]);
            let decoded_name = decode_rot13(&raw_name);
            let normalized = super::normalize_device_path(&decoded_name);
            let norm_lower = normalized.to_lowercase();

            let is_exec = norm_lower.ends_with(".exe")
                || norm_lower.ends_with(".jar")
                || norm_lower.ends_with(".dll")
                || norm_lower.ends_with(".bat")
                || norm_lower.ends_with(".cmd");

        // Skip trusted processes and anticheats
            if !super::is_whitelisted_executable(&norm_lower) {
                // Parsowanie struktury UserAssist:
        // Offset 4..8: Run count (u32)
                let run_count = if val_data_len >= 8 {
                    u32::from_le_bytes(val_data[4..8].try_into().unwrap_or([0; 4]))
                } else {
                    0
                };

                // Offset 60..68: Czas ostatniego uruchomienia (FILETIME u64)
                let (last_run, in_current_session) = if val_data_len >= 68 {
                    let ft = u64::from_le_bytes(val_data[60..68].try_into().unwrap_or([0; 8]));
                    (super::format_filetime(ft), super::was_executed_in_current_session(ft))
                } else {
                    (None, false)
                };

        // 1. Check for system process masquerading (ONLY in current system session)
                if let Some(fake_name) = super::is_fake_system_executable(&normalized) {
                    if in_current_session && reported_paths.insert(normalized.clone()) {
                        let mut finding = ScanFinding::new(
                            "Masqueraded System Process in Current Session (UserAssist)",
                            FindingCategory::WindowsForensics,
                            VerdictLevel::Warning,
                            format!("UserAssist records GUI execution of fake system executable during current session: {}", normalized),
                        )
                        .with_evidence("Program Path", normalized.clone())
                        .with_evidence("Masqueraded As", fake_name.to_string())
                        .with_evidence("Session Scope", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
                        .with_evidence("Run Count", format!("{}x", run_count));

                        if let Some(ref lr) = last_run {
                            finding = finding.with_evidence("Last Executed", lr.clone());
                        }

                        report.add(finding);
                    }
                    val_index += 1;
                    val_len = 1024;
                    val_data_len = 256;
                    continue;
                }

        // 2. Check cheat keywords (ONLY in current system session)
                let mut matched_trigger = false;
                for trigger in &suspicious_triggers {
                    if super::is_cheat_keyword_match(&norm_lower, trigger) {
                        // Ignore historical executions from before PC reboot
                        if !in_current_session {
                            matched_trigger = true;
                            break;
                        }

                        if reported_paths.insert(normalized.clone()) {
                            let title = "Active Cheat Execution in Current Session (UserAssist)";
                            let verdict = VerdictLevel::Detection;
                            let scope_desc = "Bieżąca sesja systemu (uruchomiony PO starcie PC)";

                            let mut finding = ScanFinding::new(
                                title,
                                FindingCategory::WindowsForensics,
                                verdict,
                                format!("UserAssist history records GUI execution of: {}", normalized),
                            )
                            .with_evidence("Program Path", normalized.clone())
                            .with_evidence("Session Scope", scope_desc.to_string())
                            .with_evidence("Run Count", format!("{}x", run_count));

                            if let Some(ref lr) = last_run {
                                finding = finding.with_evidence("Last Executed", lr.clone());
                            }

                            report.add(finding);
                        }
                        matched_trigger = true;
                        break;
                    }
                }

        // 3. Check volatile directories (Downloads, Temp, Desktop) - ONLY IN CURRENT SYSTEM SESSION!
                if !matched_trigger && in_current_session && is_exec && super::is_volatile_directory(&normalized) {
                    let file_path = std::path::Path::new(&normalized);
                    if !file_path.exists() {
                        if reported_paths.insert(normalized.clone()) {
                            let mut finding = ScanFinding::new(
                                "Deleted Executable Record in UserAssist (Potential Self-Destruct)",
                                FindingCategory::WindowsForensics,
                                VerdictLevel::Warning,
                                format!("UserAssist records GUI execution from volatile directory during current session, but file was deleted: {}", normalized),
                            )
                            .with_evidence("Program Path", normalized.clone())
                            .with_evidence("Disk Status", "File deleted / missing (Self-destruct trace)".to_string())
                            .with_evidence("Session Scope", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
                            .with_evidence("Run Count", format!("{}x", run_count));

                            if let Some(ref lr) = last_run {
                                finding = finding.with_evidence("Last Executed", lr.clone());
                            }

                            report.add(finding);
                        }
                    } else if norm_lower.ends_with(".exe") || norm_lower.ends_with(".dll") {
                        if !super::is_pe_signed(file_path) {
                            if reported_paths.insert(normalized.clone()) {
                                let mut finding = ScanFinding::new(
                                    "Unsigned Executable Run in Current Session (UserAssist)",
                                    FindingCategory::WindowsForensics,
                                    VerdictLevel::Warning,
                                    format!("UserAssist records GUI execution of unsigned executable during current session: {}", normalized),
                                )
                                .with_evidence("Program Path", normalized.clone())
                                .with_evidence("Digital Signature", "None (Unsigned binary)".to_string())
                                .with_evidence("Session Scope", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string())
                                .with_evidence("Run Count", format!("{}x", run_count));

                                if let Some(ref lr) = last_run {
                                    finding = finding.with_evidence("Last Executed", lr.clone());
                                }

                                report.add(finding);
                            }
                        }
                    }
                }
            }

            val_index += 1;
            val_len = 1024;
            val_data_len = 256;
        }

        RegCloseKey(h_count);
    }
}
