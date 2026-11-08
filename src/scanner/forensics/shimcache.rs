use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use std::collections::HashSet;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
};

pub fn scan_shimcache(report: &mut ScanReport) {
    let subkey: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\0"
        .encode_utf16()
        .collect();

    unsafe {
        let mut h_key = std::ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            0,
            KEY_READ,
            &mut h_key,
        ) != 0
        {
            return;
        }

        let val_name: Vec<u16> = "AppCompatCache\0".encode_utf16().collect();
        let mut val_type = 0u32;
        let mut val_size = 0u32;

        // Najpierw pobieramy wymagany rozmiar bufora
        if RegQueryValueExW(
            h_key,
            val_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            std::ptr::null_mut(),
            &mut val_size,
        ) != 0 || val_size == 0
        {
            RegCloseKey(h_key);
            return;
        }

        let mut buffer = vec![0u8; val_size as usize];
        if RegQueryValueExW(
            h_key,
            val_name.as_ptr(),
            std::ptr::null_mut(),
            &mut val_type,
            buffer.as_mut_ptr(),
            &mut val_size,
        ) != 0
        {
            RegCloseKey(h_key);
            return;
        }

        RegCloseKey(h_key);

        parse_shimcache_entries(&buffer, report);
    }
}

struct ShimEntry {
    path: String,
    filetime: u64,
}

fn extract_shim_entries(buffer: &[u8]) -> Vec<ShimEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

        // Windows 10 & 11 AppCompatCache "10ts" parser (extracts path and precise FILETIME)
    while offset + 22 <= buffer.len() {
        if &buffer[offset..offset + 4] == b"10ts" {
            let entry_size = u32::from_le_bytes(buffer[offset + 8..offset + 12].try_into().unwrap_or([0; 4])) as usize;
            let path_len = u16::from_le_bytes(buffer[offset + 12..offset + 14].try_into().unwrap_or([0; 2])) as usize;

            if path_len > 0 && offset + 14 + path_len + 8 <= buffer.len() {
                let path_bytes = &buffer[offset + 14..offset + 14 + path_len];
                let u16_slice: &[u16] = unsafe {
                    std::slice::from_raw_parts(path_bytes.as_ptr() as *const u16, path_len / 2)
                };
                let path_str = String::from_utf16_lossy(u16_slice);
                let ft = u64::from_le_bytes(buffer[offset + 14 + path_len..offset + 14 + path_len + 8].try_into().unwrap_or([0; 8]));
                entries.push(ShimEntry { path: path_str, filetime: ft });
            }

            if entry_size >= 14 && offset + entry_size <= buffer.len() {
                offset += entry_size;
                continue;
            }
        }
        offset += 1;
    }

        // Fallback for other Windows formats
    if entries.is_empty() {
        let u16_slice: &[u16] = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr() as *const u16, buffer.len() / 2)
        };
        let text = String::from_utf16_lossy(u16_slice);
        for part in text.split('\0') {
            let trimmed = part.trim();
            if trimmed.len() >= 4 {
                entries.push(ShimEntry { path: trimmed.to_string(), filetime: 0 });
            }
        }
    }

    entries
}

fn parse_shimcache_entries(buffer: &[u8], report: &mut ScanReport) {
    if buffer.len() < 128 {
        return;
    }

    let entries = extract_shim_entries(buffer);

    let suspicious_triggers = [
        "vape", "drip", "ravenbplus", "raven_b", "ravenclient", "slinky", "kura", "autoclicker",
        "dopeclicker", "vroomclicker", "inject", "injector", "cheat", "processhacker", "cheatengine",
        "string_cleaner", "vape_cleaner", "cheat_cleaner",
        "doomsday", "prestige", "imnotcheatingyouare", "marlow",
        "liquidbounce", "grimclient", "grim_client", "riseclient", "rise_client",
        "pulsarclient", "solarclient", "solar_client", "vengeance",
        "astralclient", "astral_client", "epstein", "calcium", "dclient", "dqrkis", "darkis", "trillium",
        "argonclient", "argon_client", "lvstrng", "noxx", "pulseclient", "pulse_client", "pulse-client",
        "22qq", "22qqclient", "22qq_client",
        "meraclient", "mera_client", "mera-client",
        "loader", "cleaner", "wipe", "destruct", "selfdestruct", "self_destruct", "agent", "bypass", "reach_mod",
    ];

    let mut reported_paths = HashSet::new();

    for entry in entries {
        let trimmed = entry.path.trim();
        if trimmed.len() < 4 {
            continue;
        }

        let is_path = (trimmed.len() >= 3 && trimmed.as_bytes()[1] == b':' && trimmed.as_bytes()[2] == b'\\')
            || trimmed.starts_with("\\Device\\")
            || trimmed.starts_with("??\\")
            || trimmed.starts_with("\\??\\");

        if !is_path {
            continue;
        }

        let lower = trimmed.to_lowercase();
        if !(lower.ends_with(".exe") || lower.ends_with(".jar") || lower.ends_with(".dll")) {
            continue;
        }

        // Skip trusted programs and anticheats
        if super::is_whitelisted_executable(&lower) {
            continue;
        }

        let normalized = super::normalize_device_path(trimmed);
        let norm_lower = normalized.to_lowercase();

        if super::is_whitelisted_executable(&norm_lower) {
            continue;
        }

        let (last_run, in_current_session) = if entry.filetime != 0 {
            (super::format_filetime(entry.filetime), super::was_executed_in_current_session(entry.filetime))
        } else {
            (None, false)
        };

        // 1. Check for system process masquerading (ONLY in current system session)
        if let Some(fake_name) = super::is_fake_system_executable(&normalized) {
            if in_current_session && reported_paths.insert(normalized.clone()) {
                let mut finding = ScanFinding::new(
                    "Masqueraded System Process in Current Session (ShimCache)",
                    FindingCategory::WindowsForensics,
                    VerdictLevel::Warning,
                    format!("ShimCache records execution of fake system executable during current session: {}", normalized),
                )
                .with_evidence("Cached Executable Path", normalized.clone())
                .with_evidence("Masqueraded As", fake_name.to_string())
                .with_evidence("Session Scope", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string());

                if let Some(ref lr) = last_run {
                    finding = finding.with_evidence("Last Execution Time", lr.clone());
                }

                report.add(finding);
            }
            continue;
        }

        // 2. Check known cheat keywords (ONLY in current system session)
        let mut trigger_matched = false;
        for trigger in &suspicious_triggers {
            if super::is_cheat_keyword_match(&norm_lower, trigger) {
                // Ignore historical executions from before PC reboot
                if !in_current_session {
                    trigger_matched = true;
                    break;
                }

                if reported_paths.insert(normalized.clone()) {
                    let title = "Active Cheat Execution in Current Session (ShimCache)";
                    let verdict = VerdictLevel::Detection;
                    let scope_desc = "Bieżąca sesja systemu (uruchomiony PO starcie PC)";

                    let mut finding = ScanFinding::new(
                        title,
                        FindingCategory::WindowsForensics,
                        verdict,
                        format!("AppCompatCache maintains execution evidence of: {}", normalized),
                    )
                    .with_evidence("Cached Executable Path", normalized.clone())
                    .with_evidence("Session Scope", scope_desc.to_string());

                    if let Some(ref lr) = last_run {
                        finding = finding.with_evidence("Last Execution Time", lr.clone());
                    }

                    report.add(finding);
                }
                trigger_matched = true;
                break;
            }
        }

        if trigger_matched {
            continue;
        }

        // 3. Check volatile directories (Downloads, Temp, Desktop) - ONLY IN CURRENT SYSTEM SESSION!
        if in_current_session && super::is_volatile_directory(&normalized) {
            let file_path = std::path::Path::new(&normalized);
            if !file_path.exists() {
            // File was executed from a temporary/user directory in the current session and DELETED
                if reported_paths.insert(normalized.clone()) {
                    let mut finding = ScanFinding::new(
                        "Deleted Executable Record in Current Session (ShimCache)",
                        FindingCategory::WindowsForensics,
                        VerdictLevel::Warning,
                        format!("ShimCache records execution from volatile directory during current session, but file was deleted: {}", normalized),
                    )
                    .with_evidence("Cached Executable Path", normalized.clone())
                    .with_evidence("Disk Status", "File deleted / missing (Self-destruct trace)".to_string())
                    .with_evidence("Session Scope", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string());

                    if let Some(ref lr) = last_run {
                        finding = finding.with_evidence("Last Execution Time", lr.clone());
                    }

                    report.add(finding);
                }
            } else if norm_lower.ends_with(".exe") || norm_lower.ends_with(".dll") {
            // File exists on disk - check whether it has a valid Authenticode signature
                if !super::is_pe_signed(file_path) {
                    if reported_paths.insert(normalized.clone()) {
                        let mut finding = ScanFinding::new(
                            "Unsigned Executable Run in Current Session (ShimCache)",
                            FindingCategory::WindowsForensics,
                            VerdictLevel::Warning,
                            format!("ShimCache records execution of unsigned executable during current session: {}", normalized),
                        )
                        .with_evidence("Cached Executable Path", normalized.clone())
                        .with_evidence("Digital Signature", "None (Unsigned binary)".to_string())
                        .with_evidence("Session Scope", "Bieżąca sesja systemu (od ostatniego startu PC)".to_string());

                        if let Some(ref lr) = last_run {
                            finding = finding.with_evidence("Last Execution Time", lr.clone());
                        }

                        report.add(finding);
                    }
                }
            }
        }
    }
}
