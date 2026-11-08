use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use std::collections::HashSet;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

const FSCTL_QUERY_USN_JOURNAL: u32 = 0x000900f4;
const FSCTL_READ_USN_JOURNAL: u32 = 0x000900bb;
const USN_REASON_FILE_DELETE: u32 = 0x00000200;
const USN_REASON_RENAME_OLD_NAME: u32 = 0x00001000;
const USN_REASON_RENAME_NEW_NAME: u32 = 0x00002000;

#[repr(C)]
struct UsnJournalDataV0 {
    usn_journal_id: u64,
    lowest_valid_usn: i64,
    next_usn: i64,
    maximum_size: u64,
    allocation_delta: u64,
}

#[repr(C)]
struct ReadUsnJournalDataV0 {
    start_usn: i64,
    reason_mask: u32,
    return_only_on_close: u32,
    timeout: u64,
    bytes_to_wait_for: u64,
    usn_journal_id: u64,
}

#[repr(C)]
struct UsnRecordV2Header {
    record_length: u32,
    major_version: u16,
    minor_version: u16,
    file_ref_number: u64,
    parent_file_ref_number: u64,
    usn: i64,
    timestamp: i64,
    reason: u32,
    source_info: u32,
    security_id: u32,
    file_attributes: u32,
    file_name_length: u16,
    file_name_offset: u16,
}

/// Scans USN Journals across all available disk partitions
pub fn scan_all_usn_journals(report: &mut ScanReport) {
    // Dysk C: jest podstawowym dyskiem systemowym
    scan_usn_journal('C', report);

    // Check remaining partitions (D:-Z:) if Fixed / Removable type
    for drive in b'D'..=b'Z' {
        let drive_char = drive as char;
        let root = format!("{}:\\\0", drive_char);
        let root_u16: Vec<u16> = root.encode_utf16().collect();
        let drive_type = unsafe {
            windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(root_u16.as_ptr())
        };
        // DRIVE_FIXED = 3, DRIVE_REMOVABLE = 2
        if drive_type == 3 || drive_type == 2 {
            scan_usn_journal(drive_char, report);
        }
    }
}

pub fn scan_usn_journal(drive_letter: char, report: &mut ScanReport) {
    let volume_path: Vec<u16> = format!("\\\\.\\{}:\0", drive_letter).encode_utf16().collect();

    unsafe {
        let handle = CreateFileW(
            volume_path.as_ptr(),
            FILE_READ_DATA | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );

        if handle == INVALID_HANDLE_VALUE {
            let err = GetLastError();
        // For non-C drives, report lack of access silently (e.g. no partition)
            if drive_letter == 'C' {
                report.add(
                    ScanFinding::new(
                        "USN Journal Access Limited",
                        FindingCategory::WindowsForensics,
                        VerdictLevel::Information,
                        format!("Cannot open raw volume {}:. Full USN Journal forensics requires Administrator rights (Win32 Err: {}).", drive_letter, err),
                    )
                    .with_evidence("Drive", format!("{}:", drive_letter)),
                );
            }
            return;
        }

    // 1. Check USN Journal state (whether it has been cleared / deleted)
        let mut query_buf = [0u8; 512];
        let mut bytes_returned = 0u32;

        let query_ok = DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            query_buf.as_mut_ptr() as *mut c_void,
            query_buf.len() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        );

        if query_ok == 0 {
            let err = GetLastError();
            if drive_letter == 'C' {
                if err == 5 || err == 1 || err == 1784 || !report.is_admin {
                    report.add(
                        ScanFinding::new(
                            "USN Journal Access Limited",
                            FindingCategory::WindowsForensics,
                            VerdictLevel::Information,
                            format!("Querying USN Change Journal on volume {}: requires Administrator elevation (Err: {}).", drive_letter, err),
                        )
                        .with_evidence("Drive", format!("{}:", drive_letter)),
                    );
                } else {
                    report.add(
                        ScanFinding::new(
                            "USN Journal Disabled or Deleted",
                            FindingCategory::TamperingAndAntiForensics,
                            VerdictLevel::Detection,
                            format!("USN Change Journal on volume {}: is disabled or purged (fsutil usn deletejournal, err: {}).", drive_letter, err),
                        )
                        .with_evidence("Drive", format!("{}:", drive_letter)),
                    );
                }
            }
            CloseHandle(handle);
            return;
        }

        let journal_data = &*(query_buf.as_ptr() as *const UsnJournalDataV0);

        // If NextUSN is suspiciously close to zero (< 50000 on system drive C:), the journal was recently wiped!
        if drive_letter == 'C' && journal_data.next_usn < 50_000 {
            report.add(
                ScanFinding::new(
                    "USN Journal Truncate / Reset Detected",
                    FindingCategory::TamperingAndAntiForensics,
                    VerdictLevel::Detection,
                    "USN Journal contains abnormally low entry count. Indicates deliberate journal purging to hide file tampering.",
                )
                .with_evidence("NextUSN", journal_data.next_usn.to_string())
                .with_evidence("LowestValidUSN", journal_data.lowest_valid_usn.to_string()),
            );
        }

    // 2. Read recent file deletion records (searching for deleted cheats .jar / .dll / .exe)
    // Go back up to 6 MB before NextUSN to scan fresh deletions
        let start_usn = if journal_data.next_usn > 6_000_000 {
            journal_data.next_usn - 6_000_000
        } else {
            journal_data.lowest_valid_usn
        };

        let mut cur_usn = start_usn;
        let mut buffer = vec![0u8; 128 * 1024]; // 128KB bufor
        let mut deleted_files_found = 0;
        let mut reported_files = HashSet::new();
        let mut loop_count = 0;

    // Loop reading all records up to the very end of the journal (next_usn)
        while cur_usn < journal_data.next_usn && loop_count < 100 {
            loop_count += 1;

            let mut read_data = ReadUsnJournalDataV0 {
                start_usn: cur_usn,
                reason_mask: USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME | USN_REASON_RENAME_NEW_NAME,
                return_only_on_close: 0,
                timeout: 0,
                bytes_to_wait_for: 0,
                usn_journal_id: journal_data.usn_journal_id,
            };

            let mut read_bytes = 0u32;
            let read_ok = DeviceIoControl(
                handle,
                FSCTL_READ_USN_JOURNAL,
                &mut read_data as *mut _ as *mut c_void,
                std::mem::size_of::<ReadUsnJournalDataV0>() as u32,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as u32,
                &mut read_bytes,
                std::ptr::null_mut(),
            );

            if read_ok == 0 || read_bytes <= 8 {
                break;
            }

            let next_usn_from_buf = *(buffer.as_ptr() as *const i64);
            if next_usn_from_buf <= cur_usn {
                break;
            }
            cur_usn = next_usn_from_buf;

            let mut offset = 8usize;
            while offset + std::mem::size_of::<UsnRecordV2Header>() <= read_bytes as usize {
                let header = &*(buffer.as_ptr().add(offset) as *const UsnRecordV2Header);
                if header.record_length == 0 {
                    break;
                }

                if header.major_version == 2 {
                    let name_offset = offset + header.file_name_offset as usize;
                    let name_len = (header.file_name_length / 2) as usize;

                    if name_offset + (name_len * 2) <= read_bytes as usize {
                        let name_slice = std::slice::from_raw_parts(
                            buffer.as_ptr().add(name_offset) as *const u16,
                            name_len,
                        );
                        let file_name = String::from_utf16_lossy(name_slice);
                        let lower = file_name.to_lowercase();

                        let is_delete = (header.reason & USN_REASON_FILE_DELETE) != 0;
                        let is_rename_old = (header.reason & USN_REASON_RENAME_OLD_NAME) != 0;

                        if is_delete || is_rename_old {
                            let in_current_session = super::was_executed_in_current_session(header.timestamp as u64);

                            if let Some((verdict, base_title, matched_trigger)) = evaluate_deleted_file(&lower, in_current_session) {
                                let (title, desc) = if is_rename_old {
                                    (
                                        "Cheat Executable/Mod Renamed in Current Session (USN Journal Trace)",
                                        format!("Dziennik NTFS USN Journal zarejestrował zmianę nazwy pliku cheata/loadera: {} (próba ukrycia/zamaskowania)", file_name),
                                    )
                                } else {
                                    (
                                        base_title,
                                        format!("Dziennik NTFS USN Journal zarejestrował usunięcie pliku: {}", file_name),
                                    )
                                };

                                if reported_files.insert(format!("{}_{}", if is_rename_old { "ren" } else { "del" }, lower)) {
                                    deleted_files_found += 1;
                                    let timestamp_str = super::format_filetime(header.timestamp as u64)
                                        .unwrap_or_else(|| "Unknown".to_string());

                                    let scope_desc = if in_current_session {
                                        if is_rename_old {
                                            "Bieżąca sesja systemu (zmieniono nazwę PO starcie PC / tuż przed sprawdzeniem)"
                                        } else {
                                            "Bieżąca sesja systemu (usunięty PO starcie PC / tuż przed sprawdzeniem)"
                                        }
                                    } else {
                                        "Poprzednia sesja systemu"
                                    };

                                    let category = if title.contains("Anti-Forensics") || is_rename_old {
                                        FindingCategory::TamperingAndAntiForensics
                                    } else {
                                        FindingCategory::WindowsForensics
                                    };

                                    let mut finding = ScanFinding::new(
                                        title,
                                        category,
                                        verdict,
                                        desc,
                                    )
                                    .with_evidence("Nazwa pliku", file_name)
                                    .with_evidence("Czas operacji", timestamp_str)
                                    .with_evidence("Operacja NTFS", if is_rename_old { "RENAME (Przemianowanie pliku)".to_string() } else { "DELETE (Usunięcie pliku)".to_string() })
                                    .with_evidence("Zakres sesji", scope_desc.to_string())
                                    .with_evidence("USN", header.usn.to_string())
                                    .with_evidence("Partycja", format!("{}:", drive_letter));

                                    if let Some(trig) = matched_trigger {
                                        finding = finding.with_evidence("Matched Keyword", trig.to_string());
                                    }

                                    report.add(finding);

                                    if deleted_files_found >= 25 {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                offset += header.record_length as usize;
            }

            if deleted_files_found >= 20 {
                break;
            }
        }

        CloseHandle(handle);
    }
}

fn evaluate_deleted_file(name: &str, in_current_session: bool) -> Option<(VerdictLevel, &'static str, Option<&'static str>)> {
    let lower = name.to_lowercase();

        // Ignore deletions prior to last PC reboot and trusted files
    if !in_current_session || super::is_whitelisted_executable(&lower) {
        return None;
    }

    let cheat_triggers = [
        "vape", "drip", "ravenbplus", "raven_b", "ravenclient", "slinky", "kura", "ghostclient",
        "ghost_client", "autoclicker", "dopeclicker", "inject", "reach_mod", "reachmod",
        "velocity_mod", "velocitymod", "hitbox_mod", "hitboxmod", "vengeance",
        "astralclient", "astral_client", "epstein", "calcium", "dclient", "dqrkis", "darkis", "trillium",
        "argonclient", "argon_client", "lvstrng", "noxx", "pulseclient", "pulse_client", "pulse-client",
        "22qq", "22qqclient", "22qq_client", "meraclient", "mera_client", "mera-client",
        "loader", "cheat", "cleaner", "destruct", "selfdestruct", "self_destruct",
        "journal_clean", "usn_clean", "bypass", "breeze", "liquidbounce",
    ];

    let mut matched_trigger = None;
    for t in &cheat_triggers {
        if super::is_cheat_keyword_match(&lower, t) {
            // Zabezpieczenie przed false-positive:
            if *t == "cheat" && lower.contains("anti") {
                continue;
            }
            if *t == "loader" && (lower.contains("webview") || lower.contains("upload") || lower.contains("download") || lower.contains("library") || lower.contains("vulkan")) {
                continue;
            }
            matched_trigger = Some(*t);
            break;
        }
    }

        // 1. Mod / loader .jar files (deleted in current session)
    if lower.ends_with(".jar") {
        if matched_trigger.is_some() {
            return Some((
                VerdictLevel::Detection,
                "Cheat Loader / Mod Deleted in Current Session (USN Journal Trace)",
                matched_trigger,
            ));
        } else {
            // Any .jar file deleted in current session after PC boot raises critical suspicion (loader self-destruct)
            return Some((
                VerdictLevel::Detection,
                "Minecraft .jar Mod/Loader Deleted in Current Session (Self-Destruct Trace)",
                None,
            ));
        }
    }

        // 2. Executable .dll / .exe files (deleted in current session)
    if lower.ends_with(".dll") || lower.ends_with(".exe") {
        if matched_trigger.is_some() {
            return Some((
                VerdictLevel::Detection,
                "Cheat Executable/DLL Deleted in Current Session (USN Journal Trace)",
                matched_trigger,
            ));
        } else {
            // Flag any binary executable or DLL deleted during current session to catch neutral-named loaders (e.g. AudioServiceHelper.exe)
            return Some((
                VerdictLevel::Warning,
                "Binary Executable/DLL Deleted in Current Session (Anti-Forensics / Trace Wiping)",
                None,
            ));
        }
    }

        // 3. Cleanup scripts / batch (.bat, .cmd, .ps1) (deleted in current session)
    if lower.ends_with(".bat") || lower.ends_with(".cmd") || lower.ends_with(".ps1") {
        if let Some(trig) = matched_trigger {
            return Some((
                VerdictLevel::Detection,
                "Self-Destruct / Cleaner Script Deleted in Current Session (USN Journal)",
                Some(trig),
            ));
        }
    }

        // 4. Deletion of Windows boot log file ntbtlog.txt (Item 1)
    if lower == "ntbtlog.txt" {
        return Some((
            VerdictLevel::Detection,
            "Windows Boot Log (ntbtlog.txt) Deleted in Current Session (Anti-Forensics)",
            Some("ntbtlog_wipe"),
        ));
    }

        // 5. Deletion of Windows Event Log files (.evtx / .etl) (Item 2)
    if lower.ends_with(".evtx") || (lower.ends_with(".etl") && (lower.contains("event") || lower.contains("boot") || lower.contains("diag") || lower.contains("trace"))) {
        return Some((
            VerdictLevel::Detection,
            "Windows Event Log File Deleted in Current Session (Anti-Forensics)",
            Some("event_log_wipe"),
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_deleted_loader_jar() {
        let res = evaluate_deleted_file("my_loader.jar", true);
        assert!(res.is_some());
        let (verdict, title, trig) = res.unwrap();
        assert_eq!(verdict, VerdictLevel::Detection);
        assert_eq!(title, "Cheat Loader / Mod Deleted in Current Session (USN Journal Trace)");
        assert_eq!(trig, Some("loader"));
    }

    #[test]
    fn test_evaluate_deleted_generic_jar_current_session() {
        let res = evaluate_deleted_file("custom_archive.jar", true);
        assert!(res.is_some());
        let (verdict, title, _) = res.unwrap();
        assert_eq!(verdict, VerdictLevel::Detection);
        assert_eq!(title, "Minecraft .jar Mod/Loader Deleted in Current Session (Self-Destruct Trace)");
    }

    #[test]
    fn test_evaluate_deleted_generic_jar_past_session() {
        let res = evaluate_deleted_file("custom_archive.jar", false);
        assert!(res.is_none(), "Normal generic jar deleted in past session should not be flagged");
    }

    #[test]
    fn test_evaluate_deleted_cheat_past_session_ignored() {
        let res = evaluate_deleted_file("vape_v4.exe", false);
        assert!(res.is_none(), "Cheat executed/deleted before reboot (past session) must be ignored");
    }

    #[test]
    fn test_evaluate_deleted_legitimate_windows_files_not_flagged() {
        assert!(evaluate_deleted_file("api-ms-win-core-libraryloader-l1-1-0.dll", true).is_none());
        assert!(evaluate_deleted_file("LogUploader.dll", true).is_none());
        assert!(evaluate_deleted_file("OneDrivePatcher.exe", true).is_none());
        assert!(evaluate_deleted_file("WebView2Loader.dll", true).is_none());
    }

    #[test]
    fn test_evaluate_deleted_ntbtlog_current_session() {
        let res = evaluate_deleted_file("ntbtlog.txt", true);
        assert!(res.is_some());
        let (verdict, title, _) = res.unwrap();
        assert_eq!(verdict, VerdictLevel::Detection);
        assert_eq!(title, "Windows Boot Log (ntbtlog.txt) Deleted in Current Session (Anti-Forensics)");
    }

    #[test]
    fn test_evaluate_deleted_ntbtlog_past_session_ignored() {
        assert!(evaluate_deleted_file("ntbtlog.txt", false).is_none());
    }

    #[test]
    fn test_evaluate_deleted_evtx_current_session() {
        let res = evaluate_deleted_file("System.evtx", true);
        assert!(res.is_some());
        let (verdict, title, _) = res.unwrap();
        assert_eq!(verdict, VerdictLevel::Detection);
        assert_eq!(title, "Windows Event Log File Deleted in Current Session (Anti-Forensics)");
    }

    #[test]
    fn test_evaluate_deleted_evtx_past_session_ignored() {
        assert!(evaluate_deleted_file("System.evtx", false).is_none());
    }

    #[test]
    fn test_evaluate_deleted_neutral_binary_current_session() {
        let res = evaluate_deleted_file("AudioServiceHelper.exe", true);
        assert!(res.is_some(), "Neutral named binary deleted in current session must be flagged");
        let (verdict, title, trig) = res.unwrap();
        assert_eq!(verdict, VerdictLevel::Warning);
        assert_eq!(title, "Binary Executable/DLL Deleted in Current Session (Anti-Forensics / Trace Wiping)");
        assert_eq!(trig, None);

        // Verify that past session neutral binary is ignored
        assert!(evaluate_deleted_file("AudioServiceHelper.exe", false).is_none());
    }

}
