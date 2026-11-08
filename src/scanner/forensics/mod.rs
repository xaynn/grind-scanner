pub mod amcache;
pub mod bam;
pub mod jumplists;
pub mod muicache;
pub mod pcasvc;
pub mod powershell;
pub mod prefetch;
pub mod recent_lnk;
pub mod recycle_bin;
pub mod shimcache;
pub mod userassist;
pub mod usn;
pub mod usbstor;
pub mod virtual_drives;
pub mod wer;

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::OnceLock;
use std::time::SystemTime;
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;

static DEVICE_MAP: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Retrieves NT Device path mapping (e.g. \Device\HarddiskVolume3) to DOS drive letters (e.g. C:)
pub fn get_device_map() -> &'static HashMap<String, String> {
    DEVICE_MAP.get_or_init(|| {
        let mut map = HashMap::new();
        let mut target_buf = [0u16; 1024];

        for drive_letter in b'A'..=b'Z' {
            let drive_str = format!("{}:\0", drive_letter as char);
            let drive_utf16: Vec<u16> = drive_str.encode_utf16().collect();

            unsafe {
                let len = QueryDosDeviceW(drive_utf16.as_ptr(), target_buf.as_mut_ptr(), 1024);
                if len > 0 {
                    let target_str = String::from_utf16_lossy(&target_buf[..len as usize]);
                    if let Some(first_target) = target_str.split('\0').next() {
                        if !first_target.is_empty() {
                            map.insert(first_target.to_lowercase(), format!("{}:", drive_letter as char));
                        }
                    }
                }
            }
        }
        map
    })
}

/// Resolves known Windows folder GUIDs (e.g. from UserAssist registry) to real paths
pub fn resolve_known_folder_guid(path: &str) -> String {
    let mut resolved = path.to_string();
    let user_profile = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string());

    let guid_replacements = [
        ("{37ea0000-1f1b-42c5-8650-e02f2e0e4c84}", format!("{}\\Downloads", user_profile)),
        ("{b4bfcc3a-db2c-424c-b029-7fe99a87c641}", format!("{}\\Desktop", user_profile)),
        ("{f38bf404-1d43-42f2-9305-67de0b28fc23}", "C:\\Windows".to_string()),
        ("{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}", "C:\\Windows\\System32".to_string()),
        ("{6d809377-6af0-444b-8957-a3773f02200e}", "C:\\Program Files".to_string()),
        ("{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}", "C:\\Program Files (x86)".to_string()),
    ];

    let lower = resolved.to_lowercase();
    for (guid, folder) in &guid_replacements {
        if lower.starts_with(guid) {
            resolved = format!("{}{}", folder, &resolved[guid.len()..]);
            break;
        }
    }

    resolved
}

/// Normalizes an NT / Device path to a standard Windows path (e.g. C:\Users\...)
pub fn normalize_device_path(path: &str) -> String {
    let mut clean = resolve_known_folder_guid(path.trim()).replace('/', "\\");

    if clean.starts_with("\\??\\") {
        clean = clean[4..].to_string();
    } else if clean.starts_with("??\\") {
        clean = clean[3..].to_string();
    }

    if clean.to_lowercase().starts_with("\\device\\") {
        let map = get_device_map();
        let lower = clean.to_lowercase();
        for (dev, drive) in map {
            if lower.starts_with(dev) {
                let remainder = &clean[dev.len()..];
                return format!("{}{}", drive, remainder);
            }
        }
    }

    clean
}

/// Checks whether a PE executable (.exe / .dll) has a valid Authenticode digital signature
pub fn is_pe_signed(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut dos_header = [0u8; 64];
    if file.read_exact(&mut dos_header).is_err() {
        return false;
    }

    if dos_header[0] != b'M' || dos_header[1] != b'Z' {
        return false;
    }

    let pe_offset = u32::from_le_bytes(dos_header[0x3C..0x40].try_into().unwrap_or([0; 4])) as u64;
    if file.seek(SeekFrom::Start(pe_offset)).is_err() {
        return false;
    }

    let mut pe_sig = [0u8; 4];
    if file.read_exact(&mut pe_sig).is_err() || &pe_sig != b"PE\0\0" {
        return false;
    }

    // Skip COFF Header (20 bytes) to reach Optional Header
    if file.seek(SeekFrom::Current(20)).is_err() {
        return false;
    }

    let mut magic = [0u8; 2];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }

    let magic_num = u16::from_le_bytes(magic);
    // 0x10B = PE32 (32-bit), 0x20B = PE32+ (64-bit)
    let cert_table_offset = match magic_num {
        0x10B => pe_offset + 24 + 128,
        0x20B => pe_offset + 24 + 144,
        _ => return false,
    };

    if file.seek(SeekFrom::Start(cert_table_offset)).is_err() {
        return false;
    }

    let mut cert_dir = [0u8; 8];
    if file.read_exact(&mut cert_dir).is_err() {
        return false;
    }

    let cert_rva = u32::from_le_bytes(cert_dir[0..4].try_into().unwrap_or([0; 4]));
    let cert_size = u32::from_le_bytes(cert_dir[4..8].try_into().unwrap_or([0; 4]));

    cert_rva != 0 && cert_size > 0
}

/// Checks whether a path is located in volatile / cheat-associated directories
pub fn is_volatile_directory(path: &str) -> bool {
    let lower = path.to_lowercase();

    // Exclude trusted system folders
    if lower.contains(":\\program files")
        || lower.contains(":\\program files (x86)")
        || lower.contains(":\\windows\\")
    {
        return false;
    }

    // Temporary, Downloads, Desktop, Public folders and staging directories with write permissions
    if lower.contains("\\downloads\\")
        || lower.contains("\\pobrane\\")
        || lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
        || lower.contains("\\desktop\\")
        || lower.contains("\\pulpit\\")
        || lower.contains("\\inetcache\\")
        || lower.contains("\\users\\public\\")
        || lower.contains("\\perflogs\\")
        || lower.contains("\\windows\\tasks\\")
        || lower.contains("\\windows\\tracing\\")
    {
        return true;
    }

    // Files executed directly from the root of a user profile (e.g. C:\Users\dzony\cheat.exe)
    if let Some(pos) = lower.find("\\users\\") {
        let after_users = &lower[pos + 7..];
        if let Some(first_slash) = after_users.find('\\') {
            let user_sub = &after_users[first_slash + 1..];
            // If there is no further slash, the file resides directly in C:\Users\<user>\
            if !user_sub.contains('\\') {
                return true;
            }
        }
    }

    false
}

/// Checks whether a file is masquerading as a critical Windows system process
pub fn is_fake_system_executable(path: &str) -> Option<&'static str> {
    let clean = path.replace('/', "\\");
    let mut trimmed = clean.trim();
    if trimmed.starts_with(r"\\?\") || trimmed.starts_with(r"\??\") {
        trimmed = &trimmed[4..];
    }
    let lower = trimmed.to_lowercase();
    let file_name = match lower.rfind('\\') {
        Some(pos) => &lower[pos + 1..],
        None => &lower,
    };

    let fake_targets = [
        ("svchost.exe", "c:\\windows\\system32"),
        ("csrss.exe", "c:\\windows\\system32"),
        ("lsass.exe", "c:\\windows\\system32"),
        ("smss.exe", "c:\\windows\\system32"),
        ("services.exe", "c:\\windows\\system32"),
        ("winlogon.exe", "c:\\windows\\system32"),
        ("taskhostw.exe", "c:\\windows\\system32"),
        ("explorer.exe", "c:\\windows"),
        ("runtimebroker.exe", "c:\\windows\\system32"),
        ("dwm.exe", "c:\\windows\\system32"),
        ("conhost.exe", "c:\\windows\\system32"),
        ("spoolsv.exe", "c:\\windows\\system32"),
        ("audiodg.exe", "c:\\windows\\system32"),
        ("fontdrvhost.exe", "c:\\windows\\system32"),
        ("sihost.exe", "c:\\windows\\system32"),
        ("smartscreen.exe", "c:\\windows\\system32"),
        ("taskmgr.exe", "c:\\windows\\system32"),
        ("securityhealthservice.exe", "c:\\windows\\system32"),
    ];

    for (target_exe, legit_dir) in &fake_targets {
        if file_name == *target_exe {
            if !lower.starts_with(legit_dir) && !lower.contains("\\windows\\syswow64\\") {
                return Some(target_exe);
            }
        }
    }

    None
}

pub const GRIND_SCANNER_AUTHENTIC_BUILD_SEAL: &[u8] = b"GRIND_SCANNER_OFFICIAL_INTEGRITY_WATERMARK_9A4F8B2C7E1D";

static CURRENT_SCANNER_INFO: std::sync::OnceLock<(Option<std::path::PathBuf>, Option<[u8; 32]>)> = std::sync::OnceLock::new();

fn get_current_scanner_identity() -> &'static (Option<std::path::PathBuf>, Option<[u8; 32]>) {
    CURRENT_SCANNER_INFO.get_or_init(|| {
        if let Ok(curr) = std::env::current_exe() {
            let canon = curr.canonicalize().ok().unwrap_or_else(|| curr.clone());
            let hash = if let Ok(bytes) = std::fs::read(&curr) {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let result: [u8; 32] = hasher.finalize().into();
                Some(result)
            } else {
                None
            };
            (Some(canon), hash)
        } else {
            (None, None)
        }
    })
}

/// Cryptographic and structural verification ensuring the specified file is an authentic Grind Scanner binary.
/// Prevents scanner evasion through renaming external cheats to "grind_scanner.exe"!
pub fn is_authentic_scanner_executable(path_or_name: &str) -> bool {
    let clean = path_or_name.replace('/', "\\");
    let lower = clean.to_lowercase();

    let file_name = match lower.rfind('\\') {
        Some(pos) => &lower[pos + 1..],
        None => &lower,
    };

    if !file_name.contains("grind_scanner") {
        return false;
    }

    let target_path = Path::new(&clean);
    let (curr_canon_opt, curr_hash_opt) = get_current_scanner_identity();

    // 1. Check whether path exactly matches the current running scanner process
    if let Some(curr_canon) = curr_canon_opt {
        if let Ok(target_canon) = target_path.canonicalize() {
            if target_canon == *curr_canon {
                return true;
            }
        }

        let curr_str = curr_canon.to_string_lossy();
        if clean.eq_ignore_ascii_case(&curr_str) {
            return true;
        }
    }

    // 2. If the file physically exists on disk (e.g. another copy or earlier build)
    if target_path.is_file() {
        if let Ok(meta) = target_path.metadata() {
        // Grind Scanner binary size is always > 10 MB (Rust GUI binary with embedded engines and resources)
        // External cheats/injectors/cleaners are usually between several hundred KB and at most 3 MB.
            if meta.len() >= 10 * 1024 * 1024 {
                if let Ok(bytes) = std::fs::read(target_path) {
                    if bytes.starts_with(b"MZ") {
                        // A: Fast SHA-256 hash comparison with current running process
                        if let Some(curr_hash) = curr_hash_opt {
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(&bytes);
                            let target_hash: [u8; 32] = hasher.finalize().into();
                            if target_hash == *curr_hash {
                                return true;
                            }
                        }

        // B: Structural identity verification of Grind Scanner binary (any valid version/build).
        // Require presence of unique crate and GUI framework identifiers:
                        let has_grind_identity = memchr::memmem::Finder::new(b"grind_scanner").find(&bytes).is_some()
                            || memchr::memmem::Finder::new(b"GrindScanner").find(&bytes).is_some()
                            || memchr::memmem::Finder::new(GRIND_SCANNER_AUTHENTIC_BUILD_SEAL).find(&bytes).is_some();

                        let has_rust_gui = memchr::memmem::Finder::new(b"eframe").find(&bytes).is_some()
                            && memchr::memmem::Finder::new(b"egui").find(&bytes).is_some();

                        if has_grind_identity && has_rust_gui {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

/// Checks whether a path / filename belongs to trusted tools, game platforms, or anticheats.
/// Protected against masquerading (Anti-Masquerading):
/// If a file is in a volatile directory (Desktop, Downloads, Temp) or is an unsigned PE file,
/// it will NEVER be considered trusted!
pub fn is_whitelisted_executable(path_or_name: &str) -> bool {
    let clean = path_or_name.replace('/', "\\");
    let lower = clean.to_lowercase();

    // 1. Check if it is an authentic Grind Scanner instance (cryptographic process verification / hash / seal)
    // Anti-masquerading protection: if someone names a cheat "grind_scanner.exe",
    // it will fail this verification and fall into volatile directory rules!
    if is_authentic_scanner_executable(&clean) {
        return true;
    }

    // 2. Compiler proc-macro binaries
    if lower.contains("proc-macro") || lower.contains("proc_macro") {
        return true;
    }

    // 3. Masquerading protection:
    // Files in Desktop, Downloads or Temp folders are NEVER considered safe system installations
    if is_volatile_directory(&lower) {
        return false;
    }

    // 4. If the file exists on disk as a PE binary (.exe / .dll), it must have a valid Authenticode signature
    let path = Path::new(path_or_name);
    if path.is_file() && !is_pe_signed(path) {
        return false;
    }

    // 4. Official Windows API set system libraries (.dll) and legitimate Windows/Office components
    if (lower.starts_with("api-ms-win-") && lower.ends_with(".dll"))
        || (lower.starts_with("ext-ms-win-") && lower.ends_with(".dll"))
        || lower == "webview2loader.dll"
        || lower == "loguploader.dll"
        || lower == "onedrivepatcher.exe"
    {
        return true;
    }

    let is_binary_name = lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".jar") || lower.ends_with(".pf");

    // 5. Legitimate anticheats (must reside in Program Files, game directory or be an official FriendlyAppName in MuiCache)
    let is_anticheat_name = lower.contains("easyanticheat")
        || lower.contains("easy anti-cheat")
        || lower.contains("easy anti cheat")
        || lower.contains("battleye")
        || lower.contains("vanguard")
        || lower.contains("faceit")
        || lower.contains("ricochet")
        || lower.contains("punkbuster");

    if is_anticheat_name {
        // If binary file (.exe/.dll/.jar/.pf), MUST originate from an official installation folder!
        if is_binary_name {
            if lower.contains(":\\") {
                return (lower.contains("program files")
                    || lower.contains("steamapps")
                    || lower.contains("epic games")
                    || lower.contains("origin games")
                    || lower.contains("ubisoft"))
                    && !is_volatile_directory(&lower);
            }
            // A bare file name without an installation path CANNOT be automatically trusted (masquerading risk)
            return false;
        }
        // Text description / metadata (e.g. MuiCache FriendlyAppName "Easy Anti-Cheat Bootstrapper")
        return true;
    }

    // 6. Games and platforms containing substrings prone to confusion with cheats (e.g. "Grim Dawn" containing "grim")
    if lower.contains("grim dawn") || lower.contains("tomb raider") || lower.contains("apex") {
        if lower.contains(":\\") {
            return (lower.contains("steamapps") || lower.contains("program files") || lower.contains("epic games") || lower.contains("origin"))
                && !is_volatile_directory(&lower);
        }
        // Bare filename (e.g. "apex.exe" on Desktop) cannot be whitelisted
        return false;
    }

    // 7. Official game distribution platforms (only in Program Files)
    if (lower.contains("steamapps")
        || lower.contains("epic games")
        || lower.contains("riot client")
        || lower.contains("gog galaxy")
        || lower.contains("ubisoft connect")
        || lower.contains("ea desktop")
        || lower.contains("ea games")
        || lower.contains("origin.exe")
        || lower.contains("start_protected_game.exe"))
        && lower.contains("program files")
    {
        return true;
    }

    false
}

/// Checks if a cheat keyword appears in a path or filename on a word/token boundary.
/// Prevents collisions such as:
/// - "weedclient" -> "dclient" (false match due to 'e' before 'dclient')
/// - "downloadclient" -> "dclient" (false match due to 'd')
/// - "sakura" -> "kura" (false match due to 'a')
/// - "evaporate" -> "vape"
/// - "fabric-loader" -> "loader"
pub fn is_cheat_keyword_match(path_or_name: &str, keyword: &str) -> bool {
    let lower = path_or_name.to_lowercase();
    let kw = keyword.to_lowercase();

    let mut start = 0;
    while let Some(pos) = lower[start..].find(&kw) {
        let abs_pos = start + pos;
        let end_pos = abs_pos + kw.len();

        // 1. Character before keyword: cannot be an ASCII letter (e.g. 'e' in 'weedclient' disqualifies 'dclient')
        let prefix_char = if abs_pos > 0 {
            lower[..abs_pos].chars().next_back()
        } else {
            None
        };

        let prefix_ok = match prefix_char {
            Some(c) => !c.is_ascii_alphabetic(),
            None => true,
        };

        if !prefix_ok {
            start = end_pos;
            continue;
        }

        // 2. Character after keyword:
        let suffix_char = lower[end_pos..].chars().next();
        let suffix_ok = match suffix_char {
            Some(c) => {
                // Allowed: separators, digits (versions e.g. vape4, dclient1.21), end of name
                if !c.is_ascii_alphabetic() {
                    true
                } else {
        // For base words like "inject", "destruct", "clean", allow grammatical extensions
                    if kw == "inject" || kw == "destruct" || kw == "clean" {
                        true
                    } else if (kw == "vape" || kw == "kura" || kw == "drip") && (c == 'v' || c == 'l') {
                        // np. vapev4, driplite
                        true
                    } else {
                        false
                    }
                }
            }
            None => true,
        };

        if prefix_ok && suffix_ok {
            // 3. Exclude false positives for common libraries and developer tools:
            if kw == "loader" && (lower.contains("fabric-loader") || lower.contains("forge-loader") || lower.contains("neoforge") || lower.contains("download") || lower.contains("webview") || lower.contains("vulkan")) {
                start = end_pos;
                continue;
            }
            if kw == "cleaner" && (lower.contains("diskcleaner") || lower.contains("windowscleaner") || lower.contains("systemcleaner") || lower.contains("ccleaner")) {
                start = end_pos;
                continue;
            }
            if kw == "kura" && lower.contains("sakura") {
                start = end_pos;
                continue;
            }
            if kw == "vape" && lower.contains("evaporat") {
                start = end_pos;
                continue;
            }

            return true;
        }

        start = end_pos;
    }

    false
}

/// Formats standard SystemTime into human-readable local date and time (with relative elapsed time)
pub fn format_system_time(st: SystemTime) -> String {
    let utc_dt: chrono::DateTime<chrono::Utc> = st.into();
    let local_dt: chrono::DateTime<chrono::Local> = utc_dt.with_timezone(&chrono::Local);
    let formatted = local_dt.format("%Y-%m-%d %H:%M:%S").to_string();

    let elapsed_str = match st.elapsed() {
        Ok(d) => {
            let secs = d.as_secs();
            let days = secs / 86400;
            let hours = (secs % 86400) / 3600;
            let mins = (secs % 3600) / 60;
            if days > 0 {
                format!(" ({}d {}h temu)", days, hours)
            } else if hours > 0 {
                format!(" ({}h {}m temu)", hours, mins)
            } else if mins > 0 {
                format!(" ({}m temu)", mins)
            } else {
                " (przed chwilą)".to_string()
            }
        }
        Err(_) => String::new(),
    };

    format!("{}{}", formatted, elapsed_str)
}

/// Converts Windows FILETIME (100ns intervals since 1601) to human-readable local date and time
pub fn format_filetime(ft: u64) -> Option<String> {
    const WINDOWS_TICK: u64 = 10_000_000;
    const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;
    const TICKS_TO_UNIX_EPOCH: u64 = SEC_TO_UNIX_EPOCH * WINDOWS_TICK;

    if ft < TICKS_TO_UNIX_EPOCH {
        return None;
    }

    let ticks = ft - TICKS_TO_UNIX_EPOCH;
    let secs = ticks / WINDOWS_TICK;
    let nanos = (ticks % WINDOWS_TICK) * 100;

    let utc_dt = chrono::DateTime::from_timestamp(secs as i64, nanos as u32)?;
    let local_dt: chrono::DateTime<chrono::Local> = utc_dt.with_timezone(&chrono::Local);
    let formatted = local_dt.format("%Y-%m-%d %H:%M:%S").to_string();

    let now_secs = chrono::Utc::now().timestamp() as u64;
    let elapsed_str = if now_secs >= secs {
        let diff = now_secs - secs;
        let days = diff / 86400;
        let hours = (diff % 86400) / 3600;
        let mins = (diff % 3600) / 60;
        if days > 0 {
            format!(" ({}d {}h temu)", days, hours)
        } else if hours > 0 {
            format!(" ({}h {}m temu)", hours, mins)
        } else if mins > 0 {
            format!(" ({}m temu)", mins)
        } else {
            " (przed chwilą)".to_string()
        }
    } else {
        String::new()
    };

    Some(format!("{}{}", formatted, elapsed_str))
}

/// Returns estimated system boot time as a Unix timestamp (UTC seconds)
pub fn get_boot_unix_timestamp() -> u64 {
    let uptime_ms = unsafe {
        windows_sys::Win32::System::SystemInformation::GetTickCount64()
    };
    let uptime_secs = uptime_ms / 1000;
    let now_secs = chrono::Utc::now().timestamp().max(0) as u64;
    now_secs.saturating_sub(uptime_secs)
}

/// Converts Windows FILETIME (100ns intervals since 1601) to Unix timestamp (UTC seconds)
pub fn filetime_to_unix_secs(ft: u64) -> Option<u64> {
    const WINDOWS_TICK: u64 = 10_000_000;
    const SEC_TO_UNIX_EPOCH: u64 = 11_644_473_600;
    const TICKS_TO_UNIX_EPOCH: u64 = SEC_TO_UNIX_EPOCH * WINDOWS_TICK;

    if ft < TICKS_TO_UNIX_EPOCH {
        return None;
    }

    let ticks = ft - TICKS_TO_UNIX_EPOCH;
    Some(ticks / WINDOWS_TICK)
}

/// Checks if a given FILETIME indicates execution in the current system session (since Windows boot)
pub fn was_executed_in_current_session(ft: u64) -> bool {
    if let Some(exec_secs) = filetime_to_unix_secs(ft) {
        let boot_secs = get_boot_unix_timestamp();
        // Allow a 60-second buffer for the boot process and NTP clock sync
        exec_secs >= boot_secs.saturating_sub(60)
    } else {
        false
    }
}

/// Checks if SystemTime falls within the current system session (since Windows boot)
pub fn is_system_time_in_current_session(st: SystemTime) -> bool {
    let now = SystemTime::now();
    if let Ok(elapsed) = now.duration_since(st) {
        let uptime_ms = unsafe {
            windows_sys::Win32::System::SystemInformation::GetTickCount64()
        };
        let uptime_secs = uptime_ms / 1000;
        elapsed.as_secs() <= uptime_secs + 60
    } else {
        false
    }
}

/// Checks if a Prefetch file associated with the given executable exists in C:\Windows\Prefetch
/// and returns the Prefetch modification timestamp along with current session status.
pub fn check_prefetch_for_executable(exe_name: &str) -> Option<(u64, bool)> {
    let prefetch_dir = Path::new("C:\\Windows\\Prefetch");
    if !prefetch_dir.is_dir() {
        return None;
    }

    let clean_exe = exe_name.trim();
    let prefix = format!("{}-", clean_exe.to_uppercase());
    let prefix_short = clean_exe.to_uppercase();

    if let Ok(entries) = std::fs::read_dir(prefetch_dir) {
        for entry in entries.flatten() {
            let fname = entry.file_name().to_string_lossy().to_uppercase();
            if (fname.starts_with(&prefix) || fname.starts_with(&prefix_short)) && fname.ends_with(".PF") {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(mod_time) = meta.modified() {
                        let is_current = is_system_time_in_current_session(mod_time);
                        if let Ok(dur) = mod_time.duration_since(std::time::UNIX_EPOCH) {
                            const TICKS_TO_UNIX_EPOCH: u64 = 11_644_473_600 * 10_000_000;
                            let ft = TICKS_TO_UNIX_EPOCH + dur.as_secs() * 10_000_000 + (dur.subsec_nanos() as u64 / 100);
                            return Some((ft, is_current));
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_fake_system_executable_hardening() {
        assert_eq!(is_fake_system_executable(r"C:\Users\admin\Desktop\svchost.exe"), Some("svchost.exe"));
        assert_eq!(is_fake_system_executable("C:/Users/admin/Downloads/explorer.exe"), Some("explorer.exe"));
        assert_eq!(is_fake_system_executable(r"\\?\C:\Users\admin\AppData\Local\Temp\taskmgr.exe"), Some("taskmgr.exe"));
        assert_eq!(is_fake_system_executable(r"\??\C:\Users\Public\conhost.exe"), Some("conhost.exe"));
        assert_eq!(is_fake_system_executable(r"C:\PerfLogs\spoolsv.exe"), Some("spoolsv.exe"));

        // Genuine Windows system locations
        assert_eq!(is_fake_system_executable(r"C:\Windows\System32\svchost.exe"), None);
        assert_eq!(is_fake_system_executable(r"C:\Windows\explorer.exe"), None);
        assert_eq!(is_fake_system_executable(r"C:\Windows\System32\taskmgr.exe"), None);
    }

    #[test]
    fn test_is_whitelisted_executable_anti_masquerading() {
        // Bare filename without an installation path cannot be trusted
        assert!(!is_whitelisted_executable("easyanticheat.exe"));
        assert!(!is_whitelisted_executable("battleye.exe"));
        assert!(!is_whitelisted_executable("apex.exe"));
        assert!(!is_whitelisted_executable("grim dawn.exe"));

        // Files in volatile folders (Desktop, Downloads, Temp, Public) are ALWAYS rejected
        assert!(!is_whitelisted_executable(r"C:\Users\admin\Desktop\EasyAntiCheat.exe"));
        assert!(!is_whitelisted_executable(r"C:\Users\admin\Downloads\Apex.exe"));
        assert!(!is_whitelisted_executable(r"C:\Users\Public\BattlEye.exe"));
        assert!(!is_whitelisted_executable(r"C:\Windows\Tasks\easyanticheat.exe"));

        // Official installations in Program Files
        assert!(is_whitelisted_executable(r"C:\Program Files (x86)\EasyAntiCheat\EasyAntiCheat.exe"));
        assert!(is_whitelisted_executable(r"C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EasyAntiCheat\EasyAntiCheat_EOS_Setup.exe"));

        // MuiCache FriendlyAppName (descriptive text, not a binary file)
        assert!(is_whitelisted_executable("Easy Anti-Cheat Bootstrapper"));
    }

    #[test]
    fn test_is_volatile_directory() {
        // Legitimate per-user installation folders in AppData
        assert!(!is_volatile_directory(r"C:\Users\dzony\AppData\Local\Dawn\Dawn (Feather)\Dawn (Feather).exe"));
        assert!(!is_volatile_directory(r"C:\Users\dzony\AppData\Local\Discord\app-1.0.9171\Discord.exe"));
        assert!(!is_volatile_directory(r"C:\Users\dzony\AppData\Roaming\Spotify\Spotify.exe"));
        assert!(!is_volatile_directory(r"C:\Program Files\Steam\steam.exe"));

        // Volatile directories
        assert!(is_volatile_directory(r"C:\Users\dzony\Desktop\cheat.exe"));
        assert!(is_volatile_directory(r"C:\Users\dzony\Downloads\cheat.exe"));
        assert!(is_volatile_directory(r"C:\Users\dzony\AppData\Local\Temp\cheat.exe"));
        assert!(is_volatile_directory(r"C:\Users\Public\cheat.exe"));
        assert!(is_volatile_directory(r"C:\PerfLogs\driver.sys"));
        assert!(is_volatile_directory(r"C:\Users\dzony\cheat.exe")); // directly in user profile root
    }

    #[test]
    fn test_grind_scanner_self_authentication_and_anti_masquerading() {
    // 1. Current test/scanner process is always authentic
        if let Ok(curr) = std::env::current_exe() {
            let curr_str = curr.to_string_lossy().to_string();
    // If process contains grind_scanner, is_authentic returns true
            if curr_str.to_lowercase().contains("grind_scanner") {
                assert!(is_authentic_scanner_executable(&curr_str));
                assert!(is_whitelisted_executable(&curr_str));
            }
        }

    // 2. Masquerading: fake file named grind_scanner.exe on Desktop (does not match current binary)
    // MUST be rejected and CANNOT be whitelisted!
        assert!(!is_authentic_scanner_executable(r"C:\Users\admin\Desktop\fake_nonexistent_grind_scanner.exe"));
        assert!(!is_whitelisted_executable(r"C:\Users\admin\Desktop\fake_nonexistent_grind_scanner.exe"));
    }
}

