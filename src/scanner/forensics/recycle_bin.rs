use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct RecycleBinRecord {
    pub original_path: String,
    pub original_size: u64,
    pub deletion_filetime: u64,
    pub i_file_path: PathBuf,
    pub r_file_exists: bool,
    pub in_current_session: bool,
}

/// Skanuje foldery Kosza systemowego ($Recycle.Bin) na wszystkich dyskach (C:-Z:)
/// w celu wykrycia usuniętych plików wykonywalnych cheatów, cleanerów oraz skryptów niszczących.
pub fn scan_recycle_bin(report: &mut ScanReport) {
    let mut scanned_records = Vec::new();

    // Sprawdź litery dysków od C do Z
    for drive_letter in b'C'..=b'Z' {
        let recycle_root = format!("{}:\\$Recycle.Bin", drive_letter as char);
        let path = Path::new(&recycle_root);
        if path.is_dir() {
            scan_drive_recycle_bin(path, &mut scanned_records);
        }
    }

    let suspicious_keywords = [
        "vape", "drip", "ravenbplus", "raven_b", "ravenclient", "slinky", "kura", "autoclicker",
        "dopeclicker", "vroomclicker", "inject", "cheat", "processhacker", "doomsday", "prestige",
        "imnotcheatingyouare", "marlow", "liquidbounce", "grimclient", "grim_client", "riseclient",
        "rise_client", "pulsarclient", "solarclient", "solar_client", "vengeance", "astralclient",
        "astral_client", "epstein", "calcium", "dclient", "dqrkis", "darkis", "trillium",
        "argonclient", "argon_client", "lvstrng", "noxx", "pulseclient", "pulse_client", "22qq",
        "meraclient", "cleaner", "wipe", "destruct", "self_destruct", "journal_clean", "usn_clean",
        "usndelete", "prefetch_clean", "wevtutil", "fsutil", "cleanevt", "deepclean",
    ];

    let mut reported_paths = std::collections::HashSet::new();

    for rec in scanned_records {
        // Ignoruj historyczne usunięcia do Kosza sprzed ostatniego restartu PC
        if !rec.in_current_session {
            continue;
        }

        let norm_path = rec.original_path.to_lowercase();
        let file_name = Path::new(&rec.original_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_lowercase();

        // 1. Sprawdź czy plik jest na liście zaufanych
        if super::is_whitelisted_executable(&norm_path) {
            continue;
        }

        // 2. Sprawdź podszywanie się pod proces systemowy (np. usunięty svchost.exe z Desktop/Downloads)
        if let Some(fake_name) = super::is_fake_system_executable(&rec.original_path) {
            if reported_paths.insert(rec.original_path.clone()) {
                let del_time = super::format_filetime(rec.deletion_filetime)
                    .unwrap_or_else(|| "Nieznany".to_string());

                let mut finding = ScanFinding::new(
                    "Deleted Masqueraded Executable in Recycle Bin (Current Session)",
                    FindingCategory::TamperingAndAntiForensics,
                    VerdictLevel::Detection,
                    format!(
                        "W Koszu systemowym ($Recycle.Bin) odnaleziono usunięty w bieżącej sesji plik podszywający się pod proces Windows: {}",
                        rec.original_path
                    ),
                )
                .with_evidence("Oryginalna ścieżka", rec.original_path.clone())
                .with_evidence("Podszywanie pod", fake_name.to_string())
                .with_evidence("Czas usunięcia do Kosza", del_time)
                .with_evidence("Sesja usunięcia", "Bieżąca sesja (PO starcie PC)".to_string());

                if rec.r_file_exists {
                    finding = finding.with_evidence("Payload ($R)", "Zachowany w Koszu (dostępny do analizy)".to_string());
                }

                report.add(finding);
                continue;
            }
        }

        // 3. Sprawdź słowa kluczowe cheatów i cleanerów
        let mut matched_trigger = None;
        for trigger in &suspicious_keywords {
            if super::is_cheat_keyword_match(&norm_path, trigger) || super::is_cheat_keyword_match(&file_name, trigger) {
                matched_trigger = Some(*trigger);
                break;
            }
        }

        // 4. Sprawdź podejrzane usunięcia skryptów (.bat, .ps1) lub modów (.jar) z folderów Minecrafta
        let is_mc_mod = norm_path.contains(".minecraft\\mods") && norm_path.ends_with(".jar");
        let is_cleaner_script = (norm_path.ends_with(".bat") || norm_path.ends_with(".ps1") || norm_path.ends_with(".cmd"))
            && (norm_path.contains("clean") || norm_path.contains("wipe") || norm_path.contains("destruct") || norm_path.contains("bypass"));

        if let Some(trigger) = matched_trigger {
            if reported_paths.insert(rec.original_path.clone()) {
                let del_time = super::format_filetime(rec.deletion_filetime)
                    .unwrap_or_else(|| "Nieznany".to_string());

                let mut finding = ScanFinding::new(
                    "Deleted Cheat / Cleaner in Current Session (Recycle Bin)",
                    FindingCategory::WindowsForensics,
                    VerdictLevel::Detection,
                    format!(
                        "W Koszu systemowym ($Recycle.Bin) wykryto ślad usunięcia cheata lub narzędzia w bieżącej sesji: {}",
                        rec.original_path
                    ),
                )
                .with_evidence("Oryginalna ścieżka", rec.original_path.clone())
                .with_evidence("Czas usunięcia do Kosza", del_time)
                .with_evidence("Sesja usunięcia", "Bieżąca sesja (usunięty PO starcie PC tuż przed screensharem)".to_string())
                .with_evidence("Rozmiar pliku", format!("{} bajtów", rec.original_size))
                .with_evidence("Metadane indexu", rec.i_file_path.to_string_lossy().to_string())
                .with_evidence("Matched Keyword", trigger.to_string());

                if rec.r_file_exists {
                    finding = finding.with_evidence(
                        "Payload ($R)",
                        "Zachowany w Koszu (zawartość binarna nie została nadpisana)".to_string(),
                    );
                }

                report.add(finding);
            }
        } else if (is_mc_mod || is_cleaner_script) && reported_paths.insert(rec.original_path.clone()) {
            let del_time = super::format_filetime(rec.deletion_filetime)
                .unwrap_or_else(|| "Nieznany".to_string());

            let mut finding = ScanFinding::new(
                "Suspicious File Deleted In Current Session (Recycle Bin)",
                FindingCategory::WindowsForensics,
                VerdictLevel::Warning,
                format!(
                    "Wykryto usunięcie modyfikacji lub skryptu do Kosza systemowego w bieżącej sesji: {}",
                    rec.original_path
                ),
            )
            .with_evidence("Oryginalna ścieżka", rec.original_path.clone())
            .with_evidence("Czas usunięcia do Kosza", del_time)
            .with_evidence("Sesja usunięcia", "Bieżąca sesja (PO starcie PC)".to_string())
            .with_evidence(
                "Typ pliku",
                if is_mc_mod {
                    "Modyfikacja Minecraft (.jar) usunięta z folderu mods"
                } else {
                    "Podejrzany skrypt czyszczący / wsadowy (.bat / .ps1)"
                }.to_string(),
            );

            if rec.r_file_exists {
                finding = finding.with_evidence("Payload ($R)", "Zachowany w Koszu".to_string());
            }

            report.add(finding);
        }
    }
}

fn scan_drive_recycle_bin(drive_recycle: &Path, records: &mut Vec<RecycleBinRecord>) {
    let sid_dirs = match fs::read_dir(drive_recycle) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for sid_entry in sid_dirs.flatten() {
        let sid_path = sid_entry.path();
        if !sid_path.is_dir() {
            continue;
        }

        let sid_name = sid_entry.file_name().to_string_lossy().to_string();
        // Skanuj tylko foldery użytkowników (S-1-5-21-...)
        if !sid_name.starts_with("S-1-5-") {
            continue;
        }

        let files = match fs::read_dir(&sid_path) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for file_entry in files.flatten() {
            let file_name = file_entry.file_name().to_string_lossy().to_string();

            // Interesują nas pliki indeksowe $I
            if file_name.starts_with("$I") {
                let i_path = file_entry.path();
                if let Some(record) = parse_recycle_i_file(&i_path) {
                    records.push(record);
                }
            }
        }
    }
}

/// Parsuje binarny nagłówek pliku indeksu $I w Koszu Windows
pub fn parse_recycle_i_file(path: &Path) -> Option<RecycleBinRecord> {
    let mut file = File::open(path).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;

    if buf.len() < 24 {
        return None;
    }

    let version = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    let original_size = u64::from_le_bytes(buf[8..16].try_into().ok()?);
    let deletion_filetime = u64::from_le_bytes(buf[16..24].try_into().ok()?);

    let original_path = match version {
        // Windows Vista / 7 / 8 / early 10: wersja 1, ścieżka UTF-16 o stałej długości 260 znaków (520 bajtów) od offsetu 24
        1 => {
            if buf.len() < 26 {
                return None;
            }
            let path_bytes = &buf[24..];
            let u16_chars: Vec<u16> = path_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            String::from_utf16(&u16_chars).ok()?
        }
        // Windows 10 (1703+) / Windows 11: wersja 2, u32 długości ścieżki na offsecie 24, następnie ciąg UTF-16 od offsetu 28
        2 => {
            if buf.len() < 28 {
                return None;
            }
            let char_count = u32::from_le_bytes(buf[24..28].try_into().ok()?) as usize;
            let path_bytes = &buf[28..];
            let max_chars = path_bytes.len() / 2;
            let take_count = char_count.min(max_chars);

            let u16_chars: Vec<u16> = path_bytes
                .chunks_exact(2)
                .take(take_count)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();
            String::from_utf16(&u16_chars).ok()?
        }
        // Fallback dla nietypowych lub nowszych nagłówków: szukaj litery dysku (np. C:\ w UTF-16)
        _ => {
            if buf.len() < 28 {
                return None;
            }
            let mut found_str = None;
            for offset in (24..buf.len().saturating_sub(6)).step_by(2) {
                // Sprawdź czy to ":\" w UTF-16 (0x3A, 0x00, 0x5C, 0x00)
                if buf[offset + 2] == 0x3A && buf[offset + 3] == 0x00 && buf[offset + 4] == 0x5C && buf[offset + 5] == 0x00 {
                    let start = offset;
                    let u16_chars: Vec<u16> = buf[start..]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .take_while(|&c| c != 0)
                        .collect();
                    if let Ok(s) = String::from_utf16(&u16_chars) {
                        if s.len() > 3 {
                            found_str = Some(s);
                            break;
                        }
                    }
                }
            }
            found_str?
        }
    };

    let in_current_session = super::was_executed_in_current_session(deletion_filetime);

    // Sprawdź czy plik payload $R wciąż istnieje w tym samym folderze
    let i_file_name = path.file_name()?.to_string_lossy();
    let r_file_exists = if i_file_name.starts_with("$I") {
        let r_file_name = format!("$R{}", &i_file_name[2..]);
        let r_path = path.with_file_name(r_file_name);
        r_path.is_file()
    } else {
        false
    };

    Some(RecycleBinRecord {
        original_path: original_path.trim().to_string(),
        original_size,
        deletion_filetime,
        i_file_path: path.to_path_buf(),
        r_file_exists,
        in_current_session,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_recycle_i_v2() {
        let mut buf = Vec::new();
        // Version 2 (8 bytes)
        buf.extend_from_slice(&2u64.to_le_bytes());
        // Original size 1024 bytes (8 bytes)
        buf.extend_from_slice(&1024u64.to_le_bytes());
        // Filetime (8 bytes)
        buf.extend_from_slice(&133000000000000000u64.to_le_bytes());

        let path_str = "C:\\Users\\Player\\Desktop\\VapeClient.exe\0";
        let u16_vec: Vec<u16> = path_str.encode_utf16().collect();
        // Char count (4 bytes)
        buf.extend_from_slice(&(u16_vec.len() as u32).to_le_bytes());
        // Path chars
        for ch in u16_vec {
            buf.extend_from_slice(&ch.to_le_bytes());
        }

        // Test parser in memory by creating a temporary file
        let temp_dir = std::env::temp_dir();
        let temp_i_path = temp_dir.join("$ITest123.exe");
        fs::write(&temp_i_path, &buf).unwrap();

        let parsed = parse_recycle_i_file(&temp_i_path).expect("Failed to parse $I v2");
        assert_eq!(parsed.original_path, "C:\\Users\\Player\\Desktop\\VapeClient.exe");
        assert_eq!(parsed.original_size, 1024);
        assert_eq!(parsed.deletion_filetime, 133000000000000000u64);

        let _ = fs::remove_file(&temp_i_path);
    }
}
