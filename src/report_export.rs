use crate::report::{ScanReport, VerdictLevel};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;

pub fn is_sensitive_opsec_evidence(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("matched keyword")
        || lower.contains("sygnatura")
        || lower.contains("wzorzec")
        || lower.contains("nazwa reguły")
        || lower.contains("pattern")
        || lower.contains("wykryte klasy")
        || lower.contains("wykryte sygnatury")
}

pub fn sanitize_opsec_description(desc: &str) -> String {
    if let Some(idx) = desc.find("(Wzorzec:") {
        if let Some(end) = desc[idx..].find(')') {
            let before = desc[..idx].trim_end();
            let after = desc[idx + end + 1..].trim_start();
            if after.is_empty() {
                return before.to_string();
            } else {
                return format!("{} {}", before, after);
            }
        }
    }
    desc.to_string()
}

pub fn calculate_report_seal_hash(report: &ScanReport) -> String {
    let mut hasher = Sha256::new();
    hasher.update(report.timestamp.as_bytes());
    hasher.update(report.scanner_name.as_bytes());
    hasher.update(report.scanner_version.as_bytes());
    hasher.update(&[report.is_admin as u8]);
    if let Some(ref target) = report.target_process {
        hasher.update(target.as_bytes());
    }
    for finding in &report.findings {
        hasher.update(finding.name.as_bytes());
        hasher.update(finding.level.to_string().as_bytes());
        hasher.update(finding.category.to_string().as_bytes());
        let clean_desc = sanitize_opsec_description(&finding.description);
        hasher.update(clean_desc.as_bytes());
        for (k, v) in &finding.evidence {
            if !is_sensitive_opsec_evidence(k) {
                hasher.update(k.as_bytes());
                hasher.update(v.as_bytes());
            }
        }
    }
    let hash_bytes = hasher.finalize();
    hash_bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Generuje sformatowane podsumowanie raportu w Markdownie przystosowane bezpośrednio
/// do wklejenia na Discorda (zgłoszenia screenshare / ticket administracyjny).
/// Zachowuje 100% OPSEC (brak wycieku surowych wzorców i regexów).
pub fn generate_discord_report(report: &ScanReport, duration_secs: f64) -> String {
    generate_discord_report_with_lang(report, duration_secs, crate::i18n::Language::current())
}

/// Generuje raport Markdown z jawnym wyborem języka (PL / EN).
pub fn generate_discord_report_with_lang(
    report: &ScanReport,
    duration_secs: f64,
    lang: crate::i18n::Language,
) -> String {
    let mut out = String::new();
    let detections = report.detections_count();
    let warnings = report.warnings_count();

    let (verdict_emoji, verdict_text) = if detections > 0 {
        if lang.is_polish() {
            ("🚨", "**DETECTED (WYKRYTO CHEATY)**")
        } else {
            ("🚨", "**DETECTED (CHEATS FOUND)**")
        }
    } else if warnings > 0 {
        if lang.is_polish() {
            ("⚠️", "**SUSPICIOUS (PODEJRZANE ARTEFAKTY / DO WERYFIKACJI)**")
        } else {
            ("⚠️", "**SUSPICIOUS (SUSPICIOUS ARTIFACTS / MANUAL CHECK)**")
        }
    } else {
        if lang.is_polish() {
            ("✅", "**UNDETECTED (100% CZYSTO / BRAK ŚLADÓW)**")
        } else {
            ("✅", "**UNDETECTED (100% CLEAN / NO TRACES)**")
        }
    };

    let target_str = match (&report.target_process, report.target_pid) {
        (Some(proc), Some(pid)) => format!("`{}` (PID: {})", proc, pid),
        (Some(proc), None) => format!("`{}`", proc),
        _ => {
            if lang.is_polish() {
                "`Brak aktywnego procesu gry (Skan śledczy powłoki/dysku)`".to_string()
            } else {
                "`No active game process detected (Forensic shell/disk scan)`".to_string()
            }
        }
    };

    let boot_info = crate::scanner::tampering::get_system_boot_info();
    let boot_time_str = boot_info.boot_time.format("%Y-%m-%d %H:%M:%S").to_string();

    let admin_priv_str = if report.is_admin {
        "Administrator (Elevated)"
    } else if lang.is_polish() {
        "Standardowy Użytkownik"
    } else {
        "Standard User"
    };

    if lang.is_polish() {
        out.push_str("## 🛡️ **GRIND SCANNER — RAPORT ZE SCREENSHARE**\n");
        out.push_str(&format!("> **Werdykt końcowy:** {} {}\n", verdict_emoji, verdict_text));
        out.push_str(&format!("> **Cel:** {} | **Czas skanu:** `{:.1}s`\n", target_str, duration_secs));
        out.push_str(&format!("> **Czas działania PC (Uptime):** `{}` (Włączony: `{}`)\n", boot_info.uptime_formatted, boot_time_str));
        out.push_str(&format!("> **Uprawnienia skanera:** `{}`\n\n", admin_priv_str));

        out.push_str("### 📊 **Podsumowanie wyników:**\n");
        out.push_str(&format!("* 🚨 **Detekcje (Krytyczne):** `{}`\n", detections));
        out.push_str(&format!("* ⚠️ **Ostrzeżenia (Podejrzane):** `{}`\n", warnings));
        out.push_str(&format!("* ℹ️ **Informacyjne:** `{}`\n\n", report.info_count()));
    } else {
        out.push_str("## 🛡️ **GRIND SCANNER — SCREENSHARE REPORT**\n");
        out.push_str(&format!("> **Final Verdict:** {} {}\n", verdict_emoji, verdict_text));
        out.push_str(&format!("> **Target:** {} | **Scan Duration:** `{:.1}s`\n", target_str, duration_secs));
        out.push_str(&format!("> **PC Uptime:** `{}` (Booted: `{}`)\n", boot_info.uptime_formatted, boot_time_str));
        out.push_str(&format!("> **Scanner Privileges:** `{}`\n\n", admin_priv_str));

        out.push_str("### 📊 **Results Summary:**\n");
        out.push_str(&format!("* 🚨 **Detections (Critical):** `{}`\n", detections));
        out.push_str(&format!("* ⚠️ **Warnings (Suspicious):** `{}`\n", warnings));
        out.push_str(&format!("* ℹ️ **Informational:** `{}`\n\n", report.info_count()));
    }

    if detections > 0 {
        if lang.is_polish() {
            out.push_str("### 🚨 **Wykryte zagrożenia / Modyfikacje:**\n");
        } else {
            out.push_str("### 🚨 **Detected Threats / Modifications:**\n");
        }
        let det_list: Vec<_> = report.findings.iter().filter(|f| f.level == VerdictLevel::Detection).collect();
        for (i, f) in det_list.iter().take(7).enumerate() {
            let clean_desc = sanitize_opsec_description(&f.description);
            out.push_str(&format!("{}. **{}** *[{}]*\n", i + 1, f.name, f.category));
            out.push_str(&format!("   > {}\n", clean_desc));

            let mut key_ev = Vec::new();
            for (k, v) in &f.evidence {
                if !is_sensitive_opsec_evidence(k) && key_ev.len() < 3 {
                    key_ev.push(format!("`{}: {}`", k, v));
                }
            }
            if !key_ev.is_empty() {
                out.push_str(&format!("   > • {}\n", key_ev.join(" | ")));
            }
        }
        if det_list.len() > 7 {
            if lang.is_polish() {
                out.push_str(&format!("*...oraz {} kolejnych detekcji (pełne szczegóły w pliku HTML)*\n", det_list.len() - 7));
            } else {
                out.push_str(&format!("*...and {} more detections (full details in HTML file)*\n", det_list.len() - 7));
            }
        }
        out.push('\n');
    }

    if warnings > 0 && detections < 5 {
        if lang.is_polish() {
            out.push_str("### ⚠️ **Ostrzeżenia (Wymagające manualnej weryfikacji):**\n");
        } else {
            out.push_str("### ⚠️ **Warnings (Requiring Manual Verification):**\n");
        }
        let warn_list: Vec<_> = report.findings.iter().filter(|f| f.level == VerdictLevel::Warning).collect();
        for (i, f) in warn_list.iter().take(4).enumerate() {
            let clean_desc = sanitize_opsec_description(&f.description);
            out.push_str(&format!("{}. **{}** *[{}]*\n", i + 1, f.name, f.category));
            out.push_str(&format!("   > {}\n", clean_desc));
        }
        if warn_list.len() > 4 {
            if lang.is_polish() {
                out.push_str(&format!("*...oraz {} kolejnych ostrzeżeń (szczegóły w pliku HTML)*\n", warn_list.len() - 4));
            } else {
                out.push_str(&format!("*...and {} more warnings (details in HTML file)*\n", warn_list.len() - 4));
            }
        }
        out.push('\n');
    }

    if detections == 0 && warnings == 0 {
        if lang.is_polish() {
            out.push_str("> ✅ **System czysty. Brak jakichkolwiek śladów cheatów, modyfikacji pamięci ani manipulacji śledczych.**\n\n");
        } else {
            out.push_str("> ✅ **System clean. No traces of cheats, memory modifications, or forensic tampering found.**\n\n");
        }
    }

    if lang.is_polish() {
        out.push_str("---\n*Wygenerowano przez Grind Scanner (Minecraft Forensic Anticheat Engine)*\n");
    } else {
        out.push_str("---\n*Generated by Grind Scanner (Minecraft Forensic Anticheat Engine)*\n");
    }

    out
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn parse_timestamp_from_str(s: &str, lang: crate::i18n::Language) -> Option<(String, String)> {
    let bytes = s.as_bytes();
    if bytes.len() >= 19 {
        for i in 0..=bytes.len() - 19 {
            if bytes[i..i + 4].iter().all(|b| b.is_ascii_digit())
                && bytes[i + 4] == b'-'
                && bytes[i + 5..i + 7].iter().all(|b| b.is_ascii_digit())
                && bytes[i + 7] == b'-'
                && bytes[i + 8..i + 10].iter().all(|b| b.is_ascii_digit())
                && (bytes[i + 10] == b' ' || bytes[i + 10] == b'T')
                && bytes[i + 11..i + 13].iter().all(|b| b.is_ascii_digit())
                && bytes[i + 13] == b':'
                && bytes[i + 14..i + 16].iter().all(|b| b.is_ascii_digit())
                && bytes[i + 16] == b':'
                && bytes[i + 17..i + 19].iter().all(|b| b.is_ascii_digit())
            {
                let date_str = s[i..i + 19].replace('T', " ");
                let rel_str = if let Some(open) = s[i + 19..].find('(') {
                    if let Some(close) = s[i + 19 + open..].find(')') {
                        s[i + 19 + open + 1..i + 19 + open + close].trim().to_string()
                    } else if lang.is_polish() {
                        "zarejestrowany czas".to_string()
                    } else {
                        "recorded time".to_string()
                    }
                } else if lang.is_polish() {
                    "zarejestrowany czas".to_string()
                } else {
                    "recorded time".to_string()
                };
                return Some((date_str, rel_str));
            }
        }
    }
    None
}

fn determine_finding_source(finding: &crate::report::ScanFinding, lang: crate::i18n::Language) -> String {
    let lower_name = finding.name.to_lowercase();
    let lower_cat = finding.category.to_string().to_lowercase();

    if lang.is_polish() {
        if lower_name.contains("usn") || lower_name.contains("deleted") {
            "NTFS USN Journal".to_string()
        } else if lower_name.contains("bam") {
            "Rejestr BAM (Wykonanie)".to_string()
        } else if lower_name.contains("prefetch") {
            "Windows Prefetch".to_string()
        } else if lower_name.contains("amcache") {
            "Amcache.hve Forensics".to_string()
        } else if lower_name.contains("muicache") {
            "MuiCache Shell".to_string()
        } else if lower_name.contains("userassist") {
            "UserAssist GUI (ROT13)".to_string()
        } else if lower_name.contains("recycle") || lower_name.contains("kosz") {
            "Kosz ($Recycle.Bin)".to_string()
        } else if lower_name.contains("shimcache") || lower_name.contains("appcompat") {
            "ShimCache (AppCompatCache)".to_string()
        } else if lower_name.contains("powershell") {
            "PowerShell ConsoleHost".to_string()
        } else if lower_name.contains("pcasvc") {
            "Dziennik PcaSvc".to_string()
        } else if lower_name.contains("usbstor") || lower_name.contains("mountpoints2") || lower_name.contains("usb") {
            "Rejestr USB / Dyski".to_string()
        } else if lower_name.contains("recent") || lower_name.contains("lnk") || lower_name.contains("zone.identifier") {
            "Recent LNK / Pobieranie ADS".to_string()
        } else if lower_name.contains("jump") {
            "Windows Jump Lists".to_string()
        } else if lower_name.contains("wer") || lower_name.contains("crash") {
            "Windows Error Reporting (WER)".to_string()
        } else if lower_name.contains("runmru") {
            "Explorer RunMRU (Win+R)".to_string()
        } else if lower_name.contains("driver") || lower_name.contains("byovd") {
            "Sterownik jądra (BYOVD)".to_string()
        } else if lower_name.contains("eventlog") || lower_name.contains("1102") || lower_name.contains("104") {
            "Dziennik zdarzeń EventLog".to_string()
        } else if lower_name.contains("self-defense") || lower_name.contains("hook") {
            "Scanner Self-Defense".to_string()
        } else if lower_name.contains("dns") || lower_name.contains("hosts") {
            "DNS Cache / Plik hosts".to_string()
        } else if lower_name.contains("tcp") || lower_name.contains("connection") || lower_name.contains("socket") {
            "Połączenia TCP / Sieć".to_string()
        } else if lower_cat.contains("runtime") || lower_cat.contains("minecraft") {
            "Minecraft JVM Runtime".to_string()
        } else if lower_cat.contains("memory") {
            "Inspekcja Pamięci RAM".to_string()
        } else {
            finding.category.to_string()
        }
    } else {
        if lower_name.contains("usn") || lower_name.contains("deleted") {
            "NTFS USN Journal".to_string()
        } else if lower_name.contains("bam") {
            "BAM Registry (Execution)".to_string()
        } else if lower_name.contains("prefetch") {
            "Windows Prefetch".to_string()
        } else if lower_name.contains("amcache") {
            "Amcache.hve Forensics".to_string()
        } else if lower_name.contains("muicache") {
            "MuiCache Shell".to_string()
        } else if lower_name.contains("userassist") {
            "UserAssist GUI (ROT13)".to_string()
        } else if lower_name.contains("recycle") || lower_name.contains("kosz") {
            "Recycle Bin ($Recycle.Bin)".to_string()
        } else if lower_name.contains("shimcache") || lower_name.contains("appcompat") {
            "ShimCache (AppCompatCache)".to_string()
        } else if lower_name.contains("powershell") {
            "PowerShell ConsoleHost".to_string()
        } else if lower_name.contains("pcasvc") {
            "PcaSvc Event Log".to_string()
        } else if lower_name.contains("usbstor") || lower_name.contains("mountpoints2") || lower_name.contains("usb") {
            "USB Registry / Storage".to_string()
        } else if lower_name.contains("recent") || lower_name.contains("lnk") || lower_name.contains("zone.identifier") {
            "Recent LNK / ADS Downloads".to_string()
        } else if lower_name.contains("jump") {
            "Windows Jump Lists".to_string()
        } else if lower_name.contains("wer") || lower_name.contains("crash") {
            "Windows Error Reporting (WER)".to_string()
        } else if lower_name.contains("runmru") {
            "Explorer RunMRU (Win+R)".to_string()
        } else if lower_name.contains("driver") || lower_name.contains("byovd") {
            "Kernel Driver (BYOVD)".to_string()
        } else if lower_name.contains("eventlog") || lower_name.contains("1102") || lower_name.contains("104") {
            "EventLog History".to_string()
        } else if lower_name.contains("self-defense") || lower_name.contains("hook") {
            "Scanner Self-Defense".to_string()
        } else if lower_name.contains("dns") || lower_name.contains("hosts") {
            "DNS Cache / Hosts File".to_string()
        } else if lower_name.contains("tcp") || lower_name.contains("connection") || lower_name.contains("socket") {
            "TCP Connections / Network".to_string()
        } else if lower_cat.contains("runtime") || lower_cat.contains("minecraft") {
            "Minecraft JVM Runtime".to_string()
        } else if lower_cat.contains("memory") {
            "RAM Memory Inspection".to_string()
        } else {
            finding.category.to_string()
        }
    }
}

pub fn generate_html_report(report: &ScanReport, duration_secs: f64) -> String {
    generate_html_report_with_lang(report, duration_secs, crate::i18n::Language::current())
}

pub fn generate_html_report_with_lang(
    report: &ScanReport,
    duration_secs: f64,
    lang: crate::i18n::Language,
) -> String {
    let boot_info = crate::scanner::tampering::get_system_boot_info();

    let detections = report.detections_count();
    let warnings = report.warnings_count();
    let infos = report.info_count();

    let (verdict_title, verdict_class, verdict_desc) = if detections > 0 {
        if lang.is_polish() {
            (
                "WYKRYTO NIELEGALNE OPROGRAMOWANIE (CHEAT DETECTED)",
                "verdict-danger",
                format!("Skaner zidentyfikował {} ewidentnych wskaźników ghost clienta / cheata.", detections),
            )
        } else {
            (
                "UNAUTHORIZED SOFTWARE DETECTED (CHEAT DETECTED)",
                "verdict-danger",
                format!("The scanner identified {} blatant indicators of ghost client / cheat software.", detections),
            )
        }
    } else if warnings > 0 {
        if lang.is_polish() {
            (
                "WYKRYTO PODEJRZANE ARTEFAKTY ŚLEDCZE (WARNINGS)",
                "verdict-warning",
                format!("Pamięć gry jest czysta, ale zidentyfikowano {} podejrzanych śladów w systemie lub sieci.", warnings),
            )
        } else {
            (
                "SUSPICIOUS FORENSIC ARTIFACTS DETECTED (WARNINGS)",
                "verdict-warning",
                format!("Game memory is clean, but {} suspicious traces were identified in system or network.", warnings),
            )
        }
    } else {
        if lang.is_polish() {
            (
                "100% CZYSTO - BRAK ŚLADÓW CHEATÓW (CLEAN)",
                "verdict-clean",
                "W procesie gry ani w artefaktach systemu Windows nie wykryto żadnych anomalii ani cheatów.".to_string(),
            )
        } else {
            (
                "100% CLEAN - NO CHEAT ARTIFACTS FOUND (CLEAN)",
                "verdict-clean",
                "No anomalies or cheats were detected in the game process or Windows forensic artifacts.".to_string(),
            )
        }
    };

    struct TimelineEntry {
        sort_key: String,
        time_display: String,
        time_relative: String,
        level: VerdictLevel,
        name: String,
        source: String,
        description: String,
        evidence_rows: String,
    }

    let priority_time_keys = [
        "Czas usunięcia",
        "Last Execution Time",
        "Czas wykonania",
        "Czas modyfikacji klucza",
        "Czas modyfikacji",
        "Czas aktywności",
        "Data utworzenia/modyfikacji",
        "Ostatnie wykonanie",
        "Last Executed",
        "Last Run",
        "Ostatnie uruchomienie",
        "Czas zdarzenia",
        "Data pobrania",
        "Data usunięcia",
        "Czas",
        "Timestamp",
    ];

    let mut timeline_entries: Vec<TimelineEntry> = Vec::new();
    let mut findings_html = String::new();

    if report.findings.is_empty() {
        if lang.is_polish() {
            findings_html.push_str("<div class='empty-notice'>Brak zarejestrowanych anomalii lub znalezisk.</div>");
        } else {
            findings_html.push_str("<div class='empty-notice'>No anomalies or findings recorded.</div>");
        }
    } else {
        for finding in &report.findings {
            let (level_badge_class, level_label, level_filter) = match finding.level {
                VerdictLevel::Detection => ("badge-danger", "DETECTION", "detection"),
                VerdictLevel::Warning => ("badge-warning", "WARNING", "warning"),
                VerdictLevel::Information => ("badge-info", "INFO", "info"),
            };

            let clean_desc = sanitize_opsec_description(&finding.description);

            let visible_evidence: Vec<(&String, &String)> = finding
                .evidence
                .iter()
                .filter(|(k, _)| !is_sensitive_opsec_evidence(k))
                .collect();

            let mut evidence_rows = String::new();
            if !visible_evidence.is_empty() {
                evidence_rows.push_str("<table class='evidence-table'>");
                for (k, v) in &visible_evidence {
                    evidence_rows.push_str(&format!(
                        "<tr><td class='ev-key'>{}</td><td class='ev-val'><code>{}</code></td></tr>",
                        html_escape(k),
                        html_escape(v)
                    ));
                }
                evidence_rows.push_str("</table>");
            }

            findings_html.push_str(&format!(
                r#"<div class="finding-card {level_badge_class}" data-level="{level_filter}">
                    <div class="finding-header">
                        <span class="badge {level_badge_class}">{level_label}</span>
                        <span class="finding-title">{name}</span>
                        <span class="finding-category">{category}</span>
                    </div>
                    <div class="finding-desc">{desc}</div>
                    {evidence}
                </div>"#,
                level_badge_class = level_badge_class,
                level_label = level_label,
                level_filter = level_filter,
                name = html_escape(&finding.name),
                category = html_escape(&finding.category.to_string()),
                desc = html_escape(&clean_desc),
                evidence = evidence_rows,
            ));

            // Szukanie znacznika czasu dla Osi Czasu (Timeline)
            let mut found_time = None;
            for key in &priority_time_keys {
                if let Some(val) = finding.evidence.get(*key) {
                    if let Some(t) = parse_timestamp_from_str(val, lang) {
                        found_time = Some(t);
                        break;
                    }
                }
            }

            if found_time.is_none() {
                for val in finding.evidence.values() {
                    if let Some(t) = parse_timestamp_from_str(val, lang) {
                        found_time = Some(t);
                        break;
                    }
                }
            }

            let (sort_key, time_display, time_relative) = match found_time {
                Some((date_str, rel_str)) => (date_str.clone(), date_str, rel_str),
                None => {
                    let scan_time_clean = report.timestamp[..19.min(report.timestamp.len())].replace('T', " ");
                    let fallback_disp = if lang.is_polish() {
                        "W trakcie skanowania".to_string()
                    } else {
                        "During scan".to_string()
                    };
                    let fallback_rel = if lang.is_polish() {
                        "Aktywny stan RAM / System".to_string()
                    } else {
                        "Active RAM / System state".to_string()
                    };
                    (scan_time_clean, fallback_disp, fallback_rel)
                }
            };

            let source = determine_finding_source(finding, lang);

            timeline_entries.push(TimelineEntry {
                sort_key,
                time_display,
                time_relative,
                level: finding.level,
                name: finding.name.clone(),
                source,
                description: clean_desc,
                evidence_rows,
            });
        }
    }

    // Sortuj zdarzenia na osi czasu malejąco (najnowsze wydarzenia na samej górze)
    timeline_entries.sort_by(|a, b| b.sort_key.cmp(&a.sort_key));

    let mut timeline_html = String::new();
    if timeline_entries.is_empty() {
        if lang.is_polish() {
            timeline_html.push_str("<div class='empty-notice'>Brak zarejestrowanych zdarzeń na osi czasu.</div>");
        } else {
            timeline_html.push_str("<div class='empty-notice'>No timeline events recorded.</div>");
        }
    } else {
        timeline_html.push_str("<div class='timeline-container'>");
        for entry in &timeline_entries {
            let (level_badge_class, level_label, level_filter, level_icon) = match entry.level {
                VerdictLevel::Detection => ("badge-danger", "DETECTION", "detection", "🚨"),
                VerdictLevel::Warning => ("badge-warning", "WARNING", "warning", "⚠️"),
                VerdictLevel::Information => ("badge-info", "INFO", "info", "ℹ️"),
            };

            timeline_html.push_str(&format!(
                r#"<div class="timeline-item {level_badge_class}" data-level="{level_filter}">
                    <div class="timeline-marker">
                        <span class="timeline-dot">{icon}</span>
                    </div>
                    <div class="timeline-body">
                        <div class="timeline-top">
                            <div class="timeline-time-group">
                                <span class="timeline-time">🕒 {time}</span>
                                <span class="timeline-rel-pill">{relative}</span>
                            </div>
                            <span class="badge {level_badge_class}">{level_label}</span>
                            <span class="timeline-source-badge">{source}</span>
                        </div>
                        <div class="timeline-title">{name}</div>
                        <div class="timeline-desc">{desc}</div>
                        {evidence}
                    </div>
                </div>"#,
                level_badge_class = level_badge_class,
                level_filter = level_filter,
                icon = level_icon,
                time = html_escape(&entry.time_display),
                relative = html_escape(&entry.time_relative),
                level_label = level_label,
                source = html_escape(&entry.source),
                name = html_escape(&entry.name),
                desc = html_escape(&entry.description),
                evidence = entry.evidence_rows,
            ));
        }
        timeline_html.push_str("</div>");
    }

    let target_str = match &report.target_process {
        Some(proc) => format!("{} (PID: {})", html_escape(proc), report.target_pid.unwrap_or(0)),
        None => {
            if lang.is_polish() {
                "Brak aktywnego procesu (Minecraft niewłączony)".to_string()
            } else {
                "No active process (Minecraft not running)".to_string()
            }
        }
    };

    let uptime_str = if lang.is_polish() {
        format!("{} (Start: {})", boot_info.uptime_formatted, boot_info.boot_time.format("%Y-%m-%d %H:%M:%S"))
    } else {
        format!("{} (Booted: {})", boot_info.uptime_formatted, boot_info.boot_time.format("%Y-%m-%d %H:%M:%S"))
    };

    let admin_status = if report.is_admin {
        if lang.is_polish() { "TAK (Elevated)" } else { "YES (Elevated)" }
    } else if lang.is_polish() {
        "NIE (Standard User)"
    } else {
        "NO (Standard User)"
    };

    let html_lang = if lang.is_polish() { "pl" } else { "en" };
    let page_title = if lang.is_polish() {
        "Grind Scanner - Raport Kontroli Śledczej"
    } else {
        "Grind Scanner - Forensic Inspection Report"
    };
    let meta_generated = if lang.is_polish() { "Wygenerowano:" } else { "Generated:" };
    let meta_duration = if lang.is_polish() { "Czas trwania skanu:" } else { "Scan duration:" };

    let stat_det_label = if lang.is_polish() { "Detekcje 🔍" } else { "Detections 🔍" };
    let stat_det_title = if lang.is_polish() { "Filtruj: Pokaż tylko Detekcje" } else { "Filter: Show Detections only" };
    let stat_warn_label = if lang.is_polish() { "Ostrzeżenia 🔍" } else { "Warnings 🔍" };
    let stat_warn_title = if lang.is_polish() { "Filtruj: Pokaż tylko Ostrzeżenia" } else { "Filter: Show Warnings only" };
    let stat_info_label = if lang.is_polish() { "Informacje 🔍" } else { "Information 🔍" };
    let stat_info_title = if lang.is_polish() { "Filtruj: Pokaż tylko Informacje" } else { "Filter: Show Information only" };
    let stat_time_label = if lang.is_polish() { "Czas Skanu" } else { "Scan Time" };
    let stat_time_title = if lang.is_polish() { "Pokaż wszystkie ustalenia" } else { "Show all findings" };

    let meta_admin_key = if lang.is_polish() { "Uprawnienia administratora:" } else { "Administrator Privileges:" };
    let meta_proc_key = if lang.is_polish() { "Proces Minecrafta:" } else { "Minecraft Process:" };
    let meta_uptime_key = if lang.is_polish() { "Czas pracy systemu (Uptime):" } else { "System Uptime:" };
    let meta_yara_key = if lang.is_polish() { "Liczba reguł YARA:" } else { "YARA Rule Sets:" };
    let meta_yara_val = if lang.is_polish() { "11 szyfrowanych zestawów (+ reguły własne)" } else { "11 encrypted rule sets (+ custom rules)" };

    let findings_count = report.findings.len();
    let tab_cards_label = if lang.is_polish() {
        format!("📋 Karty Dowodowe ({})", findings_count)
    } else {
        format!("📋 Evidence Cards ({})", findings_count)
    };
    let tab_timeline_label = if lang.is_polish() {
        "⏱ Oś Czasu Śledcza (Forensic Timeline)"
    } else {
        "⏱ Forensic Timeline"
    };
    let quick_copy_btn_label = if lang.is_polish() {
        "📋 Kopiuj Podsumowanie Śledcze"
    } else {
        "📋 Copy Staff Summary"
    };

    let filter_all_label = if lang.is_polish() {
        format!("Wszystkie ({})", findings_count)
    } else {
        format!("All ({})", findings_count)
    };
    let filter_det_label = if lang.is_polish() {
        format!("🚨 Detekcje ({})", detections)
    } else {
        format!("🚨 Detections ({})", detections)
    };
    let filter_warn_label = if lang.is_polish() {
        format!("⚠️ Ostrzeżenia ({})", warnings)
    } else {
        format!("⚠️ Warnings ({})", warnings)
    };
    let filter_info_label = if lang.is_polish() {
        format!("ℹ️ Informacje ({})", infos)
    } else {
        format!("ℹ️ Information ({})", infos)
    };

    let search_placeholder = if lang.is_polish() {
        "🔍 Szukaj w ustaleniach..."
    } else {
        "🔍 Search findings..."
    };
    let visible_badge_label = if lang.is_polish() { "Widoczne:" } else { "Visible:" };

    let no_findings_filtered = if lang.is_polish() {
        "Brak zarejestrowanych ustaleń w wybranej kategorii filtru."
    } else {
        "No findings recorded in the selected filter category."
    };
    let no_timeline_filtered = if lang.is_polish() {
        "Brak zarejestrowanych zdarzeń na osi czasu w wybranej kategorii filtru."
    } else {
        "No timeline events recorded in the selected filter category."
    };

    let footer_text = if lang.is_polish() {
        "Raport wygenerowany automatycznie przez Grind Scanner • Zgodny ze standardami screenshare Minecraft"
    } else {
        "Report automatically generated by Grind Scanner • Compliant with Minecraft screenshare standards"
    };

    let js_copy_verdict = if lang.is_polish() { "Werdykt:" } else { "Verdict:" };
    let js_copy_date = if lang.is_polish() { "Data kontroli:" } else { "Inspection Date:" };
    let js_copy_stats = if lang.is_polish() {
        "Statystyki: ${detCount} detekcji | ${warnCount} ostrzeżeń"
    } else {
        "Stats: ${detCount} detections | ${warnCount} warnings"
    };
    let js_copy_findings = if lang.is_polish() { "Kluczowe ustalenia:" } else { "Key Findings:" };
    let js_clean_line = if lang.is_polish() {
        "• Brak zarejestrowanych zagrożeń (100% Czysto)."
    } else {
        "• No threats recorded (100% Clean)."
    };
    let js_copied_success = if lang.is_polish() {
        "✅ Skopiowano do schowka!"
    } else {
        "✅ Copied to clipboard!"
    };
    let js_copy_fallback_error = if lang.is_polish() {
        "Nie udało się skopiować automatycznie."
    } else {
        "Could not copy automatically."
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="{html_lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{page_title}</title>
    <style>
        :root {{
            --bg: #0b0f17;
            --card-bg: #141a26;
            --border: #243048;
            --text-primary: #eceff1;
            --text-secondary: #90a4ae;
            --cyan: #00e5ff;
            --green: #00e676;
            --red: #ff1744;
            --amber: #ffb300;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{
            max-width: 1040px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #101622 0%, #172133 100%);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px 24px;
            margin-bottom: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .logo-title {{
            font-size: 22px;
            font-weight: 800;
            color: var(--cyan);
            letter-spacing: 0.5px;
        }}
        .logo-sub {{
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 4px;
        }}
        .header-meta {{
            text-align: right;
            font-size: 12px;
            color: var(--text-secondary);
        }}
        .verdict-banner {{
            border-radius: 10px;
            padding: 20px 24px;
            margin-bottom: 16px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .verdict-danger {{
            background: rgba(255, 23, 68, 0.12);
            border: 1.5px solid var(--red);
        }}
        .verdict-warning {{
            background: rgba(255, 179, 0, 0.12);
            border: 1.5px solid var(--amber);
        }}
        .verdict-clean {{
            background: rgba(0, 230, 118, 0.12);
            border: 1.5px solid var(--green);
        }}
        .verdict-title {{
            font-size: 18px;
            font-weight: 700;
        }}
        .verdict-danger .verdict-title {{ color: var(--red); }}
        .verdict-warning .verdict-title {{ color: var(--amber); }}
        .verdict-clean .verdict-title {{ color: var(--green); }}
        .verdict-desc {{
            font-size: 13px;
            color: var(--text-primary);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 12px;
            margin-bottom: 16px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 16px;
        }}
        .stat-label {{
            font-size: 11px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}
        .stat-value {{
            font-size: 26px;
            font-weight: 800;
            margin-top: 4px;
        }}
        .stat-value.red {{ color: var(--red); }}
        .stat-value.amber {{ color: var(--amber); }}
        .stat-value.cyan {{ color: var(--cyan); }}
        .stat-value.white {{ color: #ffffff; }}
        .meta-section {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 18px;
            margin-bottom: 16px;
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px 20px;
            font-size: 12px;
        }}
        .meta-item {{
            display: flex;
            justify-content: space-between;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 4px;
        }}
        .meta-key {{ color: var(--text-secondary); }}
        .meta-val {{ color: #ffffff; font-weight: 600; }}

        /* Pasek przełączania widoków (Karty vs Oś Czasu) oraz Szybkie Kopiowanie */
        .view-switcher-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
            flex-wrap: wrap;
        }}
        .view-tabs {{
            display: flex;
            gap: 8px;
        }}
        .view-tab {{
            background: #141a26;
            color: var(--text-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px 16px;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            user-select: none;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .view-tab:hover {{
            color: var(--text-primary);
            border-color: #384b6e;
        }}
        .view-tab.active {{
            background: #1c273c;
            color: var(--cyan);
            border-color: var(--cyan);
            box-shadow: 0 0 10px rgba(0, 229, 255, 0.2);
        }}
        .quick-copy-btn {{
            background: #101926;
            color: var(--cyan);
            border: 1px solid rgba(0, 229, 255, 0.4);
            border-radius: 6px;
            padding: 8px 16px;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s ease;
            user-select: none;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .quick-copy-btn:hover {{
            background: rgba(0, 229, 255, 0.15);
            border-color: var(--cyan);
            box-shadow: 0 0 12px rgba(0, 229, 255, 0.25);
        }}

        .section-header {{
            font-size: 13px;
            font-weight: 700;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }}
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 10px;
        }}
        .finding-card.badge-danger {{ border-left: 4px solid var(--red); }}
        .finding-card.badge-warning {{ border-left: 4px solid var(--amber); }}
        .finding-card.badge-info {{ border-left: 4px solid var(--cyan); }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
        }}
        .badge {{
            font-size: 10px;
            font-weight: 800;
            padding: 3px 8px;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge.badge-danger {{ background: var(--red); color: #fff; }}
        .badge.badge-warning {{ background: var(--amber); color: #000; }}
        .badge.badge-info {{ background: var(--cyan); color: #000; }}
        .finding-title {{
            font-size: 14px;
            font-weight: 700;
            color: #ffffff;
        }}
        .finding-category {{
            margin-left: auto;
            font-size: 11px;
            color: var(--text-secondary);
        }}
        .finding-desc {{
            font-size: 12px;
            color: #b0bec5;
            margin-bottom: 10px;
        }}
        .evidence-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 11.5px;
            background: rgba(0, 0, 0, 0.25);
            border-radius: 6px;
            overflow: hidden;
        }}
        .evidence-table td {{
            padding: 6px 10px;
            border-top: 1px solid rgba(255, 255, 255, 0.04);
        }}
        .ev-key {{
            color: var(--text-secondary);
            width: 250px;
            font-weight: 600;
        }}
        .ev-val code {{
            font-family: Consolas, Monaco, monospace;
            color: var(--cyan);
        }}
        .stat-card.clickable {{
            cursor: pointer;
            user-select: none;
            transition: all 0.2s ease;
        }}
        .stat-card.clickable:hover {{
            transform: translateY(-2px);
            border-color: var(--cyan);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.35);
        }}
        .filter-bar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
            flex-wrap: wrap;
        }}
        .filter-buttons {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: var(--card-bg);
            color: var(--text-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px 14px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 6px;
            user-select: none;
        }}
        .filter-btn:hover {{
            background: #1c2536;
            color: var(--text-primary);
            border-color: #384b6e;
        }}
        .filter-btn.active {{
            background: #202b40;
            color: #ffffff;
            border-color: var(--cyan);
            box-shadow: 0 0 10px rgba(0, 229, 255, 0.2);
        }}
        .filter-btn.btn-danger.active {{
            background: rgba(255, 23, 68, 0.2);
            border-color: var(--red);
            color: var(--red);
            box-shadow: 0 0 10px rgba(255, 23, 68, 0.3);
        }}
        .filter-btn.btn-warning.active {{
            background: rgba(255, 179, 0, 0.2);
            border-color: var(--amber);
            color: var(--amber);
            box-shadow: 0 0 10px rgba(255, 179, 0, 0.3);
        }}
        .filter-btn.btn-info.active {{
            background: rgba(0, 229, 255, 0.2);
            border-color: var(--cyan);
            color: var(--cyan);
            box-shadow: 0 0 10px rgba(0, 229, 255, 0.3);
        }}
        .filter-search-wrap {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .search-box {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 8px 14px;
            font-size: 12px;
            color: var(--text-primary);
            outline: none;
            min-width: 200px;
            transition: border-color 0.2s ease;
        }}
        .search-box:focus {{
            border-color: var(--cyan);
        }}
        .findings-count-badge {{
            font-size: 11px;
            color: var(--text-secondary);
            background: rgba(255, 255, 255, 0.05);
            padding: 6px 10px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            white-space: nowrap;
        }}
        .no-findings {{
            background: var(--card-bg);
            border: 1px dashed var(--border);
            border-radius: 8px;
            padding: 30px;
            text-align: center;
            color: var(--text-secondary);
            font-size: 13px;
        }}

        /* Style Osi Czasu Śledczej (Forensic Timeline) */
        .timeline-container {{
            position: relative;
            padding-left: 42px;
            margin-top: 14px;
            margin-bottom: 24px;
        }}
        .timeline-container::before {{
            content: '';
            position: absolute;
            top: 14px;
            bottom: 14px;
            left: 17px;
            width: 2px;
            background: linear-gradient(180deg, #00e5ff 0%, #30476e 50%, #243048 100%);
            border-radius: 2px;
        }}
        .timeline-item {{
            position: relative;
            margin-bottom: 18px;
        }}
        .timeline-marker {{
            position: absolute;
            left: -42px;
            top: 12px;
            width: 34px;
            height: 34px;
            border-radius: 50%;
            background: #0f1521;
            border: 2px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 13px;
            z-index: 2;
            transition: all 0.2s ease;
        }}
        .timeline-item.badge-danger .timeline-marker {{
            border-color: var(--red);
            box-shadow: 0 0 10px rgba(255, 23, 68, 0.45);
            background: #1c1117;
        }}
        .timeline-item.badge-warning .timeline-marker {{
            border-color: var(--amber);
            box-shadow: 0 0 10px rgba(255, 179, 0, 0.45);
            background: #1c1811;
        }}
        .timeline-item.badge-info .timeline-marker {{
            border-color: var(--cyan);
            box-shadow: 0 0 10px rgba(0, 229, 255, 0.35);
            background: #0d1a24;
        }}
        .timeline-body {{
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 14px 18px;
            transition: all 0.2s ease;
        }}
        .timeline-item.badge-danger .timeline-body {{ border-left: 3.5px solid var(--red); }}
        .timeline-item.badge-warning .timeline-body {{ border-left: 3.5px solid var(--amber); }}
        .timeline-item.badge-info .timeline-body {{ border-left: 3.5px solid var(--cyan); }}
        .timeline-top {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 8px;
            flex-wrap: wrap;
        }}
        .timeline-time-group {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .timeline-time {{
            font-family: Consolas, Monaco, monospace;
            font-size: 12.5px;
            color: #ffffff;
            font-weight: 700;
        }}
        .timeline-rel-pill {{
            font-size: 10.5px;
            color: var(--cyan);
            background: rgba(0, 229, 255, 0.1);
            border: 1px solid rgba(0, 229, 255, 0.25);
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: 600;
        }}
        .timeline-source-badge {{
            margin-left: auto;
            font-size: 11px;
            color: var(--text-secondary);
            background: rgba(255, 255, 255, 0.05);
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 600;
        }}
        .timeline-title {{
            font-size: 14px;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 4px;
        }}
        .timeline-desc {{
            font-size: 12px;
            color: #b0bec5;
            margin-bottom: 10px;
        }}

        .footer {{
            text-align: center;
            font-size: 11px;
            color: var(--text-secondary);
            margin-top: 30px;
            padding-top: 16px;
            border-top: 1px solid var(--border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <div class="logo-title">⚡ GRIND SCANNER</div>
                <div class="logo-sub">Minecraft Forensic Anticheat &amp; Memory Inspector v{version}</div>
            </div>
            <div class="header-meta">
                <div>{meta_generated} <strong>{timestamp}</strong></div>
                <div>{meta_duration} <strong>{duration:.2} s</strong></div>
            </div>
        </header>

        <section class="verdict-banner {verdict_class}">
            <div class="verdict-title">{verdict_title}</div>
            <div class="verdict-desc">{verdict_desc}</div>
        </section>

        <section class="stats-grid">
            <div class="stat-card clickable" onclick="filterFindings('detection')" title="{stat_det_title}">
                <div class="stat-label">{stat_det_label}</div>
                <div class="stat-value red">{detections}</div>
            </div>
            <div class="stat-card clickable" onclick="filterFindings('warning')" title="{stat_warn_title}">
                <div class="stat-label">{stat_warn_label}</div>
                <div class="stat-value amber">{warnings}</div>
            </div>
            <div class="stat-card clickable" onclick="filterFindings('info')" title="{stat_info_title}">
                <div class="stat-label">{stat_info_label}</div>
                <div class="stat-value cyan">{infos}</div>
            </div>
            <div class="stat-card clickable" onclick="filterFindings('all')" title="{stat_time_title}">
                <div class="stat-label">{stat_time_label}</div>
                <div class="stat-value white">{duration:.1}s</div>
            </div>
        </section>

        <section class="meta-section">
            <div class="meta-item">
                <span class="meta-key">{meta_admin_key}</span>
                <span class="meta-val">{admin_status}</span>
            </div>
            <div class="meta-item">
                <span class="meta-key">{meta_proc_key}</span>
                <span class="meta-val">{target_str}</span>
            </div>
            <div class="meta-item">
                <span class="meta-key">{meta_uptime_key}</span>
                <span class="meta-val">{uptime_str}</span>
            </div>
            <div class="meta-item">
                <span class="meta-key">{meta_yara_key}</span>
                <span class="meta-val">{meta_yara_val}</span>
            </div>
        </section>

        <div class="view-switcher-bar">
            <div class="view-tabs">
                <button id="tab-cards" class="view-tab active" onclick="switchView('cards')">
                    {tab_cards_label}
                </button>
                <button id="tab-timeline" class="view-tab" onclick="switchView('timeline')">
                    {tab_timeline_label}
                </button>
            </div>
            <button class="quick-copy-btn" id="quick-copy-btn" onclick="copyStaffSummary()">
                {quick_copy_btn_label}
            </button>
        </div>

        <div class="filter-bar">
            <div class="filter-buttons">
                <button class="filter-btn active" data-filter="all" onclick="filterFindings('all')">
                    {filter_all_label}
                </button>
                <button class="filter-btn btn-danger" data-filter="detection" onclick="filterFindings('detection')">
                    {filter_det_label}
                </button>
                <button class="filter-btn btn-warning" data-filter="warning" onclick="filterFindings('warning')">
                    {filter_warn_label}
                </button>
                <button class="filter-btn btn-info" data-filter="info" onclick="filterFindings('info')">
                    {filter_info_label}
                </button>
            </div>
            <div class="filter-search-wrap">
                <input type="text" id="finding-search" class="search-box" placeholder="{search_placeholder}" oninput="filterFindings()">
                <div class="findings-count-badge">{visible_badge_label} <strong id="visible-count" style="color: var(--cyan);">{findings_count}</strong></div>
            </div>
        </div>

        <section class="findings-list" id="findings-container">
            {findings_html}
            <div id="no-findings" class="no-findings" style="display: none;">
                {no_findings_filtered}
            </div>
        </section>

        <section class="timeline-section" id="timeline-container" style="display: none;">
            {timeline_html}
            <div id="no-timeline-findings" class="no-findings" style="display: none;">
                {no_timeline_filtered}
            </div>
        </section>

        <footer class="footer">
            {footer_text}
        </footer>
    </div>

    <script>
        let currentView = 'cards';
        let currentFilter = 'all';

        function switchView(viewName) {{
            currentView = viewName;
            const tabCards = document.getElementById('tab-cards');
            const tabTimeline = document.getElementById('tab-timeline');
            const findingsContainer = document.getElementById('findings-container');
            const timelineContainer = document.getElementById('timeline-container');

            if (viewName === 'timeline') {{
                if (tabCards) tabCards.classList.remove('active');
                if (tabTimeline) tabTimeline.classList.add('active');
                if (findingsContainer) findingsContainer.style.display = 'none';
                if (timelineContainer) timelineContainer.style.display = 'block';
            }} else {{
                if (tabTimeline) tabTimeline.classList.remove('active');
                if (tabCards) tabCards.classList.add('active');
                if (timelineContainer) timelineContainer.style.display = 'none';
                if (findingsContainer) findingsContainer.style.display = 'block';
            }}
            filterFindings();
        }}

        function filterFindings(level) {{
            if (level) {{
                currentFilter = level;
            }}

            document.querySelectorAll('.filter-btn').forEach(btn => {{
                if (btn.getAttribute('data-filter') === currentFilter) {{
                    btn.classList.add('active');
                }} else {{
                    btn.classList.remove('active');
                }}
            }});

            const searchInput = document.getElementById('finding-search');
            const query = searchInput ? searchInput.value.toLowerCase().trim() : '';

            // Filtruj karty dowodowe
            const cards = document.querySelectorAll('.finding-card');
            let visibleCards = 0;
            cards.forEach(card => {{
                const cardLevel = card.getAttribute('data-level');
                const matchesLevel = (currentFilter === 'all' || cardLevel === currentFilter);
                const cardText = card.textContent.toLowerCase();
                const matchesSearch = !query || cardText.includes(query);

                if (matchesLevel && matchesSearch) {{
                    card.style.display = '';
                    visibleCards++;
                }} else {{
                    card.style.display = 'none';
                }}
            }});

            // Filtruj pozycje osi czasu
            const timelineItems = document.querySelectorAll('.timeline-item');
            let visibleTimeline = 0;
            timelineItems.forEach(item => {{
                const itemLevel = item.getAttribute('data-level');
                const matchesLevel = (currentFilter === 'all' || itemLevel === currentFilter);
                const itemText = item.textContent.toLowerCase();
                const matchesSearch = !query || itemText.includes(query);

                if (matchesLevel && matchesSearch) {{
                    item.style.display = '';
                    visibleTimeline++;
                }} else {{
                    item.style.display = 'none';
                }}
            }});

            const visibleCountEl = document.getElementById('visible-count');
            if (visibleCountEl) {{
                visibleCountEl.textContent = (currentView === 'cards') ? visibleCards : visibleTimeline;
            }}

            const emptyCards = document.getElementById('no-findings');
            if (emptyCards) {{
                emptyCards.style.display = (visibleCards === 0 && cards.length > 0) ? 'block' : 'none';
            }}

            const emptyTimeline = document.getElementById('no-timeline-findings');
            if (emptyTimeline) {{
                emptyTimeline.style.display = (visibleTimeline === 0 && timelineItems.length > 0) ? 'block' : 'none';
            }}
        }}

        function copyStaffSummary() {{
            const verdictEl = document.querySelector('.verdict-title');
            const verdictTitle = verdictEl ? verdictEl.textContent.trim() : 'VERDICT';
            const timestampEl = document.querySelector('.header-meta strong');
            const timestamp = timestampEl ? timestampEl.textContent.trim() : '';
            const detEl = document.querySelector('.stat-value.red');
            const detCount = detEl ? detEl.textContent.trim() : '0';
            const warnEl = document.querySelector('.stat-value.amber');
            const warnCount = warnEl ? warnEl.textContent.trim() : '0';

            const items = [];
            document.querySelectorAll('.timeline-item.badge-danger, .finding-card.badge-danger').forEach(el => {{
                if (items.length < 6) {{
                    const titleEl = el.querySelector('.timeline-title, .finding-title');
                    const timeEl = el.querySelector('.timeline-time');
                    if (titleEl) {{
                        const title = titleEl.textContent.trim();
                        const timeStr = timeEl ? ` [${{timeEl.textContent.trim()}}]` : '';
                        const line = `• 🚨 ${{title}}${{timeStr}}`;
                        if (!items.includes(line)) {{
                            items.push(line);
                        }}
                    }}
                }}
            }});

            if (items.length === 0) {{
                document.querySelectorAll('.timeline-item.badge-warning, .finding-card.badge-warning').forEach(el => {{
                    if (items.length < 4) {{
                        const titleEl = el.querySelector('.timeline-title, .finding-title');
                        const timeEl = el.querySelector('.timeline-time');
                        if (titleEl) {{
                            const title = titleEl.textContent.trim();
                            const timeStr = timeEl ? ` [${{timeEl.textContent.trim()}}]` : '';
                            const line = `• ⚠️ ${{title}}${{timeStr}}`;
                            if (!items.includes(line)) {{
                                items.push(line);
                            }}
                        }}
                    }}
                }});
            }}

            const itemsText = items.length > 0 ? items.join('
') : '{js_clean_line}';

            const textToCopy = `=== GRIND SCANNER FORENSIC REPORT ===
` +
                `{js_copy_verdict} ${{verdictTitle}}
` +
                `{js_copy_date} ${{timestamp}}
` +
                `{js_copy_stats}
` +
                `{js_copy_findings}
${{itemsText}}
` +
                `====================================`;

            if (navigator.clipboard && navigator.clipboard.writeText) {{
                navigator.clipboard.writeText(textToCopy).then(() => {{
                    notifyCopySuccess();
                }}).catch(() => {{
                    fallbackCopy(textToCopy);
                }});
            }} else {{
                fallbackCopy(textToCopy);
            }}
        }}

        function notifyCopySuccess() {{
            const btn = document.getElementById('quick-copy-btn');
            if (btn) {{
                const orig = btn.innerHTML;
                btn.innerHTML = '{js_copied_success}';
                btn.style.borderColor = 'var(--green)';
                btn.style.color = 'var(--green)';
                setTimeout(() => {{
                    btn.innerHTML = orig;
                    btn.style.borderColor = '';
                    btn.style.color = '';
                }}, 2000);
            }}
        }}

        function fallbackCopy(text) {{
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            try {{
                document.execCommand('copy');
                notifyCopySuccess();
            }} catch (e) {{
                alert('{js_copy_fallback_error}');
            }}
            document.body.removeChild(ta);
        }}
    </script>
</body>
</html>"#,
        html_lang = html_lang,
        page_title = page_title,
        version = html_escape(&report.scanner_version),
        timestamp = html_escape(&report.timestamp),
        duration = duration_secs,
        verdict_class = verdict_class,
        verdict_title = verdict_title,
        verdict_desc = verdict_desc,
        meta_generated = meta_generated,
        meta_duration = meta_duration,
        stat_det_label = stat_det_label,
        stat_det_title = stat_det_title,
        stat_warn_label = stat_warn_label,
        stat_warn_title = stat_warn_title,
        stat_info_label = stat_info_label,
        stat_info_title = stat_info_title,
        stat_time_label = stat_time_label,
        stat_time_title = stat_time_title,
        meta_admin_key = meta_admin_key,
        admin_status = admin_status,
        meta_proc_key = meta_proc_key,
        target_str = target_str,
        meta_uptime_key = meta_uptime_key,
        uptime_str = html_escape(&uptime_str),
        meta_yara_key = meta_yara_key,
        meta_yara_val = meta_yara_val,
        tab_cards_label = tab_cards_label,
        tab_timeline_label = tab_timeline_label,
        quick_copy_btn_label = quick_copy_btn_label,
        filter_all_label = filter_all_label,
        filter_det_label = filter_det_label,
        filter_warn_label = filter_warn_label,
        filter_info_label = filter_info_label,
        search_placeholder = search_placeholder,
        visible_badge_label = visible_badge_label,
        findings_count = findings_count,
        findings_html = findings_html,
        no_findings_filtered = no_findings_filtered,
        timeline_html = timeline_html,
        no_timeline_filtered = no_timeline_filtered,
        footer_text = footer_text,
        js_clean_line = js_clean_line,
        js_copy_verdict = js_copy_verdict,
        js_copy_date = js_copy_date,
        js_copy_stats = js_copy_stats,
        js_copy_findings = js_copy_findings,
        js_copied_success = js_copied_success,
        js_copy_fallback_error = js_copy_fallback_error,
    )
}

pub fn save_html_report_file(report: &ScanReport, duration_secs: f64) -> std::io::Result<String> {
    let now = chrono::Local::now();
    let filename = format!("grind_scan_report_{}.html", now.format("%Y%m%d_%H%M%S"));
    let html = generate_html_report(report, duration_secs);

    let mut file = File::create(&filename)?;
    file.write_all(html.as_bytes())?;
    Ok(filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};

    #[test]
    fn test_calculate_report_seal_hash() {
        let mut report1 = ScanReport::new(true);
        report1.add(
            ScanFinding::new(
                "Pulse Client",
                FindingCategory::MinecraftRuntime,
                VerdictLevel::Detection,
                "Wykryto obecność Pulse Client w pamięci JVM (Wzorzec: 'pulse.jar')",
            )
            .with_evidence("Matched Keyword", "pulse.jar")
            .with_evidence("Adres pamięci", "0x7FFE1000"),
        );

        let hash1 = calculate_report_seal_hash(&report1);
        assert_eq!(hash1.len(), 64);

        // Powtarzalność
        let hash2 = calculate_report_seal_hash(&report1);
        assert_eq!(hash1, hash2);

        // Zmiana raportu powoduje zmianę hasha
        let mut report2 = report1.clone();
        report2.add(ScanFinding::new(
            "Doomsday",
            FindingCategory::MinecraftRuntime,
            VerdictLevel::Detection,
            "Wykryto Doomsday",
        ));
        let hash3 = calculate_report_seal_hash(&report2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_generate_html_report_contains_seal_and_no_opsec_leaks() {
        let mut report = ScanReport::new(true);
        report.add(
            ScanFinding::new(
                "Pulse Client",
                FindingCategory::MinecraftRuntime,
                VerdictLevel::Detection,
                "Wykryto nielegalny moduł Pulse (Wzorzec: 'pulse_module_secret_sig')",
            )
            .with_evidence("Matched Keyword", "pulse_module_secret_sig")
            .with_evidence("Adres pamięci", "0x7FFE2000"),
        );

        let html = generate_html_report(&report, 2.5);

        // Nazwa cheata musi być widoczna:
        assert!(html.contains("Pulse Client"));
        // Legalny dowód forensic / runtime musi być widoczny:
        assert!(html.contains("0x7FFE2000"));
        // Kryptograficzna pieczęć nie powinna być widoczna w raporcie HTML:
        assert!(!html.contains("Kryptograficzna Pieczęć"));
        assert!(!html.contains("seal-card"));

        // OPSEC: Wrażliwy string wzorca i 'Matched Keyword' NIE MOGĄ pojawić się w raporcie:
        assert!(!html.contains("pulse_module_secret_sig"));
        assert!(!html.contains("Matched Keyword"));
    }

    #[test]
    fn test_html_report_contains_interactive_filters() {
        let mut report = ScanReport::new(true);
        report.add(ScanFinding::new(
            "Detection Item",
            FindingCategory::MinecraftRuntime,
            VerdictLevel::Detection,
            "Wykryto detekcję",
        ));
        report.add(ScanFinding::new(
            "Warning Item",
            FindingCategory::WindowsForensics,
            VerdictLevel::Warning,
            "Wykryto ostrzeżenie",
        ));

        let html = generate_html_report(&report, 1.0);
        assert!(html.contains("data-level=\"detection\""));
        assert!(html.contains("data-level=\"warning\""));
        assert!(html.contains("filterFindings('detection')"));
        assert!(html.contains("filterFindings('warning')"));
        assert!(html.contains("filterFindings('all')"));
        assert!(html.contains("finding-search"));
    }

    #[test]
    fn test_html_report_contains_forensic_timeline() {
        let mut report = ScanReport::new(true);
        report.add(
            ScanFinding::new(
                "USN Deleted Loader",
                FindingCategory::WindowsForensics,
                VerdictLevel::Detection,
                "Usunięto loader.jar",
            )
            .with_evidence("Czas usunięcia", "2026-10-05 20:32:58 (22m temu)")
            .with_evidence("Nazwa pliku", "loader.jar"),
        );

        let html = generate_html_report(&report, 1.2);
        assert!(html.contains("timeline-container"));
        assert!(html.contains("2026-10-05 20:32:58"));
        assert!(html.contains("22m temu"));
        assert!(html.contains("Oś Czasu Śledcza"));
        assert!(html.contains("Kopiuj Podsumowanie Śledcze"));
    }

    #[test]
    fn test_generate_discord_report_clean_and_detected() {
        // 1. Czysty raport
        let report_clean = ScanReport::new(true);
        let discord_clean = generate_discord_report(&report_clean, 2.5);
        assert!(discord_clean.contains("UNDETECTED"));
        assert!(discord_clean.contains("System czysty"));

        // 2. Raport z detekcją i dowodami (bez wycieku OPSEC)
        let mut report_det = ScanReport::new(true);
        report_det.target_process = Some("javaw.exe".to_string());
        report_det.target_pid = Some(4321);
        report_det.add(
            crate::report::ScanFinding::new(
                "Doomsday Ghost Client Core",
                crate::report::FindingCategory::MemoryInspection,
                VerdictLevel::Detection,
                "Wykryto moduł Doomsday Client (Wzorzec: 'doomsdayclient')",
            )
            .with_evidence("Adres pamięci", "0x7FFE1234")
            .with_evidence("Matched Keyword", "doomsdayclient"), // Powinno być ukryte
        );

        let discord_det = generate_discord_report(&report_det, 3.1);
        assert!(discord_det.contains("DETECTED"));
        assert!(discord_det.contains("Doomsday Ghost Client Core"));
        assert!(!discord_det.contains("Wzorzec:"));
        assert!(!discord_det.contains("Matched Keyword"));
        assert!(discord_det.contains("0x7FFE1234"));
    }

    #[test]
    fn test_generate_discord_report_english_and_polish() {
        let mut report = ScanReport::new(true);
        report.target_process = Some("javaw.exe".to_string());
        report.target_pid = Some(1234);
        report.add(
            crate::report::ScanFinding::new(
                "Argon Client",
                crate::report::FindingCategory::MinecraftRuntime,
                VerdictLevel::Detection,
                "Detected Argon Client module (Wzorzec: 'dev.lvstrng.argon')",
            )
            .with_evidence("Memory Address", "0x7067B92F0")
            .with_evidence("Matched Keyword", "dev.lvstrng.argon"),
        );

        // English Discord report
        let en_discord = generate_discord_report_with_lang(&report, 3.5, crate::i18n::Language::English);
        assert!(en_discord.contains("SCREENSHARE REPORT"));
        assert!(en_discord.contains("Final Verdict:"));
        assert!(en_discord.contains("DETECTED (CHEATS FOUND)"));
        assert!(en_discord.contains("Target:"));
        assert!(en_discord.contains("PC Uptime:"));
        assert!(en_discord.contains("Results Summary:"));
        assert!(en_discord.contains("Detected Threats / Modifications:"));
        assert!(en_discord.contains("Argon Client"));
        assert!(!en_discord.contains("dev.lvstrng.argon")); // OPSEC protected

        // Polish Discord report
        let pl_discord = generate_discord_report_with_lang(&report, 3.5, crate::i18n::Language::Polish);
        assert!(pl_discord.contains("RAPORT ZE SCREENSHARE"));
        assert!(pl_discord.contains("Werdykt końcowy:"));
        assert!(pl_discord.contains("DETECTED (WYKRYTO CHEATY)"));
        assert!(pl_discord.contains("Cel:"));
        assert!(pl_discord.contains("Czas działania PC (Uptime):"));
        assert!(pl_discord.contains("Podsumowanie wyników:"));
        assert!(pl_discord.contains("Wykryte zagrożenia / Modyfikacje:"));
        assert!(pl_discord.contains("Argon Client"));
        assert!(!pl_discord.contains("dev.lvstrng.argon")); // OPSEC protected
    }

    #[test]
    fn test_generate_html_report_english_and_polish() {
        let mut report = ScanReport::new(false);
        report.add(
            crate::report::ScanFinding::new(
                "Doomsday Client",
                crate::report::FindingCategory::MinecraftRuntime,
                VerdictLevel::Detection,
                "Detected Doomsday Ghost Client (Wzorzec: 'doomsday')",
            )
            .with_evidence("Address", "0x7FFE9999")
            .with_evidence("Matched Keyword", "doomsday"),
        );

        // English HTML report
        let en_html = generate_html_report_with_lang(&report, 2.0, crate::i18n::Language::English);
        assert!(en_html.contains("<html lang=\"en\">"));
        assert!(en_html.contains("Grind Scanner - Forensic Inspection Report"));
        assert!(en_html.contains("UNAUTHORIZED SOFTWARE DETECTED"));
        assert!(en_html.contains("Evidence Cards"));
        assert!(en_html.contains("Forensic Timeline"));
        assert!(en_html.contains("Copy Staff Summary"));
        assert!(en_html.contains("Search findings..."));
        assert!(en_html.contains("Detections 🔍"));
        assert!(!en_html.contains("doomsday")); // OPSEC protected

        // Polish HTML report
        let pl_html = generate_html_report_with_lang(&report, 2.0, crate::i18n::Language::Polish);
        assert!(pl_html.contains("<html lang=\"pl\">"));
        assert!(pl_html.contains("Grind Scanner - Raport Kontroli Śledczej"));
        assert!(pl_html.contains("WYKRYTO NIELEGALNE OPROGRAMOWANIE"));
        assert!(pl_html.contains("Karty Dowodowe"));
        assert!(pl_html.contains("Oś Czasu Śledcza"));
        assert!(pl_html.contains("Kopiuj Podsumowanie Śledcze"));
        assert!(pl_html.contains("Szukaj w ustaleniach..."));
        assert!(pl_html.contains("Detekcje 🔍"));
        assert!(!pl_html.contains("doomsday")); // OPSEC protected
    }
}
