pub mod aob;
pub mod custom_rules;
pub mod embedded_rules;
pub mod forensics;
pub mod jvm;
pub mod network;
pub mod self_defense;
pub mod tampering;
pub mod yara_engine;

use crate::report::{FindingCategory, ScanFinding, ScanReport, VerdictLevel};

#[derive(Clone, Debug)]
pub enum ScanEvent {
    Stage {
        name: String,
        step: usize,
        total: usize,
    },
    MemoryProgress {
        scanned_mb: usize,
    },
    Log(String),
    #[allow(dead_code)]
    Finding(ScanFinding),
    Finished(ScanReport),
}

pub fn run_full_scan(report: &mut ScanReport) {
    run_full_scan_with_events(report, |event| {
        match event {
            ScanEvent::Log(msg) => println!("{}", msg),
            ScanEvent::MemoryProgress { scanned_mb: _ } => {}
            _ => {}
        }
    });
}

pub fn run_full_scan_with_events<F: Fn(ScanEvent) + Send + Sync + 'static>(
    report: &mut ScanReport,
    on_event: F,
) {
    let total_steps = 17;
    let lang = crate::i18n::Language::current();

    // Krok 1: Scanner Self-Defense & Anti-Hooking
    on_event(ScanEvent::Stage {
        name: lang.stage_name(1).to_string(),
        step: 1,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Weryfikacja integralności pamięci skanera i funkcji WinAPI (Anti-Hooking Self-Defense)...".to_string()));
    let findings_before = report.findings.len();
    self_defense::check_scanner_integrity(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 2: YARA Engine & Custom Detection Rules
    on_event(ScanEvent::Stage {
        name: lang.stage_name(2).to_string(),
        step: 2,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Ładowanie silnika reguł detekcji i weryfikacja katalogu /rules...".to_string()));
    let custom_rules = custom_rules::CustomRulesManager::load();
    if let Some(ref dir) = custom_rules.rules_dir {
        on_event(ScanEvent::Log(format!("  [+] Katalog reguł użytkownika: {}", dir.display())));
    }
    for err in &custom_rules.syntax_errors {
        on_event(ScanEvent::Log(format!("  [-] {}", err)));
    }
    let (yara_engine, yara_errors) = yara_engine::YaraScannerEngine::new_with_custom(&custom_rules.yara_rules);
    for err in yara_errors {
        on_event(ScanEvent::Log(format!("  [-] {}", err)));
    }
    if custom_rules.yara_rules.is_empty() && custom_rules.string_rules.is_empty() {
        on_event(ScanEvent::Log(format!("  [✓] Załadowano {} wbudowanych zestawów reguł YARA (brak dodatkowych reguł w /rules).", yara_engine.compiled_rules_count)));
    } else {
        on_event(ScanEvent::Log(format!(
            "  [✓] Załadowano reguły: {} YARA (w tym {} własnych) oraz {} własnych sygnatur tekstowych (z {} plików).",
            yara_engine.compiled_rules_count,
            yara_engine.custom_rules_count,
            custom_rules.string_rules.len(),
            custom_rules.loaded_files_count
        )));
    }

    // Krok 3: Minecraft Process, Memory & DLL Hijacking
    on_event(ScanEvent::Stage {
        name: lang.stage_name(3).to_string(),
        step: 3,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie procesów Minecrafta (javaw.exe)...".to_string()));
    let mc_processes = jvm::find_minecraft_processes();

    if mc_processes.is_empty() {
        let finding = ScanFinding::new(
            "Minecraft Not Running",
            FindingCategory::MinecraftRuntime,
            VerdictLevel::Information,
            "No active javaw.exe or java.exe process detected at scan time. Relying on forensic traces.",
        );
        report.add(finding.clone());
        on_event(ScanEvent::Finding(finding));

        let findings_before = report.findings.len();
        jvm::check_cheat_filesystem_artifacts(report);
        for f in &report.findings[findings_before..] {
            on_event(ScanEvent::Finding(f.clone()));
        }
    } else {
        for proc in &mc_processes {
            on_event(ScanEvent::Log(format!("  [+] Wykryto instancję Minecrafta (PID: {}, Klient: {}). Inspekcja JVM, pamięci i modułów...", proc.pid, proc.client_brand)));
            let findings_before = report.findings.len();

            let on_event_ref = &on_event;
            jvm::scan_minecraft_instance_with_progress(proc, &yara_engine, &custom_rules, report, |mb| {
                on_event_ref(ScanEvent::MemoryProgress { scanned_mb: mb });
            });

            for f in &report.findings[findings_before..] {
                on_event(ScanEvent::Finding(f.clone()));
            }
        }
    }

    // Krok 4: NTFS USN Journal
    on_event(ScanEvent::Stage {
        name: lang.stage_name(4).to_string(),
        step: 4,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie śladów śledczych USN Journal (NTFS partycje dyskowe)...".to_string()));
    let findings_before = report.findings.len();
    forensics::usn::scan_all_usn_journals(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 5: Prefetch
    on_event(ScanEvent::Stage {
        name: lang.stage_name(5).to_string(),
        step: 5,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie pamięci podręcznej Windows Prefetch...".to_string()));
    let findings_before = report.findings.len();
    forensics::prefetch::scan_prefetch(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 6: BAM
    on_event(ScanEvent::Stage {
        name: lang.stage_name(6).to_string(),
        step: 6,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie rejestru wykonania programów BAM...".to_string()));
    let findings_before = report.findings.len();
    forensics::bam::scan_bam(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 7: Amcache.hve Forensics
    on_event(ScanEvent::Stage {
        name: lang.stage_name(7).to_string(),
        step: 7,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie bazy kompatybilności Amcache.hve (wykonanie i usunięcie z dysku)...".to_string()));
    let findings_before = report.findings.len();
    forensics::amcache::scan_amcache(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 8: MuiCache (Pamięć powłoki Windows Shell i usunięte aplikacje)
    on_event(ScanEvent::Stage {
        name: lang.stage_name(8).to_string(),
        step: 8,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie pamięci podręcznej powłoki Windows Shell MuiCache...".to_string()));
    let findings_before = report.findings.len();
    forensics::muicache::scan_muicache(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 9: UserAssist (Historia uruchomień GUI)
    on_event(ScanEvent::Stage {
        name: lang.stage_name(9).to_string(),
        step: 9,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie historii wykonania programów UserAssist (ROT-13)...".to_string()));
    let findings_before = report.findings.len();
    forensics::userassist::scan_userassist(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 10: Kosz systemowy ($Recycle.Bin)
    on_event(ScanEvent::Stage {
        name: lang.stage_name(10).to_string(),
        step: 10,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie metadanych indeksów i usuniętych plików w $Recycle.Bin...".to_string()));
    let findings_before = report.findings.len();
    forensics::recycle_bin::scan_recycle_bin(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 11: ShimCache (AppCompatCache)
    on_event(ScanEvent::Stage {
        name: lang.stage_name(11).to_string(),
        step: 11,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie pamięci podręcznej programów ShimCache (AppCompatCache)...".to_string()));
    let findings_before = report.findings.len();
    forensics::shimcache::scan_shimcache(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 12: PowerShell History
    on_event(ScanEvent::Stage {
        name: lang.stage_name(12).to_string(),
        step: 12,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie historii poleceń konsoli PowerShell (narzędzia cleaner / pobieranie)...".to_string()));
    let findings_before = report.findings.len();
    forensics::powershell::scan_powershell_history(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 13: Dyski wirtualne VHD/VHDX, dyski RAM i udziały sieciowe
    on_event(ScanEvent::Stage {
        name: lang.stage_name(13).to_string(),
        step: 13,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie udziałów sieciowych (MRU), zdarzeń VHDMP oraz sterowników RAMDisk...".to_string()));
    let findings_before = report.findings.len();
    forensics::virtual_drives::scan_virtual_and_network_drives(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 14: USB & Removable / MountPoints2
    on_event(ScanEvent::Stage {
        name: lang.stage_name(14).to_string(),
        step: 14,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie podłączeń pamięci USB i punktów montowania (USBSTOR / MountPoints2)...".to_string()));
    let findings_before = report.findings.len();
    forensics::usbstor::scan_usbstor(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 15: PcaSvc, Recent LNK, Jump Lists, WER & Zone.Identifier
    on_event(ScanEvent::Stage {
        name: lang.stage_name(15).to_string(),
        step: 15,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie bazy PcaSvc, skrótów Recent, Jump Lists i raportów awarii WER...".to_string()));
    let findings_before = report.findings.len();
    forensics::pcasvc::scan_pcasvc_logs(report);
    forensics::recent_lnk::scan_recent_and_ads(report);
    forensics::jumplists::scan_jump_lists(report);
    forensics::wer::scan_wer_crash_reports(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 16: Anti-Tampering, BYOVD Drivers & EventLog
    on_event(ScanEvent::Stage {
        name: lang.stage_name(16).to_string(),
        step: 16,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Sprawdzanie podatnych sterowników jądra (BYOVD), trybu Test-Signing oraz EventLog...".to_string()));
    let findings_before = report.findings.len();
    tampering::check_system_tampering(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    // Krok 17: Network (TCP Connections, DNS Cache & Hosts file)
    on_event(ScanEvent::Stage {
        name: lang.stage_name(17).to_string(),
        step: 17,
        total: total_steps,
    });
    on_event(ScanEvent::Log("  [+] Skanowanie połączeń TCP, pamięci DNS Cache oraz integralności pliku hosts...".to_string()));
    let findings_before = report.findings.len();
    network::scan_active_connections(report);
    network::scan_dns_cache(report);
    network::check_hosts_file_integrity(report);
    for f in &report.findings[findings_before..] {
        on_event(ScanEvent::Finding(f.clone()));
    }

    on_event(ScanEvent::Finished(report.clone()));
}
