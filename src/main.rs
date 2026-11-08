#![windows_subsystem = "windows"]

mod gui;
pub mod i18n;
mod report;
pub mod report_export;
mod scanner;
mod security;

use report::ScanReport;
use std::env;
use std::io::{self, BufRead};

fn main() -> eframe::Result<()> {
    // Suppress system modal error dialogs (SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)
    // Ensures Windows never halts execution with "Bad Image / 0xc0000428" popups
    unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode(
            windows_sys::Win32::System::Diagnostics::Debug::SEM_FAILCRITICALERRORS
                | windows_sys::Win32::System::Diagnostics::Debug::SEM_NOGPFAULTERRORBOX,
        );
        windows_sys::Win32::System::Diagnostics::Debug::SetThreadErrorMode(
            windows_sys::Win32::System::Diagnostics::Debug::SEM_FAILCRITICALERRORS
                | windows_sys::Win32::System::Diagnostics::Debug::SEM_NOGPFAULTERRORBOX,
            std::ptr::null_mut(),
        );
    }

    // Apply process mitigation policies and anti-tamper protections (Anti-Bypass Hardening)
    security::hardening::apply_all_hardening();

    // Ensure the /rules/ folder and template documentation files exist on startup
    scanner::custom_rules::ensure_rules_templates_exist();

    let args: Vec<String> = env::args().collect();
    let is_cli = args.iter().any(|a| a == "--cli" || a == "-c" || a == "--headless");

    if is_cli {
        run_cli_mode();
        Ok(())
    } else {
        run_gui_mode()
    }
}

fn run_gui_mode() -> eframe::Result<()> {
    security::anti_analysis::crash_if_debugged();

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([620.0, 525.0])
            .with_min_inner_size([540.0, 430.0])
            .with_title("Grind Scanner - Forensic Anticheat")
            .with_active(true),
        ..Default::default()
    };

    eframe::run_native(
        "Grind Scanner - Minecraft Forensic Anticheat",
        native_options,
        Box::new(|cc| Ok(Box::new(gui::GrindScannerApp::new(cc)))),
    )
}

#[cfg(windows)]
fn attach_parent_console() {
    type AttachConsoleFn = unsafe extern "system" fn(dw_process_id: u32) -> i32;
    unsafe {
        let kernel32 = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"kernel32.dll\0".as_ptr());
        if !kernel32.is_null() {
            let p_attach = windows_sys::Win32::System::LibraryLoader::GetProcAddress(kernel32, b"AttachConsole\0".as_ptr());
            if let Some(f) = p_attach {
                let attach_fn: AttachConsoleFn = std::mem::transmute(f);
                const ATTACH_PARENT_PROCESS: u32 = 0xFFFFFFFF;
                attach_fn(ATTACH_PARENT_PROCESS);
            }
        }
    }
}

fn run_cli_mode() {
    #[cfg(windows)]
    attach_parent_console();
    print_banner();

    // 1. Anti-analysis check (crash immediately if a debugger is detected)
    security::anti_analysis::crash_if_debugged();

    // 2. Privilege verification and elevation (SeDebugPrivilege)
    let is_admin = security::anti_analysis::is_elevated();
    let lang = i18n::Language::current();
    if is_admin {
        if lang.is_polish() {
            println!("\x1b[92m[✓] Uprawnienia Administratora aktywne.\x1b[0m");
            if security::anti_analysis::enable_debug_privilege() {
                println!("\x1b[92m[✓] Nadano SeDebugPrivilege (pełny dostęp do pamięci procesów).\x1b[0m\n");
            }
        } else {
            println!("\x1b[92m[✓] Administrator Privileges active.\x1b[0m");
            if security::anti_analysis::enable_debug_privilege() {
                println!("\x1b[92m[✓] Granted SeDebugPrivilege (full process memory access).\x1b[0m\n");
            }
        }
    } else {
        if lang.is_polish() {
            println!("\x1b[93m[!] UWAGA: Skaner uruchomiono bez uprawnień Administratora!\x1b[0m");
            println!("\x1b[90m    (Dostęp do niskopoziomowego dysku NTFS USN Journal i pamięci niektórych usług może być ograniczony)\x1b[0m\n");
        } else {
            println!("\x1b[93m[!] WARNING: Scanner launched without Administrator Privileges!\x1b[0m");
            println!("\x1b[90m    (Access to low-level NTFS USN Journal and memory of some services may be restricted)\x1b[0m\n");
        }
    }

    // 3. Report initialization
    let mut report = ScanReport::new(is_admin);

    if lang.is_polish() {
        println!("[*] Rozpoczynanie wielowarstwowej inspekcji śledczej Minecrafta...\n");
    } else {
        println!("[*] Starting multi-layered Minecraft forensic inspection...\n");
    }
    let start_time = std::time::Instant::now();
    scanner::run_full_scan(&mut report);
    let duration = start_time.elapsed().as_secs_f64();

    // 4. Console summary
    report.print_console_summary();

    // 5. Save report to JSON and standalone HTML files
    let output_file = "scan_report.json";
    if let Err(e) = report.save_to_json(output_file) {
        println!("[-] Błąd zapisu raportu JSON: {}", e);
    } else if lang.is_polish() {
        println!("  [✓] Raport JSON zapisano do: \x1b[1m{}\x1b[0m", output_file);
    } else {
        println!("  [✓] JSON report saved to: \x1b[1m{}\x1b[0m", output_file);
    }

    if let Ok(html_path) = report_export::save_html_report_file(&report, duration) {
        if lang.is_polish() {
            println!("  [✓] Interaktywny raport HTML zapisano do: \x1b[1m{}\x1b[0m\n", html_path);
        } else {
            println!("  [✓] Interactive HTML report saved to: \x1b[1m{}\x1b[0m\n", html_path);
        }
    }

    if lang.is_polish() {
        println!("Naciśnij [ENTER], aby zakończyć działanie...");
    } else {
        println!("Press [ENTER] to exit...");
    }
    let mut stdin = io::stdin().lock();
    let mut _line = String::new();
    let _ = stdin.read_line(&mut _line);
}

fn print_banner() {
    println!("\x1b[96m");
    println!(r#"  ____ ____  ___ _   _ ____    ____   ____    _    _   _ _   _ _____ ____  "#);
    println!(r#" / ___|  _ \|_ _| \ | |  _ \  / ___| / ___|  / \  | \ | | \ | | ____|  _ \ "#);
    println!(r#"| |  _| |_) || ||  \| | | | | \___ \| |     / _ \ |  \| |  \| |  _| | |_) |"#);
    println!(r#"| |_| |  _ < | || |\  | |_| |  ___) | |___ / ___ \| |\  | |\  | |___|  _ < "#);
    println!(r#" \____|_| \_\___|_| \_|____/  |____/ \____/_/   \_\_| \_|_| \_|_____|_| \_\ "#);
    println!("\x1b[0m");
    println!("       \x1b[1mMINECRAFT FORENSIC & MEMORY ANTICHEAT SCANNER v1.0.0\x1b[0m");
    println!("       Architektura śledcza oparta na inspekcji JVM i NTFS Forensics");
    println!("--------------------------------------------------------------------------------\n");
}
