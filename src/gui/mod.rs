use crate::report::ScanReport;
use crate::scanner::{run_full_scan_with_events, ScanEvent};
use crate::security::anti_analysis::{crash_if_debugged, is_elevated};
use eframe::egui::{
    self, Align, Button, Color32, CornerRadius, Frame, Layout, Margin, ProgressBar, RichText,
    Stroke, Ui, Vec2,
};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FinalVerdict {
    Detected,
    Suspicious,
    Undetected,
}

impl FinalVerdict {
    pub fn from_report(report: &ScanReport) -> Self {
        if report.detections_count() > 0 {
            FinalVerdict::Detected
        } else if report.warnings_count() > 0 {
            FinalVerdict::Suspicious
        } else {
            FinalVerdict::Undetected
        }
    }

    pub fn title(&self, lang: crate::i18n::Language) -> &'static str {
        match self {
            FinalVerdict::Detected => "DETECTED",
            FinalVerdict::Suspicious => {
                if lang.is_polish() {
                    "SUSPICIOUS (DO WERYFIKACJI)"
                } else {
                    "SUSPICIOUS (TO CHECK)"
                }
            }
            FinalVerdict::Undetected => "UNDETECTED",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            FinalVerdict::Detected => "🚨",
            FinalVerdict::Suspicious => "\u{26A0}",
            FinalVerdict::Undetected => "✅",
        }
    }

    pub fn color(&self) -> Color32 {
        match self {
            FinalVerdict::Detected => Color32::from_rgb(255, 35, 75),     // Crimson / Red
            FinalVerdict::Suspicious => Color32::from_rgb(255, 185, 10),  // Amber / Gold
            FinalVerdict::Undetected => Color32::from_rgb(0, 230, 118),   // Emerald / Green
        }
    }

    pub fn bg_color(&self) -> Color32 {
        match self {
            FinalVerdict::Detected => Color32::from_rgb(42, 14, 20),
            FinalVerdict::Suspicious => Color32::from_rgb(42, 32, 10),
            FinalVerdict::Undetected => Color32::from_rgb(12, 38, 24),
        }
    }

    pub fn border_color(&self) -> Color32 {
        match self {
            FinalVerdict::Detected => Color32::from_rgb(180, 25, 55),
            FinalVerdict::Suspicious => Color32::from_rgb(180, 130, 10),
            FinalVerdict::Undetected => Color32::from_rgb(0, 160, 80),
        }
    }

    pub fn description(&self, report: &ScanReport, lang: crate::i18n::Language) -> String {
        if lang.is_polish() {
            match self {
                FinalVerdict::Detected => format!(
                    "Wykryto {} nieautoryzowane modyfikacje, narzędzia lub ślady cheatów w systemie / pamięci.",
                    report.detections_count()
                ),
                FinalVerdict::Suspicious => format!(
                    "Wykryto {} ostrzeżeń wymagających weryfikacji manualnej (anomalie pamięci, czyszczenie historii lub restart).",
                    report.warnings_count()
                ),
                FinalVerdict::Undetected => {
                    "System czysty. Brak jakichkolwiek śladów cheatów, modyfikacji pamięci i manipulacji śledczych.".to_string()
                }
            }
        } else {
            match self {
                FinalVerdict::Detected => format!(
                    "Detected {} unauthorized modifications, cheat tools, or artifacts in system / memory.",
                    report.detections_count()
                ),
                FinalVerdict::Suspicious => format!(
                    "Detected {} warnings requiring manual inspection (memory anomalies, history wipe, or reboot).",
                    report.warnings_count()
                ),
                FinalVerdict::Undetected => {
                    "System clean. No traces of cheats, memory modifications, or forensic tampering found.".to_string()
                }
            }
        }
    }
}

enum AppState {
    Scanning {
        stage_name: String,
        step: usize,
        total_steps: usize,
        memory_mb: usize,
        start_time: Instant,
        receiver: Receiver<ScanEvent>,
    },
    Results {
        report: ScanReport,
        duration_secs: f64,
        verdict: FinalVerdict,
        saved_html_path: Option<String>,
        copied_timer: f32,
        copied_discord_timer: f32,
    },
}

pub struct GrindScannerApp {
    is_admin: bool,
    is_debugged: bool,
    lang: crate::i18n::Language,
    state: AppState,
}

impl GrindScannerApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        crash_if_debugged();
        let is_admin = is_elevated();
        let is_debugged = false;
        let lang = crate::i18n::Language::current();

        let initial_stage = if lang.is_polish() {
            "Inicjalizacja procedury śledczej...".to_string()
        } else {
            "Initializing forensic scan procedure...".to_string()
        };

        let mut app = Self {
            is_admin,
            is_debugged,
            lang,
            state: AppState::Scanning {
                stage_name: initial_stage,
                step: 1,
                total_steps: 17,
                memory_mb: 0,
                start_time: Instant::now(),
                receiver: channel().1,
            },
        };

        // Automatyczne rozpoczęcie skanowania zaraz po uruchomieniu
        app.start_scan();
        app
    }

    fn start_scan(&mut self) {
        let (sender, receiver) = channel();
        let is_admin = self.is_admin;

        thread::spawn(move || {
            crash_if_debugged();
            crate::security::hardening::hide_current_thread_from_debugger();

            let mut report = ScanReport::new(is_admin);
            let sender_clone = sender.clone();

            run_full_scan_with_events(&mut report, move |event| {
                let _ = sender_clone.send(event);
            });

            let _ = report.save_to_json("scan_report.json");
            let _ = sender.send(ScanEvent::Finished(report));
        });

        let start_stage = if self.lang.is_polish() {
            "Weryfikacja integralności skanera i API...".to_string()
        } else {
            "Verifying scanner integrity and WinAPI...".to_string()
        };

        self.state = AppState::Scanning {
            stage_name: start_stage,
            step: 1,
            total_steps: 17,
            memory_mb: 0,
            start_time: Instant::now(),
            receiver,
        };
    }
}

impl eframe::App for GrindScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Ciemny motyw Cyber Dark
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = Color32::from_rgb(11, 15, 23);
        visuals.window_fill = Color32::from_rgb(11, 15, 23);
        visuals.widgets.noninteractive.bg_fill = Color32::from_rgb(20, 26, 38);
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(26, 34, 50);
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(38, 50, 75);
        visuals.widgets.active.bg_fill = Color32::from_rgb(0, 180, 216);
        ctx.set_visuals(visuals);

        let mut scan_finished_report = None;

        if let AppState::Scanning {
            ref mut stage_name,
            ref mut step,
            ref mut total_steps,
            ref mut memory_mb,
            start_time,
            ref receiver,
        } = self.state
        {
            ctx.request_repaint();

            while let Ok(event) = receiver.try_recv() {
                match event {
                    ScanEvent::Stage { name, step: s, total: t } => {
                        *stage_name = name;
                        *step = s;
                        *total_steps = t;
                    }
                    ScanEvent::MemoryProgress { scanned_mb } => {
                        *memory_mb = scanned_mb;
                    }
                    ScanEvent::Finished(report) => {
                        let duration = start_time.elapsed().as_secs_f64();
                        scan_finished_report = Some((report, duration));
                        break;
                    }
                    _ => {}
                }
            }
        }

        // Automatyczne generowanie i zapisanie raportu HTML po zakończeniu skanowania
        if let Some((report, duration)) = scan_finished_report {
            let html_path = crate::report_export::save_html_report_file(&report, duration).ok();
            let verdict = FinalVerdict::from_report(&report);

            self.state = AppState::Results {
                report,
                duration_secs: duration,
                verdict,
                saved_html_path: html_path,
                copied_timer: 0.0,
                copied_discord_timer: 0.0,
            };
        }

        let mut should_rescan = false;

        egui::CentralPanel::default().show(ctx, |ui| {
            render_logo_header(ui, self.is_admin, self.is_debugged);

            match self.state {
                AppState::Scanning {
                    ref stage_name,
                    step,
                    total_steps,
                    memory_mb,
                    start_time,
                    ..
                } => {
                    let elapsed = start_time.elapsed().as_secs_f32();
                    render_scanning(ui, stage_name, step, total_steps, memory_mb, elapsed, self.lang);
                }
                AppState::Results {
                    ref report,
                    duration_secs,
                    verdict,
                    ref saved_html_path,
                    ref mut copied_timer,
                    ref mut copied_discord_timer,
                } => {
                    if *copied_timer > 0.0 {
                        *copied_timer -= ctx.input(|i| i.stable_dt);
                    }
                    if *copied_discord_timer > 0.0 {
                        *copied_discord_timer -= ctx.input(|i| i.stable_dt);
                    }
                    should_rescan = render_results(
                        ui,
                        report,
                        duration_secs,
                        verdict,
                        saved_html_path,
                        copied_timer,
                        copied_discord_timer,
                        self.lang,
                    );
                }
            }
        });

        if should_rescan {
            self.start_scan();
        }
    }
}

fn render_logo_header(ui: &mut Ui, is_admin: bool, is_debugged: bool) {
    ui.vertical_centered(|ui| {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                if is_admin {
                    ui.label(RichText::new("🛡 ELEVATED").size(10.0).strong().color(Color32::from_rgb(0, 230, 118)));
                } else {
                    ui.label(RichText::new("⚠ STANDARD").size(10.0).strong().color(Color32::from_rgb(255, 179, 0)));
                }
                if is_debugged {
                    ui.label(RichText::new("⚡ DEBUGGER").size(10.0).strong().color(Color32::from_rgb(255, 23, 68)));
                }
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new("v1.0.0").size(10.0).color(Color32::from_rgb(100, 120, 140)));
            });
        });

        ui.add_space(2.0);
        ui.label(
            RichText::new("⚡ GRIND SCANNER")
                .size(24.0)
                .strong()
                .color(Color32::from_rgb(0, 229, 255)),
        );
        ui.label(
            RichText::new("FORENSIC ANTICHEAT ENGINE")
                .size(10.0)
                .extra_letter_spacing(1.8)
                .color(Color32::from_rgb(120, 145, 170)),
        );
        ui.add_space(6.0);
    });
}

fn render_scanning(
    ui: &mut Ui,
    stage_name: &str,
    step: usize,
    total_steps: usize,
    memory_mb: usize,
    elapsed_secs: f32,
    lang: crate::i18n::Language,
) {
    let progress = if total_steps > 0 {
        (step as f32 / total_steps as f32).clamp(0.01, 0.99)
    } else {
        0.05
    };
    let percentage = (progress * 100.0).round() as usize;

    ui.add_space(16.0);

    Frame::NONE
        .fill(Color32::from_rgb(16, 22, 34))
        .corner_radius(CornerRadius::same(12))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(32, 45, 70)))
        .inner_margin(Margin::same(24))
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                // Duży procent postępu
                ui.label(
                    RichText::new(format!("{}%", percentage))
                        .size(42.0)
                        .strong()
                        .color(Color32::from_rgb(0, 229, 255)),
                );

                ui.add_space(14.0);

                // Pasek postępu od 0 do 100%
                let pb = ProgressBar::new(progress)
                    .desired_height(14.0)
                    .corner_radius(CornerRadius::same(7))
                    .fill(Color32::from_rgb(0, 229, 255))
                    .animate(true);
                ui.add(pb);

                ui.add_space(16.0);

                // Aktualny etap
                let step_label = if lang.is_polish() {
                    format!("Krok {} z {}: {}", step, total_steps, stage_name)
                } else {
                    format!("Step {} of {}: {}", step, total_steps, stage_name)
                };
                ui.label(
                    RichText::new(step_label)
                        .size(12.5)
                        .strong()
                        .color(Color32::from_rgb(215, 230, 245)),
                );

                ui.add_space(8.0);

                // Metryki skanowania
                let mut meta_str = if lang.is_polish() {
                    format!("⏱ Czas: {:.1}s", elapsed_secs)
                } else {
                    format!("⏱ Time: {:.1}s", elapsed_secs)
                };
                if memory_mb > 0 {
                    if lang.is_polish() {
                        meta_str.push_str(&format!("  •  Pamięć JVM: {} MB", memory_mb));
                    } else {
                        meta_str.push_str(&format!("  •  JVM Memory: {} MB", memory_mb));
                    }
                }
                ui.label(
                    RichText::new(meta_str)
                        .size(11.0)
                        .color(Color32::from_rgb(120, 145, 170)),
                );
            });
        });
}

fn render_results(
    ui: &mut Ui,
    report: &ScanReport,
    duration_secs: f64,
    verdict: FinalVerdict,
    saved_html_path: &Option<String>,
    copied_timer: &mut f32,
    copied_discord_timer: &mut f32,
    lang: crate::i18n::Language,
) -> bool {
    let mut should_rescan = false;

    ui.add_space(6.0);

    // Karta Werdyktu (DETECTED / SUSPICIOUS (TO CHECK) / UNDETECTED)
    Frame::NONE
        .fill(verdict.bg_color())
        .corner_radius(CornerRadius::same(12))
        .stroke(Stroke::new(1.5_f32, verdict.border_color()))
        .inner_margin(Margin::same(18))
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new(format!("{} {}", verdict.icon(), verdict.title(lang)))
                        .size(28.0)
                        .strong()
                        .color(verdict.color()),
                );

                ui.add_space(6.0);
                ui.label(
                    RichText::new(verdict.description(report, lang))
                        .size(12.0)
                        .color(Color32::from_rgb(220, 230, 240)),
                );

                ui.add_space(12.0);

                // Pigułki statystyk
                ui.horizontal(|ui| {
                    ui.centered_and_justified(|ui| {
                        ui.horizontal(|ui| {
                            let det_color = if report.detections_count() > 0 {
                                Color32::from_rgb(255, 35, 75)
                            } else {
                                Color32::from_rgb(120, 140, 160)
                            };
                            Frame::NONE
                                .fill(Color32::from_rgb(20, 26, 38))
                                .corner_radius(CornerRadius::same(6))
                                .inner_margin(Margin::symmetric(10, 4))
                                .show(ui, |ui| {
                                    ui.label(RichText::new(format!("DETECTIONS: {}", report.detections_count())).size(11.0).strong().color(det_color));
                                });

                            let warn_color = if report.warnings_count() > 0 {
                                Color32::from_rgb(255, 185, 10)
                            } else {
                                Color32::from_rgb(120, 140, 160)
                            };
                            Frame::NONE
                                .fill(Color32::from_rgb(20, 26, 38))
                                .corner_radius(CornerRadius::same(6))
                                .inner_margin(Margin::symmetric(10, 4))
                                .show(ui, |ui| {
                                    ui.label(RichText::new(format!("WARNINGS: {}", report.warnings_count())).size(11.0).strong().color(warn_color));
                                });

                            let time_pill = if lang.is_polish() {
                                format!("CZAS: {:.1}s", duration_secs)
                            } else {
                                format!("TIME: {:.1}s", duration_secs)
                            };
                            Frame::NONE
                                .fill(Color32::from_rgb(20, 26, 38))
                                .corner_radius(CornerRadius::same(6))
                                .inner_margin(Margin::symmetric(10, 4))
                                .show(ui, |ui| {
                                    ui.label(RichText::new(time_pill).size(11.0).color(Color32::from_rgb(140, 165, 190)));
                                });
                        });
                    });
                });
            });
        });

    ui.add_space(10.0);

    // Karta Raportu HTML
    Frame::NONE
        .fill(Color32::from_rgb(16, 22, 34))
        .corner_radius(CornerRadius::same(10))
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(32, 45, 70)))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                if let Some(path) = saved_html_path {
                    let html_header = if lang.is_polish() {
                        "📄 Raport HTML został automatycznie wygenerowany:"
                    } else {
                        "📄 HTML report was automatically generated:"
                    };
                    ui.label(
                        RichText::new(html_header)
                            .size(12.0)
                            .color(Color32::from_rgb(180, 200, 220)),
                    );
                    ui.add_space(3.0);
                    ui.label(
                        RichText::new(path)
                            .size(11.5)
                            .monospace()
                            .color(Color32::from_rgb(0, 229, 255)),
                    );

                    ui.add_space(10.0);

                    let open_btn_text = if lang.is_polish() {
                        "🌐 OTWÓRZ RAPORT W PRZEGLĄDARCE"
                    } else {
                        "🌐 OPEN REPORT IN BROWSER"
                    };
                    let btn_open = Button::new(
                        RichText::new(open_btn_text)
                            .size(13.0)
                            .strong()
                            .color(Color32::BLACK),
                    )
                    .fill(Color32::from_rgb(0, 229, 255))
                    .corner_radius(CornerRadius::same(6))
                    .min_size(Vec2::new(300.0, 32.0));

                    if ui.add(btn_open).clicked() {
                        open_file_in_browser(path);
                    }

                    ui.add_space(8.0);

                    // Przycisk kopiowania raportu Discord dla administracji
                    let is_copied_discord = *copied_discord_timer > 0.0;
                    let discord_btn_text = if is_copied_discord {
                        if lang.is_polish() { "✓ SKOPIOWANO RAPORT DLA ADMINISTRACJI!" } else { "✓ COPIED REPORT FOR STAFF!" }
                    } else {
                        if lang.is_polish() { "📋 KOPIUJ RAPORT DLA ADMINISTRACJI (DISCORD)" } else { "📋 COPY REPORT FOR STAFF (DISCORD)" }
                    };
                    let btn_discord = Button::new(
                        RichText::new(discord_btn_text)
                            .size(12.0)
                            .strong()
                            .color(if is_copied_discord { Color32::from_rgb(0, 230, 118) } else { Color32::from_rgb(160, 185, 255) }),
                    )
                    .fill(Color32::from_rgb(22, 28, 44))
                    .stroke(Stroke::new(1.0_f32, if is_copied_discord { Color32::from_rgb(0, 230, 118) } else { Color32::from_rgb(88, 101, 242) }))
                    .corner_radius(CornerRadius::same(6))
                    .min_size(Vec2::new(300.0, 30.0));

                    if ui.add(btn_discord).clicked() {
                        let discord_text = crate::report_export::generate_discord_report(report, duration_secs);
                        ui.ctx().copy_text(discord_text);
                        *copied_discord_timer = 2.0;
                    }

                    ui.add_space(8.0);

                    ui.horizontal(|ui| {
                        ui.centered_and_justified(|ui| {
                            ui.horizontal(|ui| {
                                let copy_path_text = if *copied_timer > 0.0 {
                                    if lang.is_polish() { "✓ SKOPIOWANO" } else { "✓ COPIED" }
                                } else {
                                    if lang.is_polish() { "📋 Kopiuj ścieżkę" } else { "📋 Copy path" }
                                };
                                let btn_copy = Button::new(
                                    RichText::new(copy_path_text)
                                        .size(11.5)
                                        .color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(28, 38, 56))
                                .corner_radius(CornerRadius::same(6))
                                .min_size(Vec2::new(145.0, 28.0));

                                if ui.add(btn_copy).clicked() {
                                    if let Ok(abs) = std::fs::canonicalize(path) {
                                        let mut s = abs.to_string_lossy().to_string();
                                        if let Some(stripped) = s.strip_prefix(r"\\?\") {
                                            s = stripped.to_string();
                                        }
                                        ui.ctx().copy_text(s);
                                    } else {
                                        ui.ctx().copy_text(path.clone());
                                    }
                                    *copied_timer = 2.0;
                                }

                                let rescan_text = if lang.is_polish() {
                                    "🔄 Skanuj ponownie"
                                } else {
                                    "🔄 Scan Again"
                                };
                                let btn_rescan = Button::new(
                                    RichText::new(rescan_text)
                                        .size(11.5)
                                        .color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(28, 38, 56))
                                .corner_radius(CornerRadius::same(6))
                                .min_size(Vec2::new(145.0, 28.0));

                                if ui.add(btn_rescan).clicked() {
                                    should_rescan = true;
                                }
                            });
                        });
                    });
                } else {
                    let fail_msg = if lang.is_polish() {
                        "⚠ Nie udało się wygenerować raportu HTML"
                    } else {
                        "⚠ Failed to generate HTML report"
                    };
                    ui.label(RichText::new(fail_msg).size(12.0).color(Color32::from_rgb(255, 179, 0)));
                }
            });
        });

    should_rescan
}

fn open_file_in_browser(path: &str) {
    let mut target = match std::fs::canonicalize(path) {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => path.to_string(),
    };
    if let Some(stripped) = target.strip_prefix(r"\\?\") {
        target = stripped.to_string();
    }
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", &target])
        .spawn();
}

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

#[allow(dead_code)]
pub fn format_report_text(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("================================================================================\n");
    out.push_str("                         GRIND SCANNER - RAPORT ŚLEDCZY                         \n");
    out.push_str("================================================================================\n");
    out.push_str(&format!("Timestamp:        {}\n", report.timestamp));
    out.push_str(&format!("Elevation (Admin): {}\n", if report.is_admin { "YES" } else { "NO" }));
    if let Some(ref target) = report.target_process {
        out.push_str(&format!("Target Process:   {} (PID: {})\n", target, report.target_pid.unwrap_or(0)));
    }
    out.push_str("--------------------------------------------------------------------------------\n");
    out.push_str(&format!(
        "Detections: {} | Warnings: {} | Info: {}\n",
        report.detections_count(),
        report.warnings_count(),
        report.info_count()
    ));
    out.push_str("================================================================================\n\n");

    for finding in &report.findings {
        out.push_str(&format!("[{}] {} [{}]\n", finding.level, finding.name, finding.category));
        let clean_desc = sanitize_opsec_description(&finding.description);
        out.push_str(&format!("  Details: {}\n", clean_desc));
        for (k, v) in &finding.evidence {
            if !is_sensitive_opsec_evidence(k) {
                out.push_str(&format!("  > {}: {}\n", k, v));
            }
        }
        out.push('\n');
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sensitive_opsec_evidence() {
        assert!(is_sensitive_opsec_evidence("Matched Keyword"));
        assert!(is_sensitive_opsec_evidence("Sygnatura"));
        assert!(is_sensitive_opsec_evidence("Wzorzec"));
        assert!(is_sensitive_opsec_evidence("Wzorzec AOB"));
        assert!(is_sensitive_opsec_evidence("Nazwa reguły"));
        assert!(is_sensitive_opsec_evidence("Wykryte klasy"));
        assert!(is_sensitive_opsec_evidence("Wykryte sygnatury"));

        // Legalne dowody forensics i runtime MUSZĄ być dozwolone:
        assert!(!is_sensitive_opsec_evidence("Cached Executable Path"));
        assert!(!is_sensitive_opsec_evidence("Program Path"));
        assert!(!is_sensitive_opsec_evidence("Last Execution Time"));
        assert!(!is_sensitive_opsec_evidence("Session Scope"));
        assert!(!is_sensitive_opsec_evidence("Run Count"));
        assert!(!is_sensitive_opsec_evidence("Adres pamięci"));
        assert!(!is_sensitive_opsec_evidence("Moduł / Cheat"));
    }

    #[test]
    fn test_sanitize_opsec_description() {
        let dirty = "Wykryto moduł AutoClicker (Wzorzec: 'AutoClicker.class')";
        assert_eq!(sanitize_opsec_description(dirty), "Wykryto moduł AutoClicker");

        let clean = "Wykryto plik wykonywalny cheata na dysku.";
        assert_eq!(sanitize_opsec_description(clean), clean);
    }

    #[test]
    fn test_final_verdict_icons_render_cleanly() {
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |_| {});
        for verdict in &[FinalVerdict::Detected, FinalVerdict::Suspicious, FinalVerdict::Undetected] {
            let icon = verdict.icon();
            assert!(!icon.contains('\u{fe0f}'), "Icons in GUI must not contain variation selectors like \\u{{FE0F}} which break egui rendering");
            ctx.fonts(|f| {
                let job = egui::text::LayoutJob::simple_singleline(
                    format!("{} {}", icon, verdict.title(crate::i18n::Language::Polish)),
                    egui::FontId::proportional(28.0),
                    verdict.color(),
                );
                let galley = f.layout_job(job);
                assert!(galley.size().x > 50.0);
            });
        }
    }
}
