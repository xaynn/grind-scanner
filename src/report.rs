use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictLevel {
    Information,
    Warning,
    Detection,
}

impl std::fmt::Display for VerdictLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerdictLevel::Information => write!(f, "INFO"),
            VerdictLevel::Warning => write!(f, "WARNING"),
            VerdictLevel::Detection => write!(f, "DETECTION"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingCategory {
    MinecraftRuntime,
    MemoryInspection,
    WindowsForensics,
    TamperingAndAntiForensics,
    NetworkAndDns,
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::MinecraftRuntime => write!(f, "Minecraft Runtime"),
            FindingCategory::MemoryInspection => write!(f, "Memory Inspection"),
            FindingCategory::WindowsForensics => write!(f, "Windows Forensics"),
            FindingCategory::TamperingAndAntiForensics => write!(f, "Tampering / Anti-Forensics"),
            FindingCategory::NetworkAndDns => write!(f, "Network & DNS"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub name: String,
    pub category: FindingCategory,
    pub level: VerdictLevel,
    pub description: String,
    pub evidence: HashMap<String, String>,
}

impl ScanFinding {
    pub fn new(
        name: impl Into<String>,
        category: FindingCategory,
        level: VerdictLevel,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            category,
            level,
            description: description.into(),
            evidence: HashMap::new(),
        }
    }

    pub fn with_evidence(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.evidence.insert(key.into(), val.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub scanner_name: String,
    pub scanner_version: String,
    pub timestamp: String,
    pub is_admin: bool,
    pub target_process: Option<String>,
    pub target_pid: Option<u32>,
    pub findings: Vec<ScanFinding>,
}

impl ScanReport {
    pub fn new(is_admin: bool) -> Self {
        Self {
            scanner_name: "GrindScanner (Minecraft Forensic Anticheat)".to_string(),
            scanner_version: "1.0.0".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            is_admin,
            target_process: None,
            target_pid: None,
            findings: Vec::new(),
        }
    }

    pub fn add(&mut self, finding: ScanFinding) {
        self.findings.push(finding);
    }

    pub fn detections_count(&self) -> usize {
        self.findings.iter().filter(|f| f.level == VerdictLevel::Detection).count()
    }

    pub fn warnings_count(&self) -> usize {
        self.findings.iter().filter(|f| f.level == VerdictLevel::Warning).count()
    }

    pub fn info_count(&self) -> usize {
        self.findings.iter().filter(|f| f.level == VerdictLevel::Information).count()
    }

    pub fn save_to_json(&self, path: &str) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn print_console_summary(&self) {
        println!("\n================================================================================");
        println!("                         GRIND SCANNER REPORT SUMMARY                           ");
        println!("================================================================================");
        println!("Timestamp:        {}", self.timestamp);
        println!("Elevation (Admin): {}", if self.is_admin { "YES (High Privileges)" } else { "NO (Standard User - some forensics limited)" });
        if let Some(ref proc) = self.target_process {
            println!("Target Process:   {} (PID: {:?})", proc, self.target_pid.unwrap_or(0));
        } else {
            println!("Target Process:   None (Minecraft not running at scan time)");
        }
        println!("--------------------------------------------------------------------------------");
        println!(
            "Detections: \x1b[91m{}\x1b[0m | Warnings: \x1b[93m{}\x1b[0m | Info: \x1b[96m{}\x1b[0m",
            self.detections_count(),
            self.warnings_count(),
            self.info_count()
        );
        println!("================================================================================\n");

        if self.findings.is_empty() {
            println!("  \x1b[92m[✓] No anomalies, suspicious traces, or injection artifacts detected.\x1b[0m\n");
            return;
        }

        // Print Detections first
        for finding in self.findings.iter().filter(|f| f.level == VerdictLevel::Detection) {
            println!("  \x1b[91m[DETECTION]\x1b[0m \x1b[1m{}\x1b[0m [{}]", finding.name, finding.category);
            println!("    Reason:   {}", finding.description);
            for (k, v) in &finding.evidence {
                println!("    > {}: {}", k, v);
            }
            println!();
        }

        // Print Warnings
        for finding in self.findings.iter().filter(|f| f.level == VerdictLevel::Warning) {
            println!("  \x1b[93m[WARNING]\x1b[0m \x1b[1m{}\x1b[0m [{}]", finding.name, finding.category);
            println!("    Reason:   {}", finding.description);
            for (k, v) in &finding.evidence {
                println!("    > {}: {}", k, v);
            }
            println!();
        }

        // Print Information
        for finding in self.findings.iter().filter(|f| f.level == VerdictLevel::Information) {
            println!("  \x1b[96m[INFO]\x1b[0m {} [{}]", finding.name, finding.category);
            println!("    Details:  {}", finding.description);
            for (k, v) in &finding.evidence {
                println!("    > {}: {}", k, v);
            }
            println!();
        }
    }
}
