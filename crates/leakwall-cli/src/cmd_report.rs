use anyhow::{Context, Result};
use colored::Colorize;
use leakwall_report::html::render_html_report;
use leakwall_report::json::{Finding, ReportSummary, ScanReport};
use leakwall_report::sarif::generate_sarif;
use std::path::Path;

/// Run the `leakwall report` command — generate reports from scan data.
pub async fn run_report(lw_dir: &Path, html: bool, open: bool, format: Option<&str>) -> Result<()> {
    // Load latest scan report
    let report = load_latest_report(lw_dir)?;

    match format {
        Some("sarif") => {
            let sarif = generate_sarif(&report.findings).context("SARIF generation failed")?;
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        }
        Some("json") => {
            let json = leakwall_report::json::generate_json_report(&report)
                .context("JSON report generation failed")?;
            println!("{json}");
        }
        _ if html => {
            let report_dir = lw_dir.join("reports");
            std::fs::create_dir_all(&report_dir)?;

            let html_content =
                render_html_report(&report, &[]).context("HTML report generation failed")?;

            let filename = format!("report-{}.html", chrono::Utc::now().format("%Y-%m-%d"));
            let path = report_dir.join(&filename);
            std::fs::write(&path, &html_content)?;

            println!("Generated: {}", path.display().to_string().cyan());

            if open {
                let _ = open_in_browser(&path.display().to_string());
            }
        }
        _ => {
            println!(
                "{}",
                "Usage: leakwall report --html [--open] | --format sarif|json".dimmed()
            );
        }
    }

    Ok(())
}

fn load_latest_report(lw_dir: &Path) -> Result<ScanReport> {
    let report_dir = lw_dir.join("reports");

    if !report_dir.is_dir() {
        return Ok(empty_report());
    }

    // Find most recent scan-*.json file
    let mut entries: Vec<_> = std::fs::read_dir(&report_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name().to_string_lossy().starts_with("scan-")
                && e.file_name().to_string_lossy().ends_with(".json")
        })
        .collect();

    entries.sort_by_key(|e| e.file_name());

    if let Some(latest) = entries.last() {
        let content = std::fs::read_to_string(latest.path()).context("read latest scan report")?;

        // Try to parse as our ScanReport format
        if let Ok(report) = serde_json::from_str::<ScanReport>(&content) {
            return Ok(report);
        }

        // Fallback: try to extract findings from
        // the legacy format
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            return Ok(report_from_legacy(&val));
        }
    }

    Ok(empty_report())
}

fn empty_report() -> ScanReport {
    ScanReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        findings: vec![],
        summary: ReportSummary {
            total_findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        },
    }
}

fn report_from_legacy(val: &serde_json::Value) -> ScanReport {
    let mut findings = Vec::new();

    // Extract from mcp_audits
    if let Some(audits) = val.get("mcp_audits").and_then(|v| v.as_array()) {
        for audit in audits {
            if let Some(local) = audit.get("local_findings").and_then(|v| v.as_array()) {
                for f in local {
                    findings.push(Finding {
                        severity: f
                            .get("severity")
                            .and_then(|s| s.as_str())
                            .unwrap_or("Medium")
                            .to_string(),
                        finding_type: "MCP Finding".to_string(),
                        source: audit
                            .get("identity")
                            .and_then(|i| i.get("name"))
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown")
                            .to_string(),
                        detail: f
                            .get("detail")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                            .to_string(),
                        remediation: None,
                    });
                }
            }
        }
    }

    let (mut crit, mut high, mut med, mut low, mut info) = (0, 0, 0, 0, 0);
    for f in &findings {
        match f.severity.to_lowercase().as_str() {
            "critical" => crit += 1,
            "high" => high += 1,
            "medium" => med += 1,
            "low" => low += 1,
            _ => info += 1,
        }
    }

    ScanReport {
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: val
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string(),
        summary: ReportSummary {
            total_findings: findings.len(),
            critical: crit,
            high,
            medium: med,
            low,
            info,
        },
        findings,
    }
}

fn open_in_browser(path: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(path)
            .spawn()
            .ok();
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(path).spawn().ok();
    }
    #[cfg(target_os = "windows")]
    {
        // Safety: Using .args() with separate arguments avoids shell metacharacter
        // injection. The empty "" is the window title required by `start` when the
        // path contains spaces or special characters.
        std::process::Command::new("cmd")
            .args(["/C", "start", "", path])
            .spawn()
            .ok();
    }
    Ok(())
}
