use chrono::{DateTime, Utc};
use leakwall_proxy::RequestLog;
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;

/// Session report data.
#[derive(Debug, Serialize)]
pub struct SessionReport {
    pub agent_command: String,
    pub agent_pid: Option<u32>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_secs: u64,
    pub total_requests: usize,
    pub total_bytes: usize,
    pub secrets_detected: Vec<SecretSummary>,
    pub pattern_matches: Vec<PatternSummary>,
}

#[derive(Debug, Serialize)]
pub struct SecretSummary {
    pub name: String,
    pub request_count: usize,
    pub action: String,
}

#[derive(Debug, Serialize)]
pub struct PatternSummary {
    pub pattern: String,
    pub match_count: usize,
    pub request_count: usize,
    pub action: String,
}

/// Build a session report from request logs.
pub fn build_session_report(
    logs: &[RequestLog],
    command: &str,
    pid: Option<u32>,
    start_time: DateTime<Utc>,
) -> SessionReport {
    let end_time = Utc::now();
    let duration = (end_time - start_time).num_seconds().max(0) as u64;

    let total_requests = logs.len();
    let total_bytes: usize = logs.iter().map(|l| l.body_size).sum();

    // Group by action type and aggregate match counts
    let mut action_counts: HashMap<String, (usize, usize)> = HashMap::new();
    for log in logs {
        if log.matches_count > 0 {
            let action_key = match &log.action {
                leakwall_proxy::Action::Warned => "WARNED".to_string(),
                leakwall_proxy::Action::Redacted { .. } => "REDACTED".to_string(),
                leakwall_proxy::Action::Blocked => "BLOCKED".to_string(),
                leakwall_proxy::Action::Passed => "PASSED".to_string(),
            };
            let entry = action_counts.entry(action_key).or_insert((0, 0));
            entry.0 += log.matches_count;
            entry.1 += 1;
        }
    }

    let pattern_matches: Vec<PatternSummary> = action_counts
        .into_iter()
        .map(|(action_key, (match_count, request_count))| {
            let action = if action_key == "REDACTED" {
                format!("REDACTED ({match_count})")
            } else {
                action_key
            };
            PatternSummary {
                pattern: "aggregate".into(),
                match_count,
                request_count,
                action,
            }
        })
        .collect();

    SessionReport {
        agent_command: command.to_string(),
        agent_pid: pid,
        start_time,
        end_time,
        duration_secs: duration,
        total_requests,
        total_bytes,
        secrets_detected: vec![],
        pattern_matches,
    }
}

/// Render session report to terminal.
pub fn print_session_report(report: &SessionReport) {
    println!();
    println!("═══════════════════════════════════════════════════");
    println!(
        "  leakwall session report — {}",
        report.start_time.format("%Y-%m-%d %H:%M:%S")
    );
    println!("═══════════════════════════════════════════════════");
    println!();

    let pid_str = report
        .agent_pid
        .map(|p| format!("PID {p}"))
        .unwrap_or_else(|| "unknown".into());
    println!("Agent: {} ({})", report.agent_command, pid_str);

    let minutes = report.duration_secs / 60;
    let seconds = report.duration_secs % 60;
    println!("Duration: {minutes}m {seconds:02}s");
    println!("Requests intercepted: {}", report.total_requests);

    let mb = report.total_bytes as f64 / (1024.0 * 1024.0);
    println!("Data scanned: {mb:.1} MB");
    println!();

    if report.secrets_detected.is_empty() && report.pattern_matches.is_empty() {
        println!("No secrets detected during session.");
    } else {
        for secret in &report.secrets_detected {
            println!(
                "  🔴 {} — in {} requests — {}",
                secret.name, secret.request_count, secret.action
            );
        }
        for pattern in &report.pattern_matches {
            println!(
                "  🟡 {}: {} matches across {} requests — {}",
                pattern.pattern, pattern.match_count, pattern.request_count, pattern.action
            );
        }
    }

    println!();
}

/// Save session report as JSON.
pub fn save_session_report(
    report: &SessionReport,
    log_dir: &Path,
) -> Result<std::path::PathBuf, std::io::Error> {
    std::fs::create_dir_all(log_dir)?;
    let filename = format!(
        "session-{}.json",
        report.start_time.format("%Y-%m-%d-%H%M%S")
    );
    let path = log_dir.join(&filename);
    let json = serde_json::to_string_pretty(report).map_err(std::io::Error::other)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

/// Scan report for `leakwall scan` command.
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub score: i32,
    pub risk_level: String,
    pub sections: Vec<ScanReportSection>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanReportSection {
    pub title: String,
    pub findings: Vec<ScanReportFinding>,
}

#[derive(Debug, Serialize)]
pub struct ScanReportFinding {
    pub severity: String,
    pub icon: String,
    pub message: String,
}

impl ScanReport {
    /// Calculate score (100 base, deductions per finding severity).
    pub fn calculate_score(critical: usize, high: usize, medium: usize, low: usize) -> i32 {
        let score =
            100 - (critical as i32 * 20) - (high as i32 * 10) - (medium as i32 * 5) - (low as i32);
        score.max(0)
    }

    pub fn risk_level(score: i32) -> &'static str {
        if score >= 80 {
            "LOW RISK"
        } else if score >= 50 {
            "MODERATE RISK"
        } else {
            "HIGH RISK"
        }
    }

    pub fn risk_color(score: i32) -> &'static str {
        if score >= 80 {
            "green"
        } else if score >= 50 {
            "yellow"
        } else {
            "red"
        }
    }
}
