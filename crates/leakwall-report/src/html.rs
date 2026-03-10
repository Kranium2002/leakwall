use serde::Serialize;
use tera::{Context, Tera};

use crate::json::ScanReport;
use crate::ReportError;

const TEMPLATE_HTML: &str = include_str!("../templates/report.html");
const TEMPLATE_CSS: &str = include_str!("../templates/styles.css");

/// Summary of a proxy session for HTML reporting.
#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub start_time: String,
    pub duration_secs: u64,
    pub requests_intercepted: usize,
    pub secrets_detected: usize,
    pub action_taken: String,
}

/// Render a self-contained HTML report from scan results
/// and session summaries.
pub fn render_html_report(
    report: &ScanReport,
    sessions: &[SessionSummary],
) -> Result<String, ReportError> {
    let mut tera = Tera::default();
    tera.add_raw_template("report.html", TEMPLATE_HTML)
        .map_err(|e| ReportError::Template(e.to_string()))?;

    let score = compute_display_score(report);
    let score_class = match score {
        80..=100 => "score-good",
        50..=79 => "score-warn",
        _ => "score-bad",
    };

    let mut ctx = Context::new();
    ctx.insert("css", TEMPLATE_CSS);
    ctx.insert("version", &report.version);
    ctx.insert("generated_at", &report.timestamp);
    ctx.insert("score", &score);
    ctx.insert("score_class", score_class);
    ctx.insert("summary", &report.summary);
    ctx.insert("findings", &report.findings);
    ctx.insert("sessions", &sessions);

    // Build severity-ordered findings for the table
    let mut sorted_findings = report.findings.clone();
    sorted_findings.sort_by(|a, b| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)));
    ctx.insert("sorted_findings", &sorted_findings);

    tera.render("report.html", &ctx)
        .map_err(|e| ReportError::Template(e.to_string()))
}

/// Numeric rank for sorting (lower = more severe).
fn severity_rank(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

/// Compute a display score: 100 minus weighted findings.
fn compute_display_score(report: &ScanReport) -> u32 {
    let penalty = report.summary.critical * 25
        + report.summary.high * 10
        + report.summary.medium * 5
        + report.summary.low;
    let penalty_u32 = u32::try_from(penalty).unwrap_or(u32::MAX);
    100u32.saturating_sub(penalty_u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{Finding, ReportSummary, ScanReport};

    fn sample_report() -> ScanReport {
        ScanReport {
            version: "0.1.0".to_string(),
            timestamp: "2026-03-02T12:00:00Z".to_string(),
            findings: vec![Finding {
                severity: "High".to_string(),
                finding_type: "exposed_secret".to_string(),
                source: ".env".to_string(),
                detail: "AWS key found in .env".to_string(),
                remediation: Some("Rotate the key".to_string()),
            }],
            summary: ReportSummary {
                total_findings: 1,
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                info: 0,
            },
        }
    }

    #[test]
    fn html_report_renders_successfully() {
        let report = sample_report();
        let sessions = vec![SessionSummary {
            session_id: "abc-123".to_string(),
            start_time: "2026-03-02T12:00:00Z".to_string(),
            duration_secs: 120,
            requests_intercepted: 5,
            secrets_detected: 1,
            action_taken: "redact".to_string(),
        }];
        let html = render_html_report(&report, &sessions).unwrap();
        assert!(html.contains("LeakWall Security Report"));
        assert!(html.contains("AWS key found"));
        assert!(html.contains("abc-123"));
    }

    #[test]
    fn html_report_empty_findings() {
        let report = ScanReport {
            version: "0.1.0".to_string(),
            timestamp: "2026-03-02T12:00:00Z".to_string(),
            findings: vec![],
            summary: ReportSummary {
                total_findings: 0,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
            },
        };
        let html = render_html_report(&report, &[]).unwrap();
        assert!(html.contains("score-good"));
    }
}
