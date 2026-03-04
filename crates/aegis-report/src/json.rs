use serde::{Deserialize, Serialize};

use crate::ReportError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub version: String,
    pub timestamp: String,
    pub findings: Vec<Finding>,
    pub summary: ReportSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub finding_type: String,
    pub source: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Generate a pretty-printed JSON string from a ScanReport.
pub fn generate_json_report(report: &ScanReport) -> Result<String, ReportError> {
    serde_json::to_string_pretty(report).map_err(ReportError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> ScanReport {
        ScanReport {
            version: "0.1.0".to_string(),
            timestamp: "2026-03-02T00:00:00Z".to_string(),
            findings: vec![Finding {
                severity: "High".to_string(),
                finding_type: "exposed_secret".to_string(),
                source: ".env".to_string(),
                detail: "AWS key found".to_string(),
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
    fn json_roundtrip() {
        let report = sample_report();
        let json = generate_json_report(&report).unwrap();
        let parsed: ScanReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(parsed.summary.high, 1);
    }

    #[test]
    fn json_skips_none_remediation() {
        let report = ScanReport {
            version: "0.1.0".to_string(),
            timestamp: "2026-03-02T00:00:00Z".to_string(),
            findings: vec![Finding {
                severity: "Low".to_string(),
                finding_type: "info".to_string(),
                source: "scan".to_string(),
                detail: "informational".to_string(),
                remediation: None,
            }],
            summary: ReportSummary {
                total_findings: 1,
                critical: 0,
                high: 0,
                medium: 0,
                low: 1,
                info: 0,
            },
        };
        let json = generate_json_report(&report).unwrap();
        assert!(!json.contains("remediation"));
    }
}
