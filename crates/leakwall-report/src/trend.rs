use serde::{Deserialize, Serialize};

use crate::json::ScanReport;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendData {
    pub direction: TrendDirection,
    pub current_score: u32,
    pub previous_score: Option<u32>,
    pub sessions_analyzed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TrendDirection {
    Improving,
    Stable,
    Worsening,
    Insufficient,
}

/// Compute a security score from a report's summary.
/// Score = 100 - weighted findings (critical=25, high=10,
/// medium=5, low=1). Minimum 0.
fn compute_score(report: &ScanReport) -> u32 {
    let penalty = report.summary.critical * 25
        + report.summary.high * 10
        + report.summary.medium * 5
        + report.summary.low;
    let penalty_u32 = u32::try_from(penalty).unwrap_or(u32::MAX);
    100u32.saturating_sub(penalty_u32)
}

/// Compute trend data from chronologically ordered reports.
/// Need at least 2 reports for a meaningful comparison.
pub fn compute_trends(reports: &[ScanReport]) -> TrendData {
    let sessions_analyzed = reports.len();

    if sessions_analyzed < 2 {
        let current_score = reports.last().map(compute_score).unwrap_or(100);
        return TrendData {
            direction: TrendDirection::Insufficient,
            current_score,
            previous_score: None,
            sessions_analyzed,
        };
    }

    let current_score = compute_score(&reports[sessions_analyzed - 1]);
    let previous_score = compute_score(&reports[sessions_analyzed - 2]);

    let direction = if current_score > previous_score {
        TrendDirection::Improving
    } else if current_score < previous_score {
        TrendDirection::Worsening
    } else {
        TrendDirection::Stable
    };

    TrendData {
        direction,
        current_score,
        previous_score: Some(previous_score),
        sessions_analyzed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{ReportSummary, ScanReport};

    fn make_report(critical: usize, high: usize, medium: usize, low: usize) -> ScanReport {
        ScanReport {
            version: "0.1.0".to_string(),
            timestamp: "2026-03-02T00:00:00Z".to_string(),
            findings: Vec::new(),
            summary: ReportSummary {
                total_findings: critical + high + medium + low,
                critical,
                high,
                medium,
                low,
                info: 0,
            },
        }
    }

    #[test]
    fn fewer_findings_is_improving() {
        let reports = vec![
            make_report(2, 3, 1, 0), // score: 15
            make_report(0, 1, 0, 0), // score: 90
        ];
        let trend = compute_trends(&reports);
        assert_eq!(trend.direction, TrendDirection::Improving);
        assert_eq!(trend.current_score, 90);
        assert_eq!(trend.previous_score, Some(15));
    }

    #[test]
    fn more_findings_is_worsening() {
        let reports = vec![
            make_report(0, 0, 0, 0), // score: 100
            make_report(1, 2, 0, 0), // score: 55
        ];
        let trend = compute_trends(&reports);
        assert_eq!(trend.direction, TrendDirection::Worsening);
    }

    #[test]
    fn same_findings_is_stable() {
        let reports = vec![make_report(0, 1, 0, 0), make_report(0, 1, 0, 0)];
        let trend = compute_trends(&reports);
        assert_eq!(trend.direction, TrendDirection::Stable);
    }

    #[test]
    fn single_report_is_insufficient() {
        let reports = vec![make_report(0, 0, 0, 0)];
        let trend = compute_trends(&reports);
        assert_eq!(trend.direction, TrendDirection::Insufficient);
        assert_eq!(trend.current_score, 100);
        assert!(trend.previous_score.is_none());
    }

    #[test]
    fn empty_reports_is_insufficient() {
        let trend = compute_trends(&[]);
        assert_eq!(trend.direction, TrendDirection::Insufficient);
        assert_eq!(trend.sessions_analyzed, 0);
    }

    #[test]
    fn score_floors_at_zero() {
        let report = make_report(5, 0, 0, 0);
        assert_eq!(compute_score(&report), 0);
    }
}
