use serde_json::json;

use crate::json::Finding;
use crate::ReportError;

/// Map LeakWall severity strings to SARIF levels.
fn sarif_level(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// Percent-encode a source string for use as a SARIF artifact URI.
fn encode_uri(source: &str) -> String {
    source
        .replace('\\', "/")
        .replace('%', "%25")
        .replace(' ', "%20")
        .replace('#', "%23")
        .replace('?', "%3F")
}

/// Generate a SARIF 2.1.0 JSON value from a slice of findings.
pub fn generate_sarif(findings: &[Finding]) -> Result<serde_json::Value, ReportError> {
    let results: Vec<serde_json::Value> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            json!({
                "ruleId": format!(
                    "leakwall/{}/{}",
                    f.finding_type, i
                ),
                "level": sarif_level(&f.severity),
                "message": {
                    "text": f.detail
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": encode_uri(&f.source)
                        }
                    }
                }]
            })
        })
        .collect();

    let sarif = json!({
        "$schema":
            "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "leakwall",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri":
                        "https://github.com/Kranium2002/leakwall"
                }
            },
            "results": results
        }]
    });

    Ok(sarif)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Finding;

    fn sample_findings() -> Vec<Finding> {
        vec![
            Finding {
                severity: "Critical".to_string(),
                finding_type: "exposed_secret".to_string(),
                source: ".env".to_string(),
                detail: "AWS secret key exposed".to_string(),
                remediation: Some("Rotate key".to_string()),
            },
            Finding {
                severity: "Medium".to_string(),
                finding_type: "weak_config".to_string(),
                source: "config.toml".to_string(),
                detail: "Permissive CORS".to_string(),
                remediation: None,
            },
            Finding {
                severity: "Low".to_string(),
                finding_type: "info".to_string(),
                source: "scan".to_string(),
                detail: "Informational note".to_string(),
                remediation: None,
            },
        ]
    }

    #[test]
    fn sarif_has_correct_schema_and_version() {
        let sarif = generate_sarif(&sample_findings()).unwrap();
        assert_eq!(
            sarif["$schema"],
            "https://json.schemastore.org/sarif-2.1.0.json"
        );
        assert_eq!(sarif["version"], "2.1.0");
    }

    #[test]
    fn sarif_maps_severity_correctly() {
        let sarif = generate_sarif(&sample_findings()).unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        // Critical -> error
        assert_eq!(results[0]["level"], "error");
        // Medium -> warning
        assert_eq!(results[1]["level"], "warning");
        // Low -> note
        assert_eq!(results[2]["level"], "note");
    }

    #[test]
    fn sarif_tool_driver_name() {
        let sarif = generate_sarif(&[]).unwrap();
        let driver = &sarif["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "leakwall");
    }
}
