use crate::KnownCve;
use serde::Deserialize;
use tracing::debug;

#[derive(Debug, Deserialize)]
struct CveEntry {
    pub id: String,
    pub cvss: f32,
    pub affected_package: String,
    pub affected_versions: String,
    pub fixed_version: Option<String>,
    pub description: String,
}

/// Look up known CVEs for a package from the bundled database.
pub async fn lookup_cves(
    package_name: &str,
    version: Option<&str>,
) -> Result<Vec<KnownCve>, crate::McpError> {
    let entries = load_cve_database()?;

    let matches: Vec<KnownCve> = entries
        .into_iter()
        .filter(|e| e.affected_package.to_lowercase() == package_name.to_lowercase())
        .filter(|e| {
            // If we have a version, check if it's in the affected range
            // For now, simple string contains check
            if let Some(ver) = version {
                e.affected_versions.contains(ver)
                    || e.affected_versions == "*"
                    || e.fixed_version
                        .as_ref()
                        .is_some_and(|fv| is_version_before(ver, fv))
            } else {
                true // No version info, show all CVEs
            }
        })
        .map(|e| KnownCve {
            id: e.id,
            cvss: e.cvss,
            affected_versions: e.affected_versions,
            fixed_version: e.fixed_version,
            description: e.description,
        })
        .collect();

    debug!(
        package = %package_name,
        count = matches.len(),
        "CVE lookup complete"
    );
    Ok(matches)
}

/// Load the bundled CVE database from data/cve_cache.json.
fn load_cve_database() -> Result<Vec<CveEntry>, crate::McpError> {
    // Try to load from the bundled data file
    let data_paths = [
        // Relative to binary
        std::path::PathBuf::from("data/cve_cache.json"),
        // Relative to workspace root
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../data/cve_cache.json"
        )),
    ];

    for path in &data_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            match serde_json::from_str::<Vec<CveEntry>>(&content) {
                Ok(entries) => return Ok(entries),
                Err(_) => continue,
            }
        }
    }

    // Also try ~/.aegis/cve_cache.json
    let home_cache = dirs::home_dir()
        .unwrap_or_default()
        .join(".aegis/cve_cache.json");
    if let Ok(content) = std::fs::read_to_string(&home_cache) {
        if let Ok(entries) = serde_json::from_str::<Vec<CveEntry>>(&content) {
            return Ok(entries);
        }
    }

    // Empty database is acceptable — scan proceeds without CVE data
    Ok(vec![])
}

/// Simple version comparison (naive: compares as strings).
fn is_version_before(current: &str, fixed: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.')
            .filter_map(|s| s.trim_start_matches('v').parse().ok())
            .collect()
    };

    let current_parts = parse(current);
    let fixed_parts = parse(fixed);

    for (c, f) in current_parts.iter().zip(fixed_parts.iter()) {
        match c.cmp(f) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }

    current_parts.len() < fixed_parts.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(is_version_before("1.0.0", "1.0.1"));
        assert!(is_version_before("1.0.0", "1.1.0"));
        assert!(is_version_before("1.0.0", "2.0.0"));
        assert!(!is_version_before("1.0.1", "1.0.0"));
        assert!(!is_version_before("2.0.0", "1.0.0"));
        assert!(!is_version_before("1.0.0", "1.0.0"));
    }
}
