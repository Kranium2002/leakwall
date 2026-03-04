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
    if let Some(home) = dirs::home_dir() {
        let home_cache = home.join(".aegis/cve_cache.json");
        if let Ok(content) = std::fs::read_to_string(&home_cache) {
            if let Ok(entries) = serde_json::from_str::<Vec<CveEntry>>(&content) {
                return Ok(entries);
            }
        }
    }

    // Empty database is acceptable — scan proceeds without CVE data
    Ok(vec![])
}

/// Version comparison using the semver crate, with naive fallback.
fn is_version_before(current: &str, fixed: &str) -> bool {
    let current_clean = current.trim_start_matches('v');
    let fixed_clean = fixed.trim_start_matches('v');
    match (
        semver::Version::parse(current_clean),
        semver::Version::parse(fixed_clean),
    ) {
        (Ok(c), Ok(f)) => c < f,
        _ => naive_version_before(current, fixed),
    }
}

/// Fallback for non-semver version strings.
fn naive_version_before(current: &str, fixed: &str) -> bool {
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
        // Semver path
        assert!(is_version_before("1.0.0", "1.0.1"));
        assert!(is_version_before("1.0.0", "1.1.0"));
        assert!(is_version_before("1.0.0", "2.0.0"));
        assert!(!is_version_before("1.0.1", "1.0.0"));
        assert!(!is_version_before("2.0.0", "1.0.0"));
        assert!(!is_version_before("1.0.0", "1.0.0"));
        // v-prefix handled
        assert!(is_version_before("v1.0.0", "v1.0.1"));
        assert!(!is_version_before("v2.0.0", "v1.0.0"));
    }

    #[test]
    fn test_naive_version_fallback() {
        // Non-semver strings fall back to naive comparison
        assert!(is_version_before("1.0", "1.1"));
        assert!(!is_version_before("2.0", "1.0"));
    }
}
