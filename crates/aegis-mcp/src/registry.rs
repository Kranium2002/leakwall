use crate::{
    AgentAuditResult, AuditFinding, McpError, McpTrustResult, RegistryResults, RiskLevel,
    ServerIdentity, Severity, VulnDetail,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tracing::debug;
use urlencoding::encode;

const AGENTAUDIT_BASE_URL: &str = "https://api.agentaudit.dev/v1";
const MCP_TRUST_BASE_URL: &str = "https://api.mcp-trust.com/v1";
const REGISTRY_TIMEOUT_SECS: u64 = 5;
const CACHE_TTL_HOURS: i64 = 24;

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    pub results: RegistryResults,
    pub fetched_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct RegistryCache {
    pub entries: std::collections::HashMap<String, CacheEntry>,
}

/// Query all external registries for a given server identity.
/// When `refresh` is true, skip cache and force fresh HTTP requests.
pub async fn query_registries(identity: &ServerIdentity, refresh: bool) -> RegistryResults {
    let package_name = identity.package_name.as_deref().unwrap_or(&identity.name);

    // Check cache first (skip if refresh is requested)
    if !refresh {
        if let Some(cached) = load_from_cache(package_name) {
            debug!(package = %package_name, "using cached registry results");
            return cached;
        }
    }

    let timeout = Duration::from_secs(REGISTRY_TIMEOUT_SECS);

    let (aa, mt, cves) = tokio::join!(
        tokio::time::timeout(timeout, query_agentaudit(package_name)),
        tokio::time::timeout(timeout, query_mcp_trust(package_name)),
        crate::cve::lookup_cves(package_name, identity.version.as_deref()),
    );

    let results = RegistryResults {
        agent_audit: aa.ok().and_then(|r| r.ok()),
        mcp_trust: mt.ok().and_then(|r| r.ok()),
        cves: cves.unwrap_or_default(),
    };

    // Save to cache
    save_to_cache(package_name, &results);

    results
}

/// Query agentaudit.dev for trust score and findings.
async fn query_agentaudit(package_name: &str) -> Result<AgentAuditResult, McpError> {
    let encoded_name = encode(package_name);
    let url = format!("{AGENTAUDIT_BASE_URL}/packages/{encoded_name}");
    debug!(url = %url, "querying agentaudit.dev");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(REGISTRY_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| McpError::Registry(format!("HTTP client error: {e}")))?;

    let response = client
        .get(&url)
        .header("User-Agent", "aegis/0.1.0")
        .send()
        .await
        .map_err(|e| McpError::Registry(format!("agentaudit request failed: {e}")))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(McpError::Registry("package not found on agentaudit".into()));
    }

    if !response.status().is_success() {
        return Err(McpError::Registry(format!(
            "agentaudit returned status {}",
            response.status()
        )));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| McpError::Registry(format!("agentaudit parse error: {e}")))?;

    let trust_score = body
        .get("trust_score")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;

    let findings = body
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| {
                    Some(AuditFinding {
                        id: f.get("id")?.as_str()?.to_string(),
                        description: f.get("description")?.as_str()?.to_string(),
                        severity: parse_severity(f.get("severity")?.as_str().unwrap_or("info")),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let asf_ids = body
        .get("asf_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(AgentAuditResult {
        trust_score,
        findings,
        asf_ids,
    })
}

/// Query mcp-trust.com for risk assessment.
async fn query_mcp_trust(package_name: &str) -> Result<McpTrustResult, McpError> {
    let encoded_name = encode(package_name);
    let url = format!("{MCP_TRUST_BASE_URL}/packages/{encoded_name}");
    debug!(url = %url, "querying mcp-trust.com");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(REGISTRY_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| McpError::Registry(format!("HTTP client error: {e}")))?;

    let response = client
        .get(&url)
        .header("User-Agent", "aegis/0.1.0")
        .send()
        .await
        .map_err(|e| McpError::Registry(format!("mcp-trust request failed: {e}")))?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(McpError::Registry("package not found on mcp-trust".into()));
    }

    if !response.status().is_success() {
        return Err(McpError::Registry(format!(
            "mcp-trust returned status {}",
            response.status()
        )));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| McpError::Registry(format!("mcp-trust parse error: {e}")))?;

    let risk_level = match body
        .get("risk_level")
        .and_then(|v| v.as_str())
        .unwrap_or("medium")
    {
        "low" => RiskLevel::Low,
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        _ => RiskLevel::Medium,
    };

    let vulnerabilities = body
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    Some(VulnDetail {
                        id: v.get("id")?.as_str()?.to_string(),
                        description: v.get("description")?.as_str()?.to_string(),
                        severity: parse_severity(v.get("severity")?.as_str().unwrap_or("info")),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let remediation = body
        .get("remediation")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    Ok(McpTrustResult {
        risk_level,
        vulnerabilities,
        remediation,
    })
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn cache_path() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".aegis/registry_cache.json"))
}

fn load_from_cache(package_name: &str) -> Option<RegistryResults> {
    use fs2::FileExt;
    use std::io::Read;

    let path = cache_path()?;
    let mut file = std::fs::OpenOptions::new().read(true).open(&path).ok()?;

    FileExt::lock_shared(&file).ok()?;

    let mut content = String::new();
    file.read_to_string(&mut content).ok()?;
    let cache: RegistryCache = serde_json::from_str(&content).ok()?;

    // Lock is released when `file` is dropped
    let entry = cache.entries.get(package_name)?;
    let age = Utc::now() - entry.fetched_at;
    if age.num_hours() < CACHE_TTL_HOURS {
        Some(entry.results.clone())
    } else {
        None
    }
}

fn save_to_cache(package_name: &str, results: &RegistryResults) {
    use fs2::FileExt;
    use std::io::{Read, Seek, SeekFrom, Write};

    let path = match cache_path() {
        Some(p) => p,
        None => return,
    };

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return,
    };

    if file.lock_exclusive().is_err() {
        return;
    }

    // Read current contents from the locked file handle
    let mut contents = String::new();
    let mut cache: RegistryCache = if file.read_to_string(&mut contents).is_ok() {
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        RegistryCache::default()
    };

    cache.entries.insert(
        package_name.to_string(),
        CacheEntry {
            results: results.clone(),
            fetched_at: Utc::now(),
        },
    );

    if let Ok(json) = serde_json::to_string_pretty(&cache) {
        let _ = file.set_len(0);
        let _ = file.seek(SeekFrom::Start(0));
        let _ = file.write_all(json.as_bytes());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    // Lock is released when `file` is dropped
}
