use crate::{
    AgentAuditRecommendation, AgentAuditResult, AuditFinding, McpError, RegistryResults,
    ServerIdentity, Severity, SeverityBreakdown,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use tracing::debug;
use urlencoding::encode;

const AGENTAUDIT_BASE_URL: &str = "https://agentaudit.dev/api";
const REGISTRY_TIMEOUT_SECS: u64 = 5;
const CACHE_TTL_HOURS: i64 = 24;

/// Returns the AgentAudit base URL, checking `LEAKWALL_AGENTAUDIT_URL` env var first.
fn agentaudit_base_url() -> String {
    std::env::var("LEAKWALL_AGENTAUDIT_URL").unwrap_or_else(|_| AGENTAUDIT_BASE_URL.to_string())
}

/// Build a reqwest client with standard LeakWall settings.
fn build_client() -> Result<reqwest::Client, McpError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(REGISTRY_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| McpError::Registry(format!("HTTP client error: {e}")))
}

// ---------------------------------------------------------------------------
// Slug resolution
// ---------------------------------------------------------------------------

/// Quick check whether a slug exists on AgentAudit.
async fn try_slug(slug: &str) -> bool {
    let base = agentaudit_base_url();
    let url = format!("{base}/check?package={}", encode(slug));
    debug!(url = %url, "trying slug");

    let client = match build_client() {
        Ok(c) => c,
        Err(_) => return false,
    };

    let resp = match client
        .get(&url)
        .header("User-Agent", "leakwall/0.1.0")
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return false,
    };

    if !resp.status().is_success() {
        return false;
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(_) => return false,
    };

    body.get("exists")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Strip npm scope: `@scope/name` -> `name`. Returns `None` if there is no scope.
fn strip_npm_scope(name: &str) -> Option<&str> {
    if name.starts_with('@') {
        name.split_once('/').map(|(_, rest)| rest)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Package catalog (for slug resolution tier 4)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct PackageCatalog {
    pub entries: Vec<PackageCatalogEntry>,
    pub fetched_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackageCatalogEntry {
    pub slug: String,
    pub source_url: Option<String>,
}

/// Catalog cache path: `~/.leakwall/package_catalog.json`.
fn catalog_path() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".leakwall/package_catalog.json"))
}

/// Load catalog from disk if fresh (<24h), otherwise fetch from API and cache.
async fn load_or_fetch_catalog() -> Result<Vec<PackageCatalogEntry>, McpError> {
    use std::io::Read as _;

    // Try loading from disk first
    if let Some(path) = catalog_path() {
        if let Ok(mut file) = std::fs::File::open(&path) {
            let mut content = String::new();
            if file.read_to_string(&mut content).is_ok() {
                if let Ok(catalog) = serde_json::from_str::<PackageCatalog>(&content) {
                    let age = Utc::now() - catalog.fetched_at;
                    if age.num_hours() < CACHE_TTL_HOURS {
                        debug!(
                            "using cached package catalog ({} entries)",
                            catalog.entries.len()
                        );
                        return Ok(catalog.entries);
                    }
                }
            }
        }
    }

    // Fetch from API
    fetch_catalog_from_api().await
}

/// Fetch the catalog from the API and write it to disk.
async fn fetch_catalog_from_api() -> Result<Vec<PackageCatalogEntry>, McpError> {
    let base = agentaudit_base_url();
    let url = format!("{base}/packages");
    debug!(url = %url, "fetching package catalog");

    let client = build_client()?;
    let resp = client
        .get(&url)
        .header("User-Agent", "leakwall/0.1.0")
        .send()
        .await
        .map_err(|e| McpError::Registry(format!("catalog fetch failed: {e}")))?;

    if !resp.status().is_success() {
        return Err(McpError::Registry(format!(
            "catalog fetch returned status {}",
            resp.status()
        )));
    }

    // The API returns an array of objects — we extract slug + source_url.
    let raw: Vec<serde_json::Value> = resp
        .json()
        .await
        .map_err(|e| McpError::Registry(format!("catalog parse error: {e}")))?;

    let entries: Vec<PackageCatalogEntry> = raw
        .iter()
        .filter_map(|v| {
            let slug = v.get("slug")?.as_str()?.to_string();
            let source_url = v
                .get("source_url")
                .and_then(|u| u.as_str())
                .map(String::from);
            Some(PackageCatalogEntry { slug, source_url })
        })
        .collect();

    // Write to disk
    if let Some(path) = catalog_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let catalog = PackageCatalog {
            entries: entries.clone(),
            fetched_at: Utc::now(),
        };
        if let Ok(json) = serde_json::to_string_pretty(&catalog) {
            let _ = std::fs::write(&path, json.as_bytes());
        }
    }

    Ok(entries)
}

/// Search the catalog for a matching slug by `source_url` containing the package name.
/// Also tries matching by npm org name (e.g., `@modelcontextprotocol/server-x` → search
/// for "modelcontextprotocol" in source URLs) to handle monorepo packages.
fn search_catalog(catalog: &[PackageCatalogEntry], package_name: &str) -> Option<String> {
    // Direct match: source_url contains the package name
    if let Some(entry) = catalog.iter().find(|entry| {
        entry
            .source_url
            .as_deref()
            .is_some_and(|url| url.contains(package_name))
    }) {
        return Some(entry.slug.clone());
    }

    // Try npm org name match for scoped packages (e.g., @org/pkg → search for "/org/")
    // Uses path-segment matching to avoid false positives (e.g., "anthropic" in "anthropics")
    if let Some(org) = extract_npm_org(package_name) {
        let segment = format!("/{org}/");
        if let Some(entry) = catalog.iter().find(|entry| {
            entry
                .source_url
                .as_deref()
                .is_some_and(|url| url.contains(&segment))
        }) {
            return Some(entry.slug.clone());
        }
    }

    None
}

/// Extract npm org name: `@modelcontextprotocol/server-x` → `modelcontextprotocol`.
fn extract_npm_org(name: &str) -> Option<&str> {
    let without_at = name.strip_prefix('@')?;
    let (org, _) = without_at.split_once('/')?;
    Some(org)
}

/// Public helper — force-fetches the catalog and returns entry count.
pub async fn fetch_and_cache_catalog() -> Result<usize, McpError> {
    let entries = fetch_catalog_from_api().await?;
    Ok(entries.len())
}

/// Well-known npm scope → AgentAudit slug mappings for monorepo packages where
/// the npm org doesn't match the GitHub org (e.g., `@anthropic/mcp-*` packages
/// are published from `modelcontextprotocol/servers`).
const KNOWN_SCOPE_SLUGS: &[(&str, &str)] = &[
    ("@anthropic/", "servers"),
    ("@modelcontextprotocol/", "servers"),
];

/// 5-tier slug resolution:
/// 1. Direct: try `package_name` as slug
/// 2. Config name: try `identity.name`
/// 3. Strip npm scope: `@scope/name` -> `name`
/// 4. Known scope mappings (e.g., `@anthropic/*` → `servers`)
/// 5. Catalog search: match by `source_url`
async fn resolve_slug(identity: &ServerIdentity) -> Option<String> {
    let package_name = identity.package_name.as_deref().unwrap_or(&identity.name);

    // Tier 1: direct match on package_name
    debug!(slug = %package_name, "tier 1: trying package name");
    if try_slug(package_name).await {
        return Some(package_name.to_string());
    }

    // Tier 2: config name (only if different from package_name)
    if identity.package_name.is_some() && identity.name != package_name {
        debug!(slug = %identity.name, "tier 2: trying config name");
        if try_slug(&identity.name).await {
            return Some(identity.name.clone());
        }
    }

    // Tier 3: strip npm scope
    if let Some(stripped) = strip_npm_scope(package_name) {
        debug!(slug = %stripped, "tier 3: trying stripped scope");
        if try_slug(stripped).await {
            return Some(stripped.to_string());
        }
    }

    // Tier 4: known scope mappings
    for (scope, slug) in KNOWN_SCOPE_SLUGS {
        if package_name.starts_with(scope) {
            debug!(slug = %slug, scope = %scope, "tier 4: known scope mapping");
            if try_slug(slug).await {
                return Some((*slug).to_string());
            }
        }
    }

    // Tier 5: catalog search (try package_name, then config name)
    debug!("tier 5: searching package catalog");
    if let Ok(catalog) = load_or_fetch_catalog().await {
        if let Some(slug) = search_catalog(&catalog, package_name) {
            debug!(slug = %slug, "tier 5: found slug via catalog (package_name)");
            return Some(slug);
        }
        // Also try config name if different
        if identity.name != package_name {
            if let Some(slug) = search_catalog(&catalog, &identity.name) {
                debug!(slug = %slug, "tier 5: found slug via catalog (config name)");
                return Some(slug);
            }
        }
    }

    debug!(package = %package_name, "no slug resolved");
    None
}

// ---------------------------------------------------------------------------
// AgentAudit queries
// ---------------------------------------------------------------------------

/// Query AgentAudit for trust score and findings for a resolved slug.
async fn query_agentaudit(slug: &str) -> Result<AgentAuditResult, McpError> {
    let base = agentaudit_base_url();
    let encoded = encode(slug);

    // Step 1: GET /api/check?package={slug}
    let check_url = format!("{base}/check?package={encoded}");
    debug!(url = %check_url, "querying agentaudit check");

    let client = build_client()?;

    let check_resp = client
        .get(&check_url)
        .header("User-Agent", "leakwall/0.1.0")
        .send()
        .await
        .map_err(|e| McpError::Registry(format!("agentaudit check request failed: {e}")))?;

    if !check_resp.status().is_success() {
        return Err(McpError::Registry(format!(
            "agentaudit check returned status {}",
            check_resp.status()
        )));
    }

    let check: serde_json::Value = check_resp
        .json()
        .await
        .map_err(|e| McpError::Registry(format!("agentaudit check parse error: {e}")))?;

    let exists = check
        .get("exists")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !exists {
        return Err(McpError::Registry("package not found on agentaudit".into()));
    }

    // Parse check response fields
    let trust_score = check
        .get("trust_score")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u8;

    let recommendation = check
        .get("recommendation")
        .and_then(|v| v.as_str())
        .map(parse_recommendation)
        .unwrap_or(AgentAuditRecommendation::NotAudited);

    let total_findings = check
        .get("total_findings")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    // Severity counts are flat fields at the top level (not nested)
    let severity_breakdown = SeverityBreakdown {
        critical: check.get("critical").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        high: check.get("high").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        medium: check.get("medium").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        low: check.get("low").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
    };

    let audit_level = check
        .get("audit_level")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let last_audited = check
        .get("last_audited")
        .and_then(|v| v.as_str())
        .map(String::from);

    let url = check.get("url").and_then(|v| v.as_str()).map(String::from);

    // Step 2: GET /api/findings?package={slug}
    let findings_url = format!("{base}/findings?package={encoded}");
    debug!(url = %findings_url, "querying agentaudit findings");

    let findings = match client
        .get(&findings_url)
        .header("User-Agent", "leakwall/0.1.0")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let body: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| McpError::Registry(format!("findings parse error: {e}")))?;

            body.get("findings")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|f| {
                            let id = f.get("id").and_then(|v| {
                                v.as_str()
                                    .map(String::from)
                                    .or_else(|| v.as_u64().map(|n| n.to_string()))
                            })?;
                            Some(AuditFinding {
                                id,
                                title: f
                                    .get("title")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                description: f.get("description")?.as_str()?.to_string(),
                                severity: parse_severity(
                                    f.get("severity").and_then(|v| v.as_str()).unwrap_or("info"),
                                ),
                                confidence: f
                                    .get("confidence")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_string(),
                                asf_id: f.get("asf_id").and_then(|v| v.as_str()).map(String::from),
                                file_path: f
                                    .get("file_path")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                line_number: f
                                    .get("line_number")
                                    .and_then(|v| v.as_u64())
                                    .map(|n| n as u32),
                                remediation: f
                                    .get("remediation")
                                    .and_then(|v| v.as_str())
                                    .map(String::from),
                                by_design: f
                                    .get("by_design")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default()
        }
        Ok(resp) => {
            debug!(status = %resp.status(), "findings request returned non-success");
            vec![]
        }
        Err(e) => {
            debug!(error = %e, "findings request failed, continuing without findings");
            vec![]
        }
    };

    Ok(AgentAuditResult {
        trust_score,
        recommendation,
        total_findings,
        severity_breakdown,
        findings,
        audit_level,
        last_audited,
        url,
    })
}

fn parse_recommendation(s: &str) -> AgentAuditRecommendation {
    match s.to_lowercase().as_str() {
        "safe" => AgentAuditRecommendation::Safe,
        "caution" => AgentAuditRecommendation::Caution,
        "unsafe" => AgentAuditRecommendation::Unsafe,
        _ => AgentAuditRecommendation::NotAudited,
    }
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

// ---------------------------------------------------------------------------
// Registry cache
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    pub results: RegistryResults,
    pub fetched_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct RegistryCache {
    pub entries: std::collections::HashMap<String, CacheEntry>,
}

fn cache_path() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".leakwall/registry_cache.json"))
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

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

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

    // Resolve slug before querying AgentAudit
    let slug = resolve_slug(identity).await;

    let agent_audit_fut = async {
        match slug {
            Some(ref s) => tokio::time::timeout(timeout, query_agentaudit(s))
                .await
                .ok()
                .and_then(|r| r.ok()),
            None => None,
        }
    };

    let (aa, cves) = tokio::join!(
        agent_audit_fut,
        crate::cve::lookup_cves(package_name, identity.version.as_deref()),
    );

    let results = RegistryResults {
        agent_audit: aa,
        cves: cves.unwrap_or_default(),
    };

    // Save to cache
    save_to_cache(package_name, &results);

    results
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Serialize async tests that mutate `LEAKWALL_AGENTAUDIT_URL` so parallel threads
    /// don't race on the process-wide env var.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn test_check_existing_package() {
        let _guard = ENV_LOCK.lock();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/check"))
            .and(query_param("package", "mcp-remote"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "exists": true,
                "package_name": "mcp-remote",
                "trust_score": 70,
                "recommendation": "Caution",
                "total_findings": 3,
                "critical": 0,
                "high": 0,
                "medium": 2,
                "low": 1,
                "audit_level": "full",
                "last_audited": "2025-03-31",
                "url": "https://agentaudit.dev/audits/mcp-remote"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/findings"))
            .and(query_param("package", "mcp-remote"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "package": "mcp-remote",
                "findings": []
            })))
            .mount(&mock_server)
            .await;

        // Override base URL via env var
        std::env::set_var(
            "LEAKWALL_AGENTAUDIT_URL",
            format!("{}/api", mock_server.uri()),
        );

        let result = query_agentaudit("mcp-remote").await;

        // Clean up env var
        std::env::remove_var("LEAKWALL_AGENTAUDIT_URL");

        let result = result.expect("query should succeed");
        assert_eq!(result.trust_score, 70);
        assert_eq!(result.recommendation, AgentAuditRecommendation::Caution);
        assert_eq!(result.total_findings, 3);
        assert_eq!(result.severity_breakdown.critical, 0);
        assert_eq!(result.severity_breakdown.medium, 2);
        assert_eq!(result.severity_breakdown.low, 1);
        assert_eq!(result.audit_level, "full");
        assert_eq!(result.last_audited.as_deref(), Some("2025-03-31"));
        assert_eq!(
            result.url.as_deref(),
            Some("https://agentaudit.dev/audits/mcp-remote")
        );
    }

    #[tokio::test]
    async fn test_check_nonexistent_package() {
        let _guard = ENV_LOCK.lock();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/check"))
            .and(query_param("package", "nonexistent-pkg"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "exists": false,
                "package": "nonexistent-pkg"
            })))
            .mount(&mock_server)
            .await;

        std::env::set_var(
            "LEAKWALL_AGENTAUDIT_URL",
            format!("{}/api", mock_server.uri()),
        );

        let result = query_agentaudit("nonexistent-pkg").await;

        std::env::remove_var("LEAKWALL_AGENTAUDIT_URL");

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "error should mention not found: {err}"
        );
    }

    #[tokio::test]
    async fn test_findings_parsing() {
        let _guard = ENV_LOCK.lock();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/check"))
            .and(query_param("package", "test-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "exists": true,
                "package_name": "test-server",
                "trust_score": 85,
                "recommendation": "Safe",
                "total_findings": 1,
                "critical": 0,
                "high": 0,
                "medium": 1,
                "low": 0,
                "audit_level": "full",
                "last_audited": "2025-03-31",
                "url": "https://agentaudit.dev/audits/test-server"
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/findings"))
            .and(query_param("package", "test-server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "package": "test-server",
                "findings": [{
                    "id": "F001",
                    "title": "Insecure Default",
                    "description": "Server uses insecure default configuration",
                    "severity": "medium",
                    "confidence": "high",
                    "asf_id": "ASF-001",
                    "file_path": "src/lib.rs",
                    "line_number": 42,
                    "remediation": "Update configuration",
                    "by_design": false
                }]
            })))
            .mount(&mock_server)
            .await;

        std::env::set_var(
            "LEAKWALL_AGENTAUDIT_URL",
            format!("{}/api", mock_server.uri()),
        );

        let result = query_agentaudit("test-server").await;

        std::env::remove_var("LEAKWALL_AGENTAUDIT_URL");

        let result = result.expect("query should succeed");
        assert_eq!(result.trust_score, 85);
        assert_eq!(result.recommendation, AgentAuditRecommendation::Safe);
        assert_eq!(result.findings.len(), 1);

        let finding = &result.findings[0];
        assert_eq!(finding.id, "F001");
        assert_eq!(finding.title, "Insecure Default");
        assert_eq!(
            finding.description,
            "Server uses insecure default configuration"
        );
        assert_eq!(finding.severity, Severity::Medium);
        assert_eq!(finding.confidence, "high");
        assert_eq!(finding.asf_id.as_deref(), Some("ASF-001"));
        assert_eq!(finding.file_path.as_deref(), Some("src/lib.rs"));
        assert_eq!(finding.line_number, Some(42));
        assert_eq!(finding.remediation.as_deref(), Some("Update configuration"));
        assert!(!finding.by_design);
    }

    #[test]
    fn test_strip_npm_scope() {
        assert_eq!(
            strip_npm_scope("@modelcontextprotocol/server-git"),
            Some("server-git")
        );
        assert_eq!(strip_npm_scope("@scope/name"), Some("name"));
        assert_eq!(strip_npm_scope("no-scope"), None);
        assert_eq!(strip_npm_scope("@empty/"), Some(""));
        assert_eq!(strip_npm_scope("plain-package"), None);
    }

    #[test]
    fn test_recommendation_mapping() {
        assert_eq!(parse_recommendation("Safe"), AgentAuditRecommendation::Safe);
        assert_eq!(parse_recommendation("safe"), AgentAuditRecommendation::Safe);
        assert_eq!(
            parse_recommendation("Caution"),
            AgentAuditRecommendation::Caution
        );
        assert_eq!(
            parse_recommendation("caution"),
            AgentAuditRecommendation::Caution
        );
        assert_eq!(
            parse_recommendation("Unsafe"),
            AgentAuditRecommendation::Unsafe
        );
        assert_eq!(
            parse_recommendation("unsafe"),
            AgentAuditRecommendation::Unsafe
        );
        assert_eq!(
            parse_recommendation("unknown"),
            AgentAuditRecommendation::NotAudited
        );
        assert_eq!(
            parse_recommendation(""),
            AgentAuditRecommendation::NotAudited
        );
    }

    #[test]
    fn test_parse_severity() {
        assert_eq!(parse_severity("critical"), Severity::Critical);
        assert_eq!(parse_severity("Critical"), Severity::Critical);
        assert_eq!(parse_severity("high"), Severity::High);
        assert_eq!(parse_severity("medium"), Severity::Medium);
        assert_eq!(parse_severity("low"), Severity::Low);
        assert_eq!(parse_severity("info"), Severity::Info);
        assert_eq!(parse_severity("other"), Severity::Info);
    }

    #[test]
    fn test_search_catalog() {
        let catalog = vec![
            PackageCatalogEntry {
                slug: "mcp-remote".to_string(),
                source_url: Some("https://github.com/geelen/mcp-remote".to_string()),
            },
            PackageCatalogEntry {
                slug: "servers".to_string(),
                source_url: Some("https://github.com/modelcontextprotocol/servers".to_string()),
            },
            PackageCatalogEntry {
                slug: "no-url".to_string(),
                source_url: None,
            },
        ];

        // Direct match on source_url
        assert_eq!(
            search_catalog(&catalog, "mcp-remote"),
            Some("mcp-remote".to_string())
        );
        // Org-name match: scoped npm package → matches /org/ path segment in source_url
        assert_eq!(
            search_catalog(&catalog, "@modelcontextprotocol/server-brave-search"),
            Some("servers".to_string())
        );
        // Must NOT match "anthropics" when org is "anthropic" (path-segment safety)
        assert_eq!(
            search_catalog(&catalog, "@anthropic/mcp-server-brave-search"),
            None
        );
        assert_eq!(search_catalog(&catalog, "nonexistent"), None);
    }

    #[test]
    fn test_extract_npm_org() {
        assert_eq!(
            extract_npm_org("@modelcontextprotocol/server-brave-search"),
            Some("modelcontextprotocol")
        );
        assert_eq!(extract_npm_org("@scope/name"), Some("scope"));
        assert_eq!(extract_npm_org("no-scope"), None);
        assert_eq!(extract_npm_org("@noslash"), None);
    }
}
