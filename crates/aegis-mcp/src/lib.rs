pub mod analyze;
pub mod connect;
pub mod cve;
pub mod discover;
pub mod hashpin;
pub mod registry;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum McpError {
    #[error("MCP config discovery error: {0}")]
    Discovery(String),

    #[error("MCP connection error: {0}")]
    Connection(String),

    #[error("MCP configuration error: {0}")]
    Config(String),

    #[error("registry query error: {0}")]
    Registry(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentType {
    ClaudeDesktop,
    ClaudeCode,
    Cursor,
    VsCode,
    Windsurf,
    GeminiCli,
    ContinueDev,
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaudeDesktop => write!(f, "Claude Desktop"),
            Self::ClaudeCode => write!(f, "Claude Code"),
            Self::Cursor => write!(f, "Cursor"),
            Self::VsCode => write!(f, "VS Code"),
            Self::Windsurf => write!(f, "Windsurf"),
            Self::GeminiCli => write!(f, "Gemini CLI"),
            Self::ContinueDev => write!(f, "Continue.dev"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConfigScope {
    Global,
    Project,
}

impl std::fmt::Display for ConfigScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Global => write!(f, "global"),
            Self::Project => write!(f, "project"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfigLocation {
    pub agent: AgentType,
    pub path: std::path::PathBuf,
    pub scope: ConfigScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: std::collections::HashMap<String, String>,
    pub url: Option<String>,
    pub source: McpConfigLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerIdentity {
    pub name: String,
    pub version: Option<String>,
    pub package_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Option<ToolSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    pub properties: std::collections::HashMap<String, SchemaProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaProperty {
    pub description: Option<String>,
    pub default: Option<serde_json::Value>,
    pub enum_values: Option<Vec<String>>,
}

/// Severity levels for MCP audit findings.
///
/// Note: This mirrors `aegis_secrets::Severity` intentionally. Both crates are independent
/// with no shared dependency, so we maintain consistent variants here rather than introducing
/// a shared crate just for this enum.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FindingType {
    ToolPoisoning,
    UnicodeObfuscation,
    DangerousCapability,
    ConfigMisconfiguration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub finding_type: FindingType,
    pub tool_name: String,
    pub field: String,
    pub detail: String,
    pub matched_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryResults {
    pub agent_audit: Option<AgentAuditResult>,
    pub mcp_trust: Option<McpTrustResult>,
    pub cves: Vec<KnownCve>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAuditResult {
    pub trust_score: u8,
    pub findings: Vec<AuditFinding>,
    pub asf_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub id: String,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTrustResult {
    pub risk_level: RiskLevel,
    pub vulnerabilities: Vec<VulnDetail>,
    pub remediation: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnDetail {
    pub id: String,
    pub description: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownCve {
    pub id: String,
    pub cvss: f32,
    pub affected_versions: String,
    pub fixed_version: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HashChangeType {
    NewTool,
    Modified,
    Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashChange {
    pub tool_name: String,
    pub change_type: HashChangeType,
    pub previous_hash: Option<String>,
    pub current_hash: String,
    pub first_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Verdict {
    Safe,
    SafeWithAdvisory,
    Suspicious,
    Unsafe,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Safe => write!(f, "SAFE"),
            Self::SafeWithAdvisory => write!(f, "SAFE (with advisory)"),
            Self::Suspicious => write!(f, "SUSPICIOUS"),
            Self::Unsafe => write!(f, "UNSAFE"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAuditResult {
    pub identity: ServerIdentity,
    pub tools_count: usize,
    pub local_findings: Vec<Finding>,
    pub registry: RegistryResults,
    pub hash_changes: Vec<HashChange>,
    pub verdict: Verdict,
}

/// Agent configuration audit types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFinding {
    pub agent: AgentType,
    pub severity: Severity,
    pub setting: String,
    pub current_value: String,
    pub recommendation: String,
}

/// Exposure check for secrets visibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposureCheck {
    pub claudeignore_blocks_env: bool,
    pub gitignore_blocks_env: bool,
    pub claude_deny_rules: Vec<String>,
    pub dangerous_env_vars: Vec<String>,
    pub plaintext_secrets: Vec<PlaintextFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaintextFinding {
    pub file: String,
    pub description: String,
}

/// Run the full MCP audit pipeline for a single server.
///
/// When `trust_project` is false, project-level MCP servers are not executed.
pub async fn audit_mcp_server(
    server: &McpServerConfig,
    refresh: bool,
    trust_project: bool,
) -> Result<McpAuditResult, McpError> {
    let identity = connect::extract_identity(server);
    let tools = connect::connect_and_list_tools(server, trust_project).await?;
    let local_findings = analyze::analyze_tools_locally(&tools);
    let registry = registry::query_registries(&identity, refresh).await;
    let hash_changes = hashpin::check_hash_pins(&identity, &tools);
    let verdict = compute_verdict(&local_findings, &registry, &hash_changes);

    Ok(McpAuditResult {
        identity,
        tools_count: tools.len(),
        local_findings,
        registry,
        hash_changes,
        verdict,
    })
}

/// Compute overall verdict from findings.
fn compute_verdict(
    findings: &[Finding],
    registry: &RegistryResults,
    hash_changes: &[HashChange],
) -> Verdict {
    let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
    let has_poisoning = findings
        .iter()
        .any(|f| f.finding_type == FindingType::ToolPoisoning);

    if has_poisoning {
        return Verdict::Unsafe;
    }

    if has_critical {
        return Verdict::Unsafe;
    }

    // Check registry for high risk
    if let Some(ref aa) = registry.agent_audit {
        if aa.trust_score < 40 {
            return Verdict::Unsafe;
        }
    }
    if let Some(ref mt) = registry.mcp_trust {
        if mt.risk_level == RiskLevel::Critical || mt.risk_level == RiskLevel::High {
            return Verdict::Unsafe;
        }
    }

    // Check for rug pull
    let has_modifications = hash_changes
        .iter()
        .any(|h| h.change_type == HashChangeType::Modified);
    if has_modifications {
        return Verdict::Suspicious;
    }

    // Check for medium findings
    let has_high = findings.iter().any(|f| f.severity == Severity::High);
    if has_high {
        return Verdict::SafeWithAdvisory;
    }

    Verdict::Safe
}

/// Check secrets exposure in the current project.
#[must_use]
pub fn check_exposure(cwd: &std::path::Path) -> ExposureCheck {
    let claudeignore = cwd.join(".claudeignore");
    let gitignore = cwd.join(".gitignore");

    let claudeignore_blocks_env = check_ignore_file(&claudeignore, &[".env"]);
    let gitignore_blocks_env = check_ignore_file(&gitignore, &[".env"]);

    let claude_deny_rules = load_claude_deny_rules();
    let dangerous_env_vars = find_dangerous_env_vars();

    let plaintext_secrets = find_plaintext_secrets(cwd);

    ExposureCheck {
        claudeignore_blocks_env,
        gitignore_blocks_env,
        claude_deny_rules,
        dangerous_env_vars,
        plaintext_secrets,
    }
}

fn check_ignore_file(path: &std::path::Path, patterns: &[&str]) -> bool {
    if let Ok(content) = std::fs::read_to_string(path) {
        patterns
            .iter()
            .all(|p| content.lines().any(|l| l.trim().contains(p)))
    } else {
        false
    }
}

fn load_claude_deny_rules() -> Vec<String> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return vec![],
    };
    let settings_path = home.join(".claude/settings.json");
    if let Ok(content) = std::fs::read_to_string(settings_path) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(deny) = val.get("deny").and_then(|d| d.as_array()) {
                return deny
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
            }
        }
    }
    vec![]
}

fn find_dangerous_env_vars() -> Vec<String> {
    let secret_indicators = ["KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "AUTH"];
    let exclude = ["PATH", "HOME", "SHELL", "TERM", "EDITOR", "LANG", "USER"];

    std::env::vars()
        .filter(|(k, v)| {
            let upper = k.to_uppercase();
            !exclude.iter().any(|e| upper == *e)
                && secret_indicators.iter().any(|s| upper.contains(s))
                && v.len() >= 8
        })
        .map(|(k, _)| k)
        .collect()
}

/// Check for plaintext secrets in non-gitignored config files.
fn find_plaintext_secrets(cwd: &std::path::Path) -> Vec<PlaintextFinding> {
    let secret_patterns = [
        "password",
        "secret",
        "api_key",
        "apikey",
        "token",
        "private_key",
        "access_key",
    ];
    let config_files = [
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        "config.json",
        "config.yaml",
        "config.yml",
        "config.toml",
        "secrets.json",
        "credentials.json",
    ];

    let gitignore_path = cwd.join(".gitignore");
    let gitignore_content = std::fs::read_to_string(gitignore_path).unwrap_or_default();

    let mut findings = Vec::new();

    for filename in &config_files {
        let file_path = cwd.join(filename);
        if !file_path.exists() {
            continue;
        }

        // Check if the file is gitignored
        let is_gitignored = gitignore_content.lines().any(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty()
                && !trimmed.starts_with('#')
                && (trimmed == *filename || trimmed.trim_start_matches('/') == *filename)
        });

        if is_gitignored {
            continue;
        }

        // Read the file and look for secret patterns
        if let Ok(content) = std::fs::read_to_string(&file_path) {
            let lower = content.to_lowercase();
            for pattern in &secret_patterns {
                if lower.contains(pattern) {
                    findings.push(PlaintextFinding {
                        file: filename.to_string(),
                        description: format!(
                            "possible secret ('{pattern}' pattern) in non-gitignored file \
                             {filename}"
                        ),
                    });
                    break;
                }
            }
        }
    }

    findings
}
