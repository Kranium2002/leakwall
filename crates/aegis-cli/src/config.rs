use serde::Deserialize;
use std::path::PathBuf;
use tracing::debug;

// Config struct fields match the aegis.toml schema; not all are consumed by CLI yet.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct McpScanConfig {
    #[serde(default = "default_mcp_scan_enabled")]
    pub enabled: bool,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
}

fn default_mcp_scan_enabled() -> bool {
    true
}

fn default_connect_timeout() -> u64 {
    10
}

impl Default for McpScanConfig {
    fn default() -> Self {
        Self {
            enabled: default_mcp_scan_enabled(),
            connect_timeout_secs: default_connect_timeout(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RegistryConfig {
    #[serde(default = "default_registry_enabled")]
    pub enabled: bool,
    #[serde(default = "default_agentaudit_url")]
    pub agentaudit_url: String,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_hours: i64,
}

fn default_registry_enabled() -> bool {
    true
}

fn default_agentaudit_url() -> String {
    "https://agentaudit.dev/api".into()
}

fn default_cache_ttl() -> i64 {
    24
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            enabled: default_registry_enabled(),
            agentaudit_url: default_agentaudit_url(),
            cache_ttl_hours: default_cache_ttl(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AegisConfig {
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_log_dir")]
    pub log_dir: PathBuf,
    #[serde(default)]
    pub mcp_scan: McpScanConfig,
    #[serde(default)]
    pub registry: RegistryConfig,
}

fn default_proxy_port() -> u16 {
    9090
}

fn default_mode() -> String {
    "redact".into()
}

fn default_log_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".aegis/logs")
}

impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            proxy_port: default_proxy_port(),
            mode: default_mode(),
            log_dir: default_log_dir(),
            mcp_scan: McpScanConfig::default(),
            registry: RegistryConfig::default(),
        }
    }
}

/// Load configuration from file, checking local then global paths.
/// Falls back to defaults if no config file is found.
pub fn load_config(explicit_path: Option<&PathBuf>) -> AegisConfig {
    // If an explicit path was provided, try that first
    if let Some(path) = explicit_path {
        if let Some(config) = try_load_config(path) {
            return config;
        }
        tracing::warn!(
            path = %path.display(),
            "specified config file not found, using defaults"
        );
    }

    // Try ./aegis.toml (project-level)
    let local = PathBuf::from("aegis.toml");
    if let Some(config) = try_load_config(&local) {
        debug!(path = %local.display(), "loaded project config");
        return config;
    }

    // Try ~/.aegis/config.toml (global)
    if let Some(home) = dirs::home_dir() {
        let global = home.join(".aegis/config.toml");
        if let Some(config) = try_load_config(&global) {
            debug!(path = %global.display(), "loaded global config");
            return config;
        }
    }

    debug!("no config file found, using defaults");
    AegisConfig::default()
}

fn try_load_config(path: &std::path::Path) -> Option<AegisConfig> {
    let content = std::fs::read_to_string(path).ok()?;
    match toml::from_str::<AegisConfig>(&content) {
        Ok(config) => Some(config),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "failed to parse config file"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AegisConfig::default();
        assert_eq!(config.proxy_port, 9090);
        assert_eq!(config.mode, "redact");
        assert!(config.mcp_scan.enabled);
        assert!(config.registry.enabled);
        assert_eq!(config.registry.cache_ttl_hours, 24);
    }

    #[test]
    fn test_parse_example_config() {
        let toml_str = r#"
proxy_port = 8080
mode = "block"

[mcp_scan]
enabled = false
connect_timeout_secs = 5

[registry]
enabled = true
cache_ttl_hours = 12
"#;
        let config: AegisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proxy_port, 8080);
        assert_eq!(config.mode, "block");
        assert!(!config.mcp_scan.enabled);
        assert_eq!(config.mcp_scan.connect_timeout_secs, 5);
        assert_eq!(config.registry.cache_ttl_hours, 12);
    }

    #[test]
    fn test_partial_config_uses_defaults() {
        let toml_str = r#"
proxy_port = 3000
"#;
        let config: AegisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.proxy_port, 3000);
        assert_eq!(config.mode, "redact");
        assert!(config.mcp_scan.enabled);
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let config = load_config(Some(&PathBuf::from("/nonexistent/path.toml")));
        assert_eq!(config.proxy_port, 9090);
    }
}
