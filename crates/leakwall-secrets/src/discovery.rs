use crate::fingerprint::generate_fingerprints;
use crate::{DiscoveredSecret, SecretError};
use std::path::{Path, PathBuf};
use tracing::{debug, instrument, warn};
use uuid::Uuid;

/// All secret source files to scan, in priority order.
fn secret_file_paths(home: &Path, cwd: &Path) -> Vec<PathBuf> {
    let mut paths = vec![];

    // Environment files (highest priority)
    for name in &[
        ".env",
        ".env.local",
        ".env.development",
        ".env.production",
        ".env.staging",
        ".env.test",
    ] {
        paths.push(cwd.join(name));
    }
    paths.push(home.join(".env"));

    // Cloud credentials
    paths.push(home.join(".aws/credentials"));
    paths.push(home.join(".aws/config"));
    paths.push(home.join(".azure/credentials"));
    paths.push(home.join(".config/gcloud/application_default_credentials.json"));
    paths.push(home.join(".config/gcloud/credentials.db"));

    // SSH keys (detect + warn only)
    for key in &["id_rsa", "id_ed25519", "id_ecdsa"] {
        paths.push(home.join(format!(".ssh/{key}")));
    }

    // API tokens in config files
    paths.push(home.join(".npmrc"));
    paths.push(home.join(".docker/config.json"));
    paths.push(home.join(".config/gh/hosts.yml"));
    paths.push(home.join(".kube/config"));
    paths.push(home.join(".netrc"));
    paths.push(home.join(".pypirc"));

    // Git credentials
    paths.push(home.join(".git-credentials"));

    paths
}

/// Discover all secrets on the local machine.
#[instrument(skip_all)]
pub fn discover_secrets(home: &Path, cwd: &Path) -> Result<Vec<DiscoveredSecret>, SecretError> {
    let mut secrets = Vec::new();

    // Scan files
    let paths = secret_file_paths(home, cwd);
    for path in &paths {
        if path.exists() {
            match scan_file(path) {
                Ok(found) => secrets.extend(found),
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "failed to scan file");
                }
            }
        }
    }

    // Scan environment variables
    secrets.extend(scan_env_vars());

    // Scan git remotes in CWD
    if let Ok(found) = scan_git_remotes(cwd) {
        secrets.extend(found);
    }

    debug!(count = secrets.len(), "discovery complete");
    Ok(secrets)
}

/// Scan a single file for secrets.
fn scan_file(path: &Path) -> Result<Vec<DiscoveredSecret>, SecretError> {
    let content = std::fs::read_to_string(path).map_err(|source| SecretError::FileRead {
        path: path.to_path_buf(),
        source,
    })?;

    let filename = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    // SSH key detection — warn only, don't store full key
    if is_ssh_key(path) {
        return Ok(vec![DiscoveredSecret {
            id: Uuid::new_v4(),
            name: filename,
            fingerprints: vec![],
        }]);
    }

    // JSON files
    if path.extension().is_some_and(|e| e == "json") {
        return scan_json_file(path, &content);
    }

    // YAML files
    if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
        return scan_key_value_file(path, &content, ':');
    }

    // .env and similar key=value files
    scan_key_value_file(path, &content, '=')
}

/// Scan a key=value format file (e.g. .env, .aws/credentials).
///
/// All values are treated as potential secrets. The minimum length threshold
/// depends on whether the key name looks secret-related (4 chars) or not
/// (8 chars). Common non-secret values (true, localhost, etc.) are skipped
/// to prevent false-positive redactions in code.
fn scan_key_value_file(
    _path: &Path,
    content: &str,
    separator: char,
) -> Result<Vec<DiscoveredSecret>, SecretError> {
    let mut secrets = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('[') {
            continue;
        }

        if let Some((key, value)) = trimmed.split_once(separator) {
            let key = key.trim().trim_start_matches("export ");
            let value = value.trim().trim_matches('"').trim_matches('\'');

            let min_len = min_length_for_key(key);
            if value.is_empty() || value.len() < min_len {
                continue;
            }

            if is_common_value(value) {
                continue;
            }

            secrets.push(DiscoveredSecret {
                id: Uuid::new_v4(),
                name: key.to_string(),
                fingerprints: generate_fingerprints(value),
            });
        }
    }

    Ok(secrets)
}

/// Scan a JSON file for secrets in key-value pairs.
fn scan_json_file(path: &Path, content: &str) -> Result<Vec<DiscoveredSecret>, SecretError> {
    let mut secrets = Vec::new();

    let value: serde_json::Value = serde_json::from_str(content).map_err(|e| {
        SecretError::Serialization(format!("JSON parse error in {}: {e}", path.display()))
    })?;

    collect_json_secrets(&value, "", &mut secrets, 0);
    Ok(secrets)
}

const MAX_JSON_DEPTH: usize = 32;

fn collect_json_secrets(
    value: &serde_json::Value,
    key_path: &str,
    secrets: &mut Vec<DiscoveredSecret>,
    depth: usize,
) {
    if depth > MAX_JSON_DEPTH {
        return;
    }

    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let new_path = if key_path.is_empty() {
                    k.clone()
                } else {
                    format!("{key_path}.{k}")
                };
                collect_json_secrets(v, &new_path, secrets, depth + 1);
            }
        }
        serde_json::Value::String(s) => {
            let min_len = min_length_for_key(key_path);
            if s.len() >= min_len && !is_common_value(s) {
                secrets.push(DiscoveredSecret {
                    id: Uuid::new_v4(),
                    name: key_path.to_string(),
                    fingerprints: generate_fingerprints(s),
                });
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                collect_json_secrets(v, &format!("{key_path}[{i}]"), secrets, depth + 1);
            }
        }
        _ => {}
    }
}

/// Scan shell environment variables for secrets.
fn scan_env_vars() -> Vec<DiscoveredSecret> {
    let mut secrets = Vec::new();
    let exclude_names = [
        "PATH",
        "HOME",
        "SHELL",
        "TERM",
        "EDITOR",
        "LANG",
        "USER",
        "LOGNAME",
        "HOSTNAME",
        "PWD",
        "OLDPWD",
        "SHLVL",
        "DISPLAY",
        "XDG_",
        "LC_",
        // Terminal and desktop
        "TERM_PROGRAM",
        "TERM_SESSION_ID",
        "COLORTERM",
        "WINDOWID",
        "DBUS_SESSION_BUS_ADDRESS",
        "DESKTOP_SESSION",
        "SESSION_MANAGER",
        "GTK_",
        "QT_",
        "GDK_",
        "GNOME_",
        "KDE_",
        "WAYLAND_",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "GPG_AGENT_INFO",
        // Pager and color
        "LESS",
        "PAGER",
        "MANPATH",
        "INFOPATH",
        "LS_COLORS",
        "LSCOLORS",
        "CLICOLOR",
        "GREP_",
        // Editors and tools
        "BROWSER",
        "VISUAL",
        "TMPDIR",
        "TEMP",
        "TMP",
        // Language toolchains
        "CARGO_",
        "RUSTUP_",
        "RUSTC",
        "RUST_",
        "NVM_",
        "PYENV_",
        "GOPATH",
        "GOROOT",
        "JAVA_HOME",
        "NODE_PATH",
        "VIRTUAL_ENV",
        "CONDA_",
        // WSL
        "WSL_",
        "WSLENV",
        "WT_",
    ];

    for (key, value) in std::env::vars() {
        // Skip excluded
        if exclude_names
            .iter()
            .any(|e| key.starts_with(e) || key == *e)
        {
            continue;
        }

        let min_len = min_length_for_key(&key);
        if value.len() < min_len {
            continue;
        }

        if is_common_value(&value) {
            continue;
        }

        secrets.push(DiscoveredSecret {
            id: Uuid::new_v4(),
            name: key,
            fingerprints: generate_fingerprints(&value),
        });
    }

    secrets
}

/// Scan git remotes in a directory for embedded tokens.
fn scan_git_remotes(cwd: &Path) -> Result<Vec<DiscoveredSecret>, SecretError> {
    let git_config = cwd.join(".git/config");
    if !git_config.exists() {
        return Ok(vec![]);
    }

    let content = std::fs::read_to_string(&git_config).map_err(|source| SecretError::FileRead {
        path: git_config.clone(),
        source,
    })?;

    let mut secrets = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("url =") {
            if let Some(url) = trimmed.strip_prefix("url = ") {
                // Check for embedded credentials in URLs like https://user:token@github.com
                if let Some(at_pos) = url.find('@') {
                    if let Some(proto_end) = url.find("://") {
                        let cred_start = proto_end + 3;
                        if let Some(cred_part) = url.get(cred_start..at_pos) {
                            if cred_part.contains(':') {
                                let token = cred_part.split(':').nth(1).unwrap_or(cred_part);
                                if token.len() >= 8 {
                                    secrets.push(DiscoveredSecret {
                                        id: Uuid::new_v4(),
                                        name: "git_remote_token".into(),
                                        fingerprints: generate_fingerprints(token),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(secrets)
}

/// Common non-secret values that appear in config files but would cause
/// false-positive redactions if fingerprinted (e.g. "true" in code).
const COMMON_VALUES: &[&str] = &[
    // Booleans / nulls
    "true",
    "false",
    "yes",
    "no",
    "null",
    "none",
    "undefined",
    // Environments
    "development",
    "production",
    "staging",
    "test",
    "testing",
    "local",
    // Log levels
    "debug",
    "info",
    "warn",
    "warning",
    "error",
    "trace",
    "verbose",
    // Common hosts / values
    "localhost",
    "0.0.0.0",
    "127.0.0.1",
    "::1",
    // Common defaults
    "default",
    "auto",
    "enabled",
    "disabled",
    "on",
    "off",
    "utf-8",
    "utf8",
    "json",
    "text",
    "html",
    "https",
    "http",
];

/// Returns true if the value is a common non-secret config value.
fn is_common_value(value: &str) -> bool {
    let lower = value.to_lowercase();
    COMMON_VALUES.iter().any(|&cv| lower == cv)
}

/// Minimum fingerprint length depends on whether the key name looks secret-related.
/// Secret-looking keys: 4 chars. Everything else: 8 chars.
fn min_length_for_key(key: &str) -> usize {
    if is_secret_key_name(key) {
        4
    } else {
        8
    }
}

/// Check if a key name likely refers to a secret.
fn is_secret_key_name(key: &str) -> bool {
    let upper = key.to_uppercase();
    let secret_indicators = [
        "KEY",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "CREDENTIAL",
        "AUTH",
        "API_KEY",
        "APIKEY",
        "ACCESS_KEY",
        "PRIVATE",
        "PASSWD",
        "CONN",
        "DSN",
        "URL",
    ];
    secret_indicators.iter().any(|ind| upper.contains(ind))
}

fn is_ssh_key(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    name.starts_with("id_") && !name.ends_with(".pub")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_secret_key_name() {
        assert!(is_secret_key_name("AWS_SECRET_ACCESS_KEY"));
        assert!(is_secret_key_name("GITHUB_TOKEN"));
        assert!(is_secret_key_name("api_key"));
        assert!(is_secret_key_name("DATABASE_PASSWORD"));
        assert!(is_secret_key_name("DATABASE_URL"));
        assert!(!is_secret_key_name("HOME"));
        assert!(!is_secret_key_name("PATH"));
        assert!(!is_secret_key_name("EDITOR"));
    }

    #[test]
    fn test_common_values_skipped() {
        assert!(is_common_value("true"));
        assert!(is_common_value("false"));
        assert!(is_common_value("localhost"));
        assert!(is_common_value("development"));
        assert!(is_common_value("production"));
        assert!(is_common_value("True")); // case-insensitive
        assert!(is_common_value("DEBUG"));
        assert!(!is_common_value("sk_live_abc123"));
        assert!(!is_common_value("ghp_1234567890abcdef"));
    }

    #[test]
    fn test_two_tier_min_length() {
        // Secret-looking key: min 4
        assert_eq!(min_length_for_key("API_KEY"), 4);
        assert_eq!(min_length_for_key("SECRET_TOKEN"), 4);
        // Non-secret key: min 8
        assert_eq!(min_length_for_key("NODE_ENV"), 8);
        assert_eq!(min_length_for_key("DEBUG"), 8);
        assert_eq!(min_length_for_key("PORT"), 8);
    }

    #[test]
    fn test_scan_kv_skips_common_values() {
        let content = "NODE_ENV=development\nAPI_KEY=sk_1234\nDEBUG=true\nDB_HOST=localhost\n";
        let secrets = scan_key_value_file(Path::new("test"), content, '=').unwrap();
        let names: Vec<&str> = secrets.iter().map(|s| s.name.as_str()).collect();
        // API_KEY=sk_1234 should be found (secret key, 7 chars >= 4)
        assert!(names.contains(&"API_KEY"));
        // NODE_ENV=development should be skipped (common value)
        assert!(!names.contains(&"NODE_ENV"));
        // DEBUG=true should be skipped (common value)
        assert!(!names.contains(&"DEBUG"));
        // DB_HOST=localhost should be skipped (common value)
        assert!(!names.contains(&"DB_HOST"));
    }

    #[test]
    fn test_scan_kv_short_non_secret_key_needs_8_chars() {
        let content = "PORT=3000\nMY_SETTING=abcdefgh\n";
        let secrets = scan_key_value_file(Path::new("test"), content, '=').unwrap();
        let names: Vec<&str> = secrets.iter().map(|s| s.name.as_str()).collect();
        // PORT=3000 — non-secret key, value 4 chars < 8 minimum
        assert!(!names.contains(&"PORT"));
        // MY_SETTING=abcdefgh — non-secret key, value 8 chars = 8 minimum
        assert!(names.contains(&"MY_SETTING"));
    }
}
