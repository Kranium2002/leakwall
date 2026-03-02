use crate::{SecretError, Severity};
use regex::bytes::Regex;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct PatternFile {
    pub patterns: Vec<PatternDef>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PatternDef {
    pub name: String,
    pub regex: String,
    pub severity: String,
    pub description: String,
    #[serde(default)]
    pub context_regex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub name: String,
    pub regex: Regex,
    pub context_regex: Option<Regex>,
    pub severity: Severity,
    pub description: String,
}

/// Load pattern definitions from a TOML file.
pub fn load_patterns(path: &Path) -> Result<Vec<PatternDef>, SecretError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        SecretError::PatternFile(format!(
            "failed to read patterns file {}: {e}",
            path.display()
        ))
    })?;
    let file: PatternFile = toml::from_str(&content)
        .map_err(|e| SecretError::PatternFile(format!("failed to parse patterns TOML: {e}")))?;
    Ok(file.patterns)
}

/// Compile pattern definitions into regex-ready patterns.
pub fn compile_patterns(defs: &[PatternDef]) -> Result<Vec<CompiledPattern>, SecretError> {
    let mut compiled = Vec::with_capacity(defs.len());
    for def in defs {
        let regex = Regex::new(&def.regex)
            .map_err(|e| SecretError::PatternCompile(format!("pattern '{}': {e}", def.name)))?;
        let context_regex = def
            .context_regex
            .as_ref()
            .map(|cr| {
                Regex::new(cr).map_err(|e| {
                    SecretError::PatternCompile(format!("context regex for '{}': {e}", def.name))
                })
            })
            .transpose()?;
        let severity = parse_severity(&def.severity);
        compiled.push(CompiledPattern {
            name: def.name.clone(),
            regex,
            context_regex,
            severity,
            description: def.description.clone(),
        });
    }
    Ok(compiled)
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

/// Return embedded default patterns for when no patterns file is available.
#[must_use]
pub fn default_pattern_defs() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "aws_access_key".into(),
            regex: r"AKIA[0-9A-Z]{16}".into(),
            severity: "critical".into(),
            description: "AWS Access Key ID".into(),
            context_regex: None,
        },
        PatternDef {
            name: "aws_secret_key".into(),
            regex: r"[0-9a-zA-Z/+]{40}".into(),
            severity: "critical".into(),
            description: "AWS Secret Access Key (requires context)".into(),
            context_regex: Some(r"(?i)(aws|secret|access).*[0-9a-zA-Z/+]{40}".into()),
        },
        PatternDef {
            name: "github_pat".into(),
            regex: r"ghp_[a-zA-Z0-9]{36}".into(),
            severity: "critical".into(),
            description: "GitHub Personal Access Token".into(),
            context_regex: None,
        },
        PatternDef {
            name: "github_oauth".into(),
            regex: r"gho_[a-zA-Z0-9]{36}".into(),
            severity: "critical".into(),
            description: "GitHub OAuth Token".into(),
            context_regex: None,
        },
        PatternDef {
            name: "github_fine_grained".into(),
            regex: r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}".into(),
            severity: "critical".into(),
            description: "GitHub Fine-Grained PAT".into(),
            context_regex: None,
        },
        PatternDef {
            name: "stripe_live".into(),
            regex: r"sk_live_[a-zA-Z0-9]{24,}".into(),
            severity: "critical".into(),
            description: "Stripe Live Secret Key".into(),
            context_regex: None,
        },
        PatternDef {
            name: "stripe_test".into(),
            regex: r"sk_test_[a-zA-Z0-9]{24,}".into(),
            severity: "medium".into(),
            description: "Stripe Test Secret Key".into(),
            context_regex: None,
        },
        PatternDef {
            name: "slack_bot_token".into(),
            regex: r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}".into(),
            severity: "critical".into(),
            description: "Slack Bot Token".into(),
            context_regex: None,
        },
        PatternDef {
            name: "slack_user_token".into(),
            regex: r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}".into(),
            severity: "critical".into(),
            description: "Slack User Token".into(),
            context_regex: None,
        },
        PatternDef {
            name: "npm_token".into(),
            regex: r"npm_[a-zA-Z0-9]{36}".into(),
            severity: "high".into(),
            description: "npm Access Token".into(),
            context_regex: None,
        },
        PatternDef {
            name: "openai_api_key".into(),
            regex: r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}".into(),
            severity: "critical".into(),
            description: "OpenAI API Key".into(),
            context_regex: None,
        },
        PatternDef {
            name: "anthropic_api_key".into(),
            regex: r"sk-ant-[a-zA-Z0-9\-]{90,}".into(),
            severity: "critical".into(),
            description: "Anthropic API Key".into(),
            context_regex: None,
        },
        PatternDef {
            name: "google_api_key".into(),
            regex: r"AIza[0-9A-Za-z_-]{35}".into(),
            severity: "high".into(),
            description: "Google API Key".into(),
            context_regex: None,
        },
        PatternDef {
            name: "jwt_token".into(),
            regex: r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}".into(),
            severity: "high".into(),
            description: "JWT Token".into(),
            context_regex: None,
        },
        PatternDef {
            name: "private_key".into(),
            regex: r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----".into(),
            severity: "critical".into(),
            description: "Private Key (PEM format)".into(),
            context_regex: None,
        },
        PatternDef {
            name: "database_url".into(),
            regex: r"(?:postgres|mysql|mongodb)://[^:]+:[^@]+@[^/]+".into(),
            severity: "critical".into(),
            description: "Database Connection URL with credentials".into(),
            context_regex: None,
        },
        PatternDef {
            name: "generic_bearer".into(),
            regex: r"Bearer [a-zA-Z0-9_-]{20,}".into(),
            severity: "medium".into(),
            description: "Bearer Token".into(),
            context_regex: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compile_default_patterns() {
        let defs = default_pattern_defs();
        let compiled = compile_patterns(&defs).unwrap();
        assert_eq!(compiled.len(), 17);
    }

    #[test]
    fn test_aws_key_pattern() {
        let defs = default_pattern_defs();
        let compiled = compile_patterns(&defs).unwrap();
        let aws = compiled
            .iter()
            .find(|p| p.name == "aws_access_key")
            .unwrap();
        assert!(aws.regex.is_match(b"AKIAIOSFODNN7EXAMPLE"));
        assert!(!aws.regex.is_match(b"not_an_aws_key"));
    }
}
