use serde::{Deserialize, Serialize};

/// Maps secret pattern names to the domains where they are allowed to be sent.
/// Supports auto-detection of provider API keys and custom wildcard rules.
#[derive(Deserialize, Serialize, Clone)]
pub struct AllowlistConfig {
    #[serde(default = "default_true")]
    pub auto_provider_allowlist: bool,
    #[serde(default)]
    pub rules: Vec<AllowlistRule>,
}

impl Default for AllowlistConfig {
    fn default() -> Self {
        Self {
            auto_provider_allowlist: true,
            rules: Vec::new(),
        }
    }
}

/// A single allowlist rule mapping a secret pattern to permitted destinations.
#[derive(Deserialize, Serialize, Clone)]
pub struct AllowlistRule {
    pub secret_pattern: String,
    pub allowed_domains: Vec<String>,
}

fn default_true() -> bool {
    true
}

/// Built-in mapping of well-known secret patterns to their expected API
/// destinations. Used when `auto_provider_allowlist` is enabled.
const AUTO_PROVIDER_MAP: &[(&str, &[&str])] = &[
    ("anthropic_api_key", &["api.anthropic.com"]),
    ("openai_api_key", &["api.openai.com"]),
    ("stripe_live", &["api.stripe.com"]),
    ("github_pat", &["api.github.com", "uploads.github.com"]),
];

impl AllowlistConfig {
    /// Check whether a secret matching `pattern_name` is allowed to be sent
    /// to `destination`.
    ///
    /// Returns `true` if:
    /// 1. The auto-provider allowlist is enabled and the pattern + destination
    ///    match a built-in mapping, OR
    /// 2. A custom rule's `secret_pattern` matches and any of its
    ///    `allowed_domains` match the destination (with wildcard support).
    pub fn is_allowed(&self, pattern_name: &str, destination: &str) -> bool {
        // Check auto-provider allowlist
        if self.auto_provider_allowlist {
            for &(pattern, domains) in AUTO_PROVIDER_MAP {
                if pattern == pattern_name && domains.contains(&destination) {
                    return true;
                }
            }
        }

        // Check custom rules
        for rule in &self.rules {
            if rule.secret_pattern == pattern_name
                && rule
                    .allowed_domains
                    .iter()
                    .any(|d| domain_matches(d, destination))
            {
                return true;
            }
        }

        false
    }
}

/// Match a domain pattern against a destination. Supports wildcard prefix
/// patterns like `*.stripe.com` which match any subdomain of `stripe.com`.
fn domain_matches(pattern: &str, destination: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard: match the suffix itself or any subdomain
        destination == suffix || destination.ends_with(&format!(".{}", suffix))
    } else {
        pattern == destination
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_provider_anthropic() {
        let config = AllowlistConfig::default();
        assert!(config.is_allowed("anthropic_api_key", "api.anthropic.com"));
    }

    #[test]
    fn auto_provider_openai() {
        let config = AllowlistConfig::default();
        assert!(config.is_allowed("openai_api_key", "api.openai.com"));
    }

    #[test]
    fn auto_provider_rejects_wrong_destination() {
        let config = AllowlistConfig::default();
        assert!(!config.is_allowed("anthropic_api_key", "evil.example.com"));
    }

    #[test]
    fn auto_provider_github_multiple_domains() {
        let config = AllowlistConfig::default();
        assert!(config.is_allowed("github_pat", "api.github.com"));
        assert!(config.is_allowed("github_pat", "uploads.github.com"));
        assert!(!config.is_allowed("github_pat", "evil.github.com"));
    }

    #[test]
    fn custom_rule_exact_match() {
        let config = AllowlistConfig {
            auto_provider_allowlist: false,
            rules: vec![AllowlistRule {
                secret_pattern: "my_custom_key".into(),
                allowed_domains: vec!["api.myservice.com".into()],
            }],
        };
        assert!(config.is_allowed("my_custom_key", "api.myservice.com"));
        assert!(!config.is_allowed("my_custom_key", "other.com"));
    }

    #[test]
    fn wildcard_domain_matching() {
        let config = AllowlistConfig {
            auto_provider_allowlist: false,
            rules: vec![AllowlistRule {
                secret_pattern: "stripe_key".into(),
                allowed_domains: vec!["*.stripe.com".into()],
            }],
        };
        assert!(config.is_allowed("stripe_key", "api.stripe.com"));
        assert!(config.is_allowed("stripe_key", "dashboard.stripe.com"));
        assert!(config.is_allowed("stripe_key", "stripe.com"));
        assert!(!config.is_allowed("stripe_key", "notstripe.com"));
    }

    #[test]
    fn disabled_auto_provider() {
        let config = AllowlistConfig {
            auto_provider_allowlist: false,
            rules: vec![],
        };
        assert!(
            !config.is_allowed("anthropic_api_key", "api.anthropic.com"),
            "auto-provider should be disabled"
        );
    }

    #[test]
    fn unknown_pattern_not_allowed() {
        let config = AllowlistConfig::default();
        assert!(!config.is_allowed("unknown_key", "api.anything.com"));
    }
}
