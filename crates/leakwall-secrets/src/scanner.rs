use crate::patterns::CompiledPattern;
use crate::Severity;
use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Information about a known secret in the Aho-Corasick automaton.
#[derive(Debug, Clone)]
pub struct KnownSecretInfo {
    pub name: String,
    pub secret_id: String,
}

/// Source of a match — known secret from DB or pattern regex.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MatchSource {
    Known,
    Pattern,
}

/// A single secret match found during scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub matched_text_preview: String,
    pub byte_offset: usize,
    pub match_length: usize,
    pub source: MatchSource,
    pub severity: Severity,
}

/// Result of scanning a body for secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub matches: Vec<SecretMatch>,
    pub scan_duration: Duration,
    pub body_size: usize,
}

impl ScanResult {
    /// Returns true if no secrets were found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.matches.is_empty()
    }

    /// Returns the highest severity among all matches.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.matches.iter().map(|m| m.severity).max()
    }
}

/// Two-layer secret scanner combining Aho-Corasick (known secrets) and regex (patterns).
pub struct SecretScanner {
    known_automaton: Option<AhoCorasick>,
    known_patterns: Vec<KnownSecretInfo>,
    pattern_regexes: Vec<CompiledPattern>,
}

impl SecretScanner {
    /// Build a scanner from known secret fingerprints and compiled regex patterns.
    pub fn new(
        known_fingerprints: Vec<(KnownSecretInfo, Vec<Vec<u8>>)>,
        pattern_regexes: Vec<CompiledPattern>,
    ) -> Result<Self, crate::SecretError> {
        let mut all_patterns = Vec::new();
        let mut known_patterns = Vec::new();

        for (info, fingerprints) in known_fingerprints {
            for fp in fingerprints {
                known_patterns.push(info.clone());
                all_patterns.push(fp);
            }
        }

        let known_automaton = if all_patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .build(&all_patterns)
                    .map_err(|e| crate::SecretError::PatternCompile(e.to_string()))?,
            )
        };

        Ok(Self {
            known_automaton,
            known_patterns,
            pattern_regexes,
        })
    }

    /// Build a scanner from just regex patterns (no known secrets).
    pub fn from_patterns(pattern_regexes: Vec<CompiledPattern>) -> Self {
        Self {
            known_automaton: None,
            known_patterns: Vec::new(),
            pattern_regexes,
        }
    }

    /// Scan a byte slice for secrets. Designed to be called from spawn_blocking.
    #[must_use]
    pub fn scan(&self, body: &[u8]) -> ScanResult {
        let start = Instant::now();
        let mut matches = Vec::new();

        // Layer 1: Aho-Corasick (known secrets)
        if let Some(ref automaton) = self.known_automaton {
            for mat in automaton.find_iter(body) {
                // Skip substring matches that aren't at word boundaries
                // to avoid "test" matching inside "testing" or "latest".
                if !is_at_word_boundary(body, mat.start(), mat.end()) {
                    continue;
                }
                let info = &self.known_patterns[mat.pattern().as_usize()];
                matches.push(SecretMatch {
                    pattern_name: format!("known:{}", info.name),
                    matched_text_preview: preview(&body[mat.start()..mat.end()]),
                    byte_offset: mat.start(),
                    match_length: mat.end() - mat.start(),
                    source: MatchSource::Known,
                    severity: Severity::Critical,
                });
            }
        }

        // Layer 2: Regex patterns (generic formats) — match directly on raw bytes
        // to avoid UTF-8 lossy conversion which can shift byte offsets.
        for pattern in &self.pattern_regexes {
            // If pattern has a context_regex, check that first
            if let Some(ref ctx) = pattern.context_regex {
                if !ctx.is_match(body) {
                    continue;
                }
            }

            for mat in pattern.regex.find_iter(body) {
                let offset = mat.start();
                let len = mat.len();
                // Deduplicate against Layer 1 matches
                if !matches.iter().any(|m| overlaps(m, offset, len)) {
                    matches.push(SecretMatch {
                        pattern_name: pattern.name.clone(),
                        matched_text_preview: preview(&body[offset..offset + len]),
                        byte_offset: offset,
                        match_length: len,
                        source: MatchSource::Pattern,
                        severity: pattern.severity,
                    });
                }
            }
        }

        ScanResult {
            matches,
            scan_duration: start.elapsed(),
            body_size: body.len(),
        }
    }
}

/// Check that a match is not a substring of a larger word.
/// A byte is a "word char" if it's alphanumeric or underscore.
fn is_at_word_boundary(body: &[u8], start: usize, end: usize) -> bool {
    let before_ok = start == 0 || !is_word_char(body[start - 1]);
    let after_ok = end >= body.len() || !is_word_char(body[end]);
    before_ok && after_ok
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn overlaps(existing: &SecretMatch, offset: usize, length: usize) -> bool {
    let e_start = existing.byte_offset;
    let e_end = e_start + existing.match_length;
    let n_end = offset + length;
    offset < e_end && n_end > e_start
}

fn preview(bytes: &[u8]) -> String {
    let len = bytes.len().min(8);
    let s = String::from_utf8_lossy(&bytes[..len]);
    format!("{s}...")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::{compile_patterns, default_pattern_defs};

    #[test]
    fn test_aws_key_detection() {
        let defs = default_pattern_defs();
        let compiled = compile_patterns(&defs).unwrap();
        let scanner = SecretScanner::from_patterns(compiled);
        let body = br#"{"content": "key is AKIAIOSFODNN7EXAMPLE"}"#;
        let result = scanner.scan(body);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].pattern_name, "aws_access_key");
    }

    #[test]
    fn test_no_false_positive_on_prose() {
        let defs = default_pattern_defs();
        let compiled = compile_patterns(&defs).unwrap();
        let scanner = SecretScanner::from_patterns(compiled);
        let body = br#"{"content": "How to implement a binary tree in Rust"}"#;
        let result = scanner.scan(body);
        assert!(result.is_clean());
    }

    #[test]
    fn test_github_pat_detection() {
        let defs = default_pattern_defs();
        let compiled = compile_patterns(&defs).unwrap();
        let scanner = SecretScanner::from_patterns(compiled);
        let body = b"token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";
        let result = scanner.scan(body);
        assert!(!result.is_clean());
        assert!(result
            .matches
            .iter()
            .any(|m| m.pattern_name == "github_pat"));
    }

    #[test]
    fn test_known_secret_detection() {
        let known = vec![(
            KnownSecretInfo {
                name: "MY_API_KEY".into(),
                secret_id: "test-id".into(),
            },
            vec![b"super_secret_value_123".to_vec()],
        )];
        let scanner = SecretScanner::new(known, vec![]).unwrap();
        let body = b"sending data with super_secret_value_123 embedded";
        let result = scanner.scan(body);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].pattern_name, "known:MY_API_KEY");
    }
}
