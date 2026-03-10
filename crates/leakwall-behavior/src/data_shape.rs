use crate::Confidence;

/// Result of classifying a single string value as potentially sensitive.
#[derive(Debug, Clone)]
pub struct ShapeMatch {
    pub value_preview: String,
    pub entropy: f64,
    pub length: usize,
    pub confidence: Confidence,
    pub reason: String,
}

/// Detects credential-shaped strings using Shannon entropy and heuristics.
pub struct DataShapeClassifier {
    pub entropy_threshold: f64,
}

impl DataShapeClassifier {
    pub fn new() -> Self {
        Self {
            entropy_threshold: 4.5,
        }
    }

    /// Classify each value as potentially credential-shaped.
    /// Returns matches for values that pass entropy and heuristic checks.
    pub fn classify_values(&self, values: &[&str]) -> Vec<ShapeMatch> {
        let mut matches = Vec::new();

        for &value in values {
            if let Some(m) = self.classify_single(value) {
                matches.push(m);
            }
        }

        matches
    }

    fn classify_single(&self, value: &str) -> Option<ShapeMatch> {
        // Length filter
        if value.len() < 16 || value.len() > 512 {
            return None;
        }

        // Natural language filter: skip if >3 spaces
        if value.chars().filter(|&c| c == ' ').count() > 3 {
            return None;
        }

        let entropy = shannon_entropy(value);
        let prefix_match = has_known_prefix(value);

        // Skip below entropy threshold unless it has a known prefix
        if entropy < self.entropy_threshold && !prefix_match {
            return None;
        }

        // Score heuristics
        let has_mixed_case =
            value.chars().any(|c| c.is_uppercase()) && value.chars().any(|c| c.is_lowercase());
        let has_digits = value.chars().any(|c| c.is_ascii_digit());
        let has_special = value.chars().any(|c| {
            matches!(
                c,
                '_' | '-' | '/' | '+' | '=' | '.' | ':' | '@' | '!' | '#' | '$' | '%' | '&' | '*'
            )
        });
        let no_spaces = !value.contains(' ');

        let score = has_mixed_case as u8 + has_digits as u8 + has_special as u8 + no_spaces as u8;

        // Must meet minimum score OR have known prefix
        if score < 3 && !prefix_match {
            return None;
        }

        // Determine confidence
        let confidence = if prefix_match || score == 4 {
            Confidence::High
        } else if score == 3 && entropy > 5.0 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        // Build preview: show first 8 chars + "..."
        // Use char_indices to avoid panicking on multi-byte UTF-8 boundaries.
        let preview = if value.len() > 12 {
            let end = value
                .char_indices()
                .take(8)
                .last()
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(value.len());
            format!("{}...", &value[..end])
        } else {
            value.to_owned()
        };

        let reason = if prefix_match {
            "known credential prefix".to_owned()
        } else {
            format!("high entropy ({:.2}), score {}/4", entropy, score)
        };

        Some(ShapeMatch {
            value_preview: preview,
            entropy,
            length: value.len(),
            confidence,
            reason,
        })
    }
}

impl Default for DataShapeClassifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate Shannon entropy of a byte string.
/// Returns 0.0 for empty input.
pub fn shannon_entropy(data: &str) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for byte in data.bytes() {
        freq[byte as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Check whether the value starts with a known credential prefix.
pub fn has_known_prefix(value: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "sk_",
        "pk_",
        "ghp_",
        "gho_",
        "github_pat_",
        "AKIA",
        "sk-ant-",
        "xoxb-",
        "xoxp-",
        "npm_",
        "eyJ",
        "Bearer ",
        "Basic ",
    ];
    PREFIXES.iter().any(|prefix| value.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_entropy_random_string() {
        // 40 chars with high variety: letters, digits, symbols
        let entropy = shannon_entropy("aB3$xZ9!mK7@pQ2&nW5#rT8^yU1*dF6%hG4+jL0");
        assert!(
            entropy > 4.5,
            "expected entropy > 4.5 for random-looking string, got {}",
            entropy
        );
    }

    #[test]
    fn low_entropy_repeated_string() {
        let entropy = shannon_entropy("aaaaaaa");
        assert!(
            entropy < 1.0,
            "expected entropy < 1.0 for repeated chars, got {}",
            entropy
        );
    }

    #[test]
    fn classifies_api_key_with_known_prefix() {
        let classifier = DataShapeClassifier::new();
        // Value starts with "sk_" (known prefix) and is >= 16 chars
        let values = vec!["sk_live_4eC39HqLyjWDarjtT1zdp7dc"];
        let matches = classifier.classify_values(&values);
        assert!(!matches.is_empty(), "should detect Stripe API key");
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn ignores_natural_language() {
        let classifier = DataShapeClassifier::new();
        let values = vec!["this is a normal English sentence with many words in it"];
        let matches = classifier.classify_values(&values);
        assert!(matches.is_empty(), "should not flag natural language");
    }

    #[test]
    fn classifies_github_pat() {
        let classifier = DataShapeClassifier::new();
        let values = vec!["ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"];
        let matches = classifier.classify_values(&values);
        assert!(!matches.is_empty(), "should detect GitHub PAT");
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn skips_short_values() {
        let classifier = DataShapeClassifier::new();
        let values = vec!["sk_short"];
        let matches = classifier.classify_values(&values);
        assert!(
            matches.is_empty(),
            "should skip values shorter than 16 chars"
        );
    }

    #[test]
    fn detects_high_entropy_no_prefix() {
        let classifier = DataShapeClassifier::new();
        // High entropy, mixed case, digits, special chars, no spaces => score 4
        let values = vec!["Xk9m-2Pq7_Rv5t.Yw3n/Bf8j+Ls4h=Gd6c"];
        let matches = classifier.classify_values(&values);
        assert!(
            !matches.is_empty(),
            "should detect high-entropy credential-like string"
        );
        assert_eq!(matches[0].confidence, Confidence::High);
    }

    #[test]
    fn known_prefix_detection() {
        assert!(has_known_prefix("sk_live_something"));
        assert!(has_known_prefix("AKIAIOSFODNN7EXAMPLE"));
        assert!(has_known_prefix("sk-ant-api03-something"));
        assert!(has_known_prefix("eyJhbGciOiJIUzI1NiJ9"));
        assert!(has_known_prefix("npm_abcdefghijklmnop"));
        assert!(!has_known_prefix("not_a_known_prefix"));
        assert!(!has_known_prefix("random_string_here"));
    }
}
