use base64::Engine;

/// Generate multiple fingerprint variants for a secret value.
///
/// Each fingerprint is a byte pattern that can be used in Aho-Corasick
/// matching to detect the secret in various encodings.
#[must_use]
pub fn generate_fingerprints(value: &str) -> Vec<Vec<u8>> {
    let mut fps = Vec::new();

    // 1. Raw value (exact match)
    fps.push(value.as_bytes().to_vec());

    // 2. URL-encoded (secrets in query strings)
    let url_encoded = urlencoding::encode(value);
    if url_encoded.as_ref() != value {
        fps.push(url_encoded.as_bytes().to_vec());
    }

    // 3. Base64-encoded (secrets in JSON/YAML/XML)
    let b64 = base64::engine::general_purpose::STANDARD.encode(value);
    fps.push(b64.as_bytes().to_vec());

    // 4. For long secrets (>20 chars): prefix + suffix patterns
    if value.len() > 20 {
        fps.push(value.as_bytes()[..16].to_vec());
        fps.push(value.as_bytes()[value.len() - 16..].to_vec());
    }

    // 5. JSON-escaped version (for secrets with special chars)
    if value.contains('"') || value.contains('\\') {
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        fps.push(escaped.as_bytes().to_vec());
    }

    fps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_fingerprints() {
        let fps = generate_fingerprints("short_key");
        // Should have raw, url-encoded (if different), and base64
        assert!(fps.len() >= 2);
        assert_eq!(fps[0], b"short_key");
    }

    #[test]
    fn test_long_secret_has_prefix_suffix() {
        let secret = "this_is_a_very_long_secret_value_12345";
        let fps = generate_fingerprints(secret);
        // Should include prefix and suffix
        let has_prefix = fps.iter().any(|f| f == secret[..16].as_bytes());
        let has_suffix = fps
            .iter()
            .any(|f| f == secret[secret.len() - 16..].as_bytes());
        assert!(has_prefix);
        assert!(has_suffix);
    }

    #[test]
    fn test_special_char_escaping() {
        let secret = r#"key"with\special"#;
        let fps = generate_fingerprints(secret);
        let escaped = fps.iter().any(|f| {
            let s = String::from_utf8_lossy(f);
            s.contains("\\\"") || s.contains("\\\\")
        });
        assert!(escaped);
    }
}
