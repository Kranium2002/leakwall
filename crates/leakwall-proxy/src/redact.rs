use bytes::Bytes;
use leakwall_secrets::scanner::{SecretMatch, SecretScanner};
use std::sync::Arc;

/// JSON-aware redaction: parse the body as JSON, scan each decoded string
/// value for secrets, replace matches, and re-serialize. This avoids
/// breaking JSON escape sequences that byte-level replacement would corrupt.
///
/// Returns the redacted body and the number of actual replacements made.
pub fn redact_json_body(body: &[u8], scanner: &Arc<SecretScanner>) -> (Bytes, usize) {
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(body) else {
        // Not valid JSON — fall back to byte-level redaction
        let result = scanner.scan(body);
        let count = result.matches.len();
        return (Bytes::from(redact_body(body, &result.matches)), count);
    };

    let mut count = 0;
    redact_json_value(&mut json, scanner, &mut count);

    let bytes = serde_json::to_vec(&json)
        .map(Bytes::from)
        .unwrap_or_else(|_| Bytes::from(body.to_vec()));
    (bytes, count)
}

/// Recursively walk a JSON value and redact secrets in all string values.
fn redact_json_value(
    value: &mut serde_json::Value,
    scanner: &Arc<SecretScanner>,
    count: &mut usize,
) {
    match value {
        serde_json::Value::String(s) => {
            let result = scanner.scan(s.as_bytes());
            if !result.is_clean() {
                // Replace matches in the decoded string (no JSON escaping issues)
                let mut redacted = s.clone();
                let mut sorted = result.matches.clone();
                sorted.sort_by(|a, b| b.byte_offset.cmp(&a.byte_offset));
                for m in &sorted {
                    let end = m.byte_offset + m.match_length;
                    if end <= redacted.len()
                        && redacted.is_char_boundary(m.byte_offset)
                        && redacted.is_char_boundary(end)
                    {
                        let replacement = format!("[LEAKWALL:{}:REDACTED]", m.pattern_name);
                        redacted.replace_range(m.byte_offset..end, &replacement);
                        *count += 1;
                    }
                }
                *s = redacted;
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr.iter_mut() {
                redact_json_value(item, scanner, count);
            }
        }
        serde_json::Value::Object(map) => {
            for (_key, val) in map.iter_mut() {
                redact_json_value(val, scanner, count);
            }
        }
        _ => {}
    }
}

/// Redact secrets from a request body, replacing matched regions
/// with `[LEAKWALL:<pattern_name>:REDACTED]` markers.
///
/// Matches are processed in reverse byte-offset order to preserve
/// positions during replacement.
pub fn redact_body(body: &[u8], matches: &[SecretMatch]) -> Vec<u8> {
    let mut result = body.to_vec();

    // Sort by byte offset in reverse so replacements don't shift earlier offsets
    let mut sorted: Vec<&SecretMatch> = matches.iter().collect();
    sorted.sort_by(|a, b| b.byte_offset.cmp(&a.byte_offset));

    for m in &sorted {
        let replacement = format!("[LEAKWALL:{}:REDACTED]", m.pattern_name);
        let end = m.byte_offset + m.match_length;
        if end <= result.len() {
            result.splice(m.byte_offset..end, replacement.bytes());
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use leakwall_secrets::scanner::MatchSource;
    use leakwall_secrets::Severity;

    #[test]
    fn test_single_redaction() {
        let body = b"my key is AKIAIOSFODNN7EXAMPLE ok";
        let matches = vec![SecretMatch {
            pattern_name: "aws_access_key".into(),
            matched_text_preview: "AKIAIOOS...".into(),
            byte_offset: 10,
            match_length: 20,
            source: MatchSource::Pattern,
            severity: Severity::Critical,
        }];
        let redacted = redact_body(body, &matches);
        let result = String::from_utf8(redacted).unwrap();
        assert!(result.contains("[LEAKWALL:aws_access_key:REDACTED]"));
        assert!(!result.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_multiple_redactions() {
        let body = b"key1=SECRET1 and key2=SECRET2";
        let matches = vec![
            SecretMatch {
                pattern_name: "key1".into(),
                matched_text_preview: "SECRET1...".into(),
                byte_offset: 5,
                match_length: 7,
                source: MatchSource::Known,
                severity: Severity::Critical,
            },
            SecretMatch {
                pattern_name: "key2".into(),
                matched_text_preview: "SECRET2...".into(),
                byte_offset: 22,
                match_length: 7,
                source: MatchSource::Known,
                severity: Severity::Critical,
            },
        ];
        let redacted = redact_body(body, &matches);
        let result = String::from_utf8(redacted).unwrap();
        assert!(result.contains("[LEAKWALL:key1:REDACTED]"));
        assert!(result.contains("[LEAKWALL:key2:REDACTED]"));
        assert!(!result.contains("SECRET1"));
        assert!(!result.contains("SECRET2"));
    }

    #[test]
    fn test_no_matches_returns_unchanged() {
        let body = b"normal body with no secrets";
        let redacted = redact_body(body, &[]);
        assert_eq!(redacted, body);
    }
}
