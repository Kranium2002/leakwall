use crate::ConfigChange;

/// Compare two MCP config JSON strings and return a list of changes
/// to the "mcpServers" section.
pub fn diff_mcp_config(old_content: &str, new_content: &str) -> Vec<ConfigChange> {
    let old: serde_json::Value = serde_json::from_str(old_content).unwrap_or_default();
    let new: serde_json::Value = serde_json::from_str(new_content).unwrap_or_default();

    let old_servers = old
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let new_servers = new
        .get("mcpServers")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    let mut changes = Vec::new();

    // Detect added and modified servers
    for (name, new_val) in &new_servers {
        match old_servers.get(name) {
            None => {
                changes.push(ConfigChange::ServerAdded { name: name.clone() });
            }
            Some(old_val) if old_val != new_val => {
                changes.push(ConfigChange::ServerModified { name: name.clone() });
            }
            _ => {}
        }
    }

    // Detect removed servers
    for name in old_servers.keys() {
        if !new_servers.contains_key(name) {
            changes.push(ConfigChange::ServerRemoved { name: name.clone() });
        }
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_detects_added_server() {
        let old = r#"{"mcpServers": {"a": {"cmd": "a"}}}"#;
        let new = r#"{"mcpServers": {"a": {"cmd": "a"}, "b": {"cmd": "b"}}}"#;

        let changes = diff_mcp_config(old, new);
        assert!(changes.iter().any(|c| matches!(
            c,
            ConfigChange::ServerAdded { name } if name == "b"
        )));
    }

    #[test]
    fn test_diff_detects_removed_server() {
        let old = r#"{"mcpServers": {"a": {"cmd": "a"}, "b": {"cmd": "b"}}}"#;
        let new = r#"{"mcpServers": {"a": {"cmd": "a"}}}"#;

        let changes = diff_mcp_config(old, new);
        assert!(changes.iter().any(|c| matches!(
            c,
            ConfigChange::ServerRemoved { name } if name == "b"
        )));
    }

    #[test]
    fn test_diff_detects_modified_server() {
        let old = r#"{"mcpServers": {"a": {"cmd": "old"}}}"#;
        let new = r#"{"mcpServers": {"a": {"cmd": "new"}}}"#;

        let changes = diff_mcp_config(old, new);
        assert_eq!(changes.len(), 1);
        assert!(matches!(
            &changes[0],
            ConfigChange::ServerModified { name } if name == "a"
        ));
    }

    #[test]
    fn test_diff_no_changes() {
        let content = r#"{"mcpServers": {"a": {"cmd": "a"}}}"#;
        let changes = diff_mcp_config(content, content);
        assert!(changes.is_empty());
    }

    #[test]
    fn test_diff_invalid_json_returns_empty() {
        let changes = diff_mcp_config("not json", "also not json");
        assert!(changes.is_empty());
    }
}
