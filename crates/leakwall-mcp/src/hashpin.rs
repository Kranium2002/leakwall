use crate::{HashChange, HashChangeType, ServerIdentity, ToolDefinition};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{debug, warn};

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolHash {
    pub server_name: String,
    pub tool_name: String,
    pub hash: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct HashStore {
    pub hashes: HashMap<String, ToolHash>,
}

/// Check tool definitions against stored hash pins.
#[must_use]
pub fn check_hash_pins(identity: &ServerIdentity, tools: &[ToolDefinition]) -> Vec<HashChange> {
    let stored = load_stored_hashes();
    let mut changes = Vec::new();
    let prefix = format!("{}:", identity.name);

    for tool in tools {
        let current_hash = match sha256_tool(tool) {
            Ok(h) => h,
            Err(e) => {
                warn!(tool = %tool.name, error = %e, "skipping tool: hash computation failed");
                continue;
            }
        };
        let key = format!("{prefix}{}", tool.name);

        match stored.hashes.get(&key) {
            Some(stored_hash) if stored_hash.hash != current_hash => {
                changes.push(HashChange {
                    tool_name: tool.name.clone(),
                    change_type: HashChangeType::Modified,
                    previous_hash: Some(stored_hash.hash.clone()),
                    current_hash: current_hash.clone(),
                    first_seen: Some(stored_hash.first_seen),
                });
            }
            None => {
                changes.push(HashChange {
                    tool_name: tool.name.clone(),
                    change_type: HashChangeType::NewTool,
                    previous_hash: None,
                    current_hash: current_hash.clone(),
                    first_seen: None,
                });
            }
            _ => {} // Hash matches, no change
        }
    }

    // Detect removed tools: stored hashes for this server that have no matching current tool
    let current_tool_names: std::collections::HashSet<&str> =
        tools.iter().map(|t| t.name.as_str()).collect();
    for (key, stored_hash) in &stored.hashes {
        if let Some(tool_name) = key.strip_prefix(&prefix) {
            if !current_tool_names.contains(tool_name) {
                changes.push(HashChange {
                    tool_name: tool_name.to_string(),
                    change_type: HashChangeType::Removed,
                    previous_hash: Some(stored_hash.hash.clone()),
                    current_hash: String::new(),
                    first_seen: Some(stored_hash.first_seen),
                });
            }
        }
    }

    // Update stored hashes
    save_hashes(identity, tools);

    debug!(
        server = %identity.name,
        changes = changes.len(),
        "hash pin check complete"
    );
    changes
}

/// Compute SHA-256 hash of a tool's full JSON definition.
fn sha256_tool(tool: &ToolDefinition) -> Result<String, crate::McpError> {
    let json = serde_json::to_string(tool)
        .map_err(|e| crate::McpError::Serialization(format!("hash serialization: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn hash_store_path() -> Option<std::path::PathBuf> {
    Some(dirs::home_dir()?.join(".leakwall/tool_hashes.json"))
}

fn load_stored_hashes() -> HashStore {
    use std::io::Read;

    let path = match hash_store_path() {
        Some(p) => p,
        None => return HashStore::default(),
    };

    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return HashStore::default(),
    };

    if <std::fs::File as fs2::FileExt>::lock_shared(&file).is_err() {
        return HashStore::default();
    }

    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_ok() {
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        HashStore::default()
    }
    // Lock released when file dropped
}

fn save_hashes(identity: &ServerIdentity, tools: &[ToolDefinition]) {
    use fs2::FileExt;
    use std::io::{Read, Seek, SeekFrom, Write};

    let path = match hash_store_path() {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Open or create the file, then acquire exclusive lock to prevent TOCTOU
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    {
        Ok(f) => f,
        Err(_) => return,
    };

    if file.lock_exclusive().is_err() {
        return;
    }

    // Read current contents from the locked file handle
    let mut contents = String::new();
    let mut store: HashStore = if file.read_to_string(&mut contents).is_ok() {
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        HashStore::default()
    };

    let now = Utc::now();
    let prefix = format!("{}:", identity.name);

    // Remove stale entries for this server (tools that no longer exist)
    let current_tool_names: std::collections::HashSet<&str> =
        tools.iter().map(|t| t.name.as_str()).collect();
    store.hashes.retain(|key, _| {
        if let Some(tool_name) = key.strip_prefix(&prefix) {
            current_tool_names.contains(tool_name)
        } else {
            true // Keep entries for other servers
        }
    });

    for tool in tools {
        let key = format!("{prefix}{}", tool.name);
        let current_hash = match sha256_tool(tool) {
            Ok(h) => h,
            Err(e) => {
                warn!(tool = %tool.name, error = %e, "skipping tool: hash serialization failed");
                continue;
            }
        };

        let entry = store.hashes.entry(key).or_insert_with(|| ToolHash {
            server_name: identity.name.clone(),
            tool_name: tool.name.clone(),
            hash: current_hash.clone(),
            first_seen: now,
            last_seen: now,
        });

        entry.hash = current_hash;
        entry.last_seen = now;
    }

    if let Ok(json) = serde_json::to_string_pretty(&store) {
        // Truncate and rewrite using the already-locked file handle
        let _ = file.set_len(0);
        let _ = file.seek(SeekFrom::Start(0));
        let _ = file.write_all(json.as_bytes());
    }

    // Restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    // Lock is released when `file` is dropped
    drop(file);
}
