pub mod daemon;
pub mod mcp_monitor;
pub mod notifier;
pub mod secret_monitor;
pub mod skills_monitor;
pub mod watcher;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use std::path::PathBuf;

#[derive(Error, Debug)]
pub enum WatchError {
    #[error("daemon error: {0}")]
    Daemon(String),

    #[error("watcher error: {0}")]
    Watcher(String),

    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("notification error: {0}")]
    Notification(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct WatchConfig {
    pub mcp_config_paths: Vec<PathBuf>,
    pub skills_directories: Vec<PathBuf>,
    pub secret_files: Vec<PathBuf>,
    pub agent_config_paths: Vec<PathBuf>,
    pub tool_hash_file: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum WatchEvent {
    McpConfigChanged {
        path: PathBuf,
        agent: String,
        change: ConfigChange,
    },
    ToolHashChanged {
        server_name: String,
        tool_name: String,
        old_hash: String,
        new_hash: String,
    },
    SkillChanged {
        path: PathBuf,
        change: FileChange,
    },
    SecretFileChanged {
        path: PathBuf,
        new_secret_count: usize,
    },
    AgentConfigWeakened {
        agent: String,
        setting: String,
        old_value: String,
        new_value: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConfigChange {
    ServerAdded { name: String },
    ServerRemoved { name: String },
    ServerModified { name: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FileChange {
    Created,
    Modified,
    Deleted,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method")]
pub enum DaemonRequest {
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "trigger_scan")]
    TriggerScan,
    #[serde(rename = "pause")]
    Pause,
    #[serde(rename = "resume")]
    Resume,
    #[serde(rename = "stop")]
    Stop,
    #[serde(rename = "get_events")]
    GetEvents { since: Option<String> },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DaemonResponse {
    pub success: bool,
    pub data: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub pid_file: PathBuf,
    pub log_file: PathBuf,
    pub socket_path: PathBuf,
}
