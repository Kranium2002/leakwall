pub mod discovery;
pub mod fingerprint;
pub mod patterns;
pub mod scanner;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use std::path::PathBuf;

#[derive(Error, Debug)]
pub enum SecretError {
    #[error("failed to read secret file: {path}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("pattern compilation failed: {0}")]
    PatternCompile(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("pattern file error: {0}")]
    PatternFile(String),
}

#[derive(Debug, Clone)]
pub struct DiscoveredSecret {
    pub id: Uuid,
    pub name: String,
    pub fingerprints: Vec<Vec<u8>>,
}

/// Severity levels for secret findings.
///
/// Note: This mirrors `leakwall_mcp::Severity` intentionally. Both crates are independent
/// with no shared dependency, so we maintain consistent variants here rather than introducing
/// a shared crate just for this enum.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}
