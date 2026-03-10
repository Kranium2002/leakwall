pub mod ca;
pub mod intercept;
pub mod process;
pub mod proxy;
pub mod redact;
pub mod stream;

use chrono::{DateTime, Utc};
use leakwall_secrets::scanner::ScanResult;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, RwLock};
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("CA certificate error: {0}")]
    CaError(String),

    #[error("proxy bind error: {0}")]
    BindError(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("process spawn error: {0}")]
    ProcessSpawn(String),

    #[error("SSE stream error: {0}")]
    SseStream(String),

    #[error("body size limit exceeded: {size} bytes (max {limit})")]
    BodyTooLarge { size: usize, limit: usize },
}

/// Proxy event emitted to TUI and loggers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProxyEvent {
    RequestIntercepted {
        timestamp: DateTime<Utc>,
        host: String,
        method: String,
        path: String,
        body_size: usize,
        scan_result: ScanResult,
        action: Action,
    },
    AgentStarted {
        pid: u32,
        command: String,
    },
    AgentExited {
        pid: u32,
        exit_code: Option<i32>,
    },
    ProxyError {
        message: String,
    },
}

/// Action taken for a request based on scan results and config.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Action {
    Passed,
    Warned,
    Redacted { count: usize },
    Blocked,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passed => write!(f, "OK"),
            Self::Warned => write!(f, "WARNED"),
            Self::Redacted { count } => write!(f, "REDACTED ({count})"),
            Self::Blocked => write!(f, "BLOCKED"),
        }
    }
}

/// Scan mode determining action on secret detection.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum ScanMode {
    WarnOnly,
    #[default]
    Redact,
    Block,
}

impl std::fmt::Display for ScanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WarnOnly => write!(f, "WARN"),
            Self::Redact => write!(f, "REDACT"),
            Self::Block => write!(f, "BLOCK"),
        }
    }
}

/// Request log entry for session reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLog {
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub method: String,
    pub path: String,
    pub body_size: usize,
    pub matches_count: usize,
    pub action: Action,
}

/// Default maximum body size for scanning (50 MB).
pub const DEFAULT_MAX_BODY_SIZE: usize = 50 * 1024 * 1024;

/// Shared proxy state accessible across async tasks.
pub struct ProxyState {
    pub scanner: Arc<leakwall_secrets::scanner::SecretScanner>,
    pub mode: Arc<RwLock<ScanMode>>,
    pub event_tx: broadcast::Sender<ProxyEvent>,
    pub session_log: Arc<RwLock<Vec<RequestLog>>>,
    pub cert_cache: Arc<dashmap::DashMap<String, Arc<CertifiedKeyPair>>>,
    pub ca_cert_pem: String,
    pub ca_key_pem: Zeroizing<String>,
    pub proxy_port: u16,
    pub max_body_size: usize,
    pub http_client: reqwest::Client,
    /// Random token for proxy authentication (Basic auth with username "leakwall").
    pub proxy_token: String,
}

/// Generate a random 32-byte hex proxy token.
pub fn generate_proxy_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}

/// A certificate + key pair for TLS.
pub struct CertifiedKeyPair {
    pub cert_pem: String,
    pub key_pem: Zeroizing<String>,
}

/// Domains to intercept (LLM/agent API endpoints).
pub const INTERCEPT_DOMAINS: &[&str] = &[
    "api.anthropic.com",
    "api.openai.com",
    "api.groq.com",
    "api.mistral.ai",
    "api.together.xyz",
    "api.fireworks.ai",
    "generativelanguage.googleapis.com",
    "api.cohere.com",
    "api.deepseek.com",
];

/// Check if a host should be intercepted for MITM.
#[must_use]
pub fn should_intercept(host: &str) -> bool {
    let host = host.to_lowercase();
    INTERCEPT_DOMAINS
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")))
}
