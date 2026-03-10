pub mod allowlist;
pub mod data_shape;
pub mod profile;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BehaviorError {
    #[error("behavioral analysis error: {0}")]
    Analysis(String),

    #[error("allowlist configuration error: {0}")]
    Allowlist(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Anomaly {
    pub kind: AnomalyKind,
    pub severity: Severity,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnomalyKind {
    NewDestination,
    VolumeSpike,
    BurstActivity,
    HighEntropyPayload,
    SensitiveDataShape,
}

impl std::fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewDestination => write!(f, "New Destination"),
            Self::VolumeSpike => write!(f, "Volume Spike"),
            Self::BurstActivity => write!(f, "Burst Activity"),
            Self::HighEntropyPayload => write!(f, "High Entropy Payload"),
            Self::SensitiveDataShape => write!(f, "Sensitive Data Shape"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

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
