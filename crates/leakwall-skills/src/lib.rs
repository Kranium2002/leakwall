pub mod analyze;
pub mod discover;
pub mod parser;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use std::path::PathBuf;

#[derive(Error, Debug)]
pub enum SkillsError {
    #[error("failed to read skill file: {path}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("skill parse error: {0}")]
    Parse(String),

    #[error("skill discovery error: {0}")]
    Discovery(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentType {
    ClaudeCode,
    OpenClaw,
    Aider,
    Custom(String),
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaudeCode => write!(f, "Claude Code"),
            Self::OpenClaw => write!(f, "OpenClaw"),
            Self::Aider => write!(f, "Aider"),
            Self::Custom(name) => write!(f, "{name}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SkillScope {
    Global,
    Project,
}

impl std::fmt::Display for SkillScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Global => write!(f, "GLOBAL"),
            Self::Project => write!(f, "PROJECT"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SkillLocation {
    pub agent: AgentType,
    pub path: PathBuf,
    pub scope: SkillScope,
}

#[derive(Debug, Clone)]
pub struct SkillAnalysis {
    pub path: PathBuf,
    pub agent: AgentType,
    pub scope: SkillScope,
    pub findings: Vec<SkillFinding>,
    pub stats: SkillStats,
}

#[derive(Debug, Clone)]
pub struct SkillFinding {
    pub severity: Severity,
    pub finding_type: SkillFindingType,
    pub line_number: usize,
    pub context: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SkillFindingType {
    ShellCommand,
    ExternalUrl,
    SensitiveFileRead,
    SensitiveFileWrite,
    NetworkExfiltration,
    CredentialAccess,
    PackageInstall,
    ElevatedPermission,
    ObfuscatedContent,
    PromptInjection,
    ReverseShell,
}

impl std::fmt::Display for SkillFindingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShellCommand => write!(f, "Shell Command"),
            Self::ExternalUrl => write!(f, "External URL"),
            Self::SensitiveFileRead => write!(f, "Sensitive File Read"),
            Self::SensitiveFileWrite => write!(f, "Sensitive File Write"),
            Self::NetworkExfiltration => write!(f, "Network Exfiltration"),
            Self::CredentialAccess => write!(f, "Credential Access"),
            Self::PackageInstall => write!(f, "Package Install"),
            Self::ElevatedPermission => write!(f, "Elevated Permission"),
            Self::ObfuscatedContent => write!(f, "Obfuscated Content"),
            Self::PromptInjection => write!(f, "Prompt Injection"),
            Self::ReverseShell => write!(f, "Reverse Shell"),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SkillStats {
    pub line_count: usize,
    pub shell_commands: usize,
    pub external_urls: usize,
    pub file_references: usize,
    pub complexity_score: u32,
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
