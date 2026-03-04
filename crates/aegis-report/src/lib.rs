pub mod cost;
pub mod html;
pub mod json;
pub mod sarif;
pub mod trend;

use thiserror::Error;

use std::path::PathBuf;

#[derive(Error, Debug)]
pub enum ReportError {
    #[error("template rendering error: {0}")]
    Template(String),

    #[error("report generation error: {0}")]
    Generation(String),

    #[error("failed to read report file: {path}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
