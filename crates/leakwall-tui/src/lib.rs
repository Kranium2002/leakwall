pub mod dashboard;
pub mod events;
pub mod monitor;
pub mod report;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TuiError {
    #[error("terminal error: {0}")]
    Terminal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("render error: {0}")]
    Render(String),
}
