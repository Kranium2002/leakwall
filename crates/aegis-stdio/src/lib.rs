pub mod jsonrpc;
pub mod pipe;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StdioError {
    #[error("stdio interception error: {0}")]
    Interception(String),

    #[error("JSON-RPC parse error: {0}")]
    JsonRpc(String),

    #[error("process spawn error: {0}")]
    ProcessSpawn(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
