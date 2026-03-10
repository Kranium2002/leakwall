use crate::jsonrpc::JsonRpcMessage;
use crate::StdioError;
use leakwall_secrets::scanner::SecretScanner;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::broadcast;
use tracing::{debug, instrument, warn};

/// Events emitted by the stdio interceptor.
#[derive(Clone, Debug)]
pub enum StdioEvent {
    SecretDetected {
        server: String,
        method: String,
        match_count: usize,
    },
    ToolCall {
        server: String,
        tool: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },
    ServerStarted {
        server: String,
    },
    ServerExited {
        server: String,
        exit_code: Option<i32>,
    },
}

/// Intercepts stdin/stdout of MCP server processes to monitor JSON-RPC traffic.
pub struct StdioInterceptor {
    pub scanner: Arc<SecretScanner>,
    pub event_tx: broadcast::Sender<StdioEvent>,
}

/// A handle to a spawned and intercepted MCP server process.
pub struct InterceptedProcess {
    pub child: tokio::process::Child,
}

impl StdioInterceptor {
    /// Create a new interceptor with a secret scanner and event broadcast channel.
    pub fn new(scanner: Arc<SecretScanner>, event_tx: broadcast::Sender<StdioEvent>) -> Self {
        Self { scanner, event_tx }
    }

    /// Spawn an MCP server command and begin intercepting its stdout.
    ///
    /// Reads lines from stdout, parses them as JSON-RPC messages, scans for
    /// secrets, and emits events via the broadcast channel.
    #[instrument(skip(self, env), fields(server = %server_name))]
    pub async fn intercept(
        &self,
        server_name: &str,
        command: &str,
        args: &[String],
        env: &std::collections::HashMap<String, String>,
    ) -> Result<InterceptedProcess, StdioError> {
        use std::process::Stdio;

        let mut cmd = Command::new(command);
        cmd.args(args)
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| StdioError::Interception("failed to capture stdout".into()))?;

        let tx = self.event_tx.clone();
        let scanner = Arc::clone(&self.scanner);
        let name = server_name.to_string();

        // Emit server started event
        let _ = tx.send(StdioEvent::ServerStarted {
            server: name.clone(),
        });
        debug!("server process spawned");

        // Background task to read and inspect stdout lines
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut line_buf = String::new();
            const MAX_LINE_LEN: usize = 10 * 1024 * 1024; // 10 MB

            loop {
                line_buf.clear();
                match reader.read_line(&mut line_buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) if n > MAX_LINE_LEN => {
                        warn!(bytes = n, "skipping oversized line from MCP server");
                        continue;
                    }
                    Ok(_) => {
                        let line = line_buf.trim_end();
                        if line.is_empty() {
                            continue;
                        }

                        match JsonRpcMessage::parse(line) {
                            Ok(msg) => {
                                process_message(&msg, &name, &scanner, &tx);
                            }
                            Err(e) => {
                                debug!(error = %e, "non-JSON-RPC line on stdout");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "error reading stdout");
                        break;
                    }
                }
            }
            debug!(server = %name, "stdout reader finished");
        });

        // Background task to monitor process exit
        let tx_exit = self.event_tx.clone();
        let exit_name = server_name.to_string();
        let child_id = child.id();
        tokio::spawn(async move {
            // We need a mutable reference to the child to wait, but we've
            // already moved it into InterceptedProcess. Instead, the caller
            // should monitor exit via the child handle. We emit exit events
            // from the child handle's perspective. For now, log the PID.
            debug!(
                server = %exit_name,
                pid = ?child_id,
                "monitoring process started"
            );
            // Exit monitoring is handled by the caller via InterceptedProcess.child
            let _ = tx_exit;
        });

        Ok(InterceptedProcess { child })
    }
}

/// Inspect a parsed JSON-RPC message for tool calls and secrets.
fn process_message(
    msg: &JsonRpcMessage,
    server: &str,
    scanner: &SecretScanner,
    tx: &broadcast::Sender<StdioEvent>,
) {
    // Track tool calls
    if msg.is_tool_call() {
        if let Some(tool_name) = msg.tool_name() {
            debug!(server, tool = %tool_name, "tool call detected");
            let _ = tx.send(StdioEvent::ToolCall {
                server: server.to_string(),
                tool: tool_name,
                timestamp: chrono::Utc::now(),
            });
        }
    }

    // Scan the entire message JSON for secrets
    let method = msg.method.as_deref().unwrap_or("response");

    let json_bytes = match serde_json::to_vec(msg) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "failed to serialize message for scanning");
            return;
        }
    };

    let result = scanner.scan(&json_bytes);
    if !result.is_clean() {
        let match_count = result.matches.len();
        debug!(
            server,
            method, match_count, "secrets detected in JSON-RPC message"
        );
        let _ = tx.send(StdioEvent::SecretDetected {
            server: server.to_string(),
            method: method.to_string(),
            match_count,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leakwall_secrets::scanner::SecretScanner;

    fn empty_scanner() -> Arc<SecretScanner> {
        Arc::new(SecretScanner::from_patterns(vec![]))
    }

    #[test]
    fn test_process_message_tool_call() {
        let (tx, mut rx) = broadcast::channel(16);
        let scanner = empty_scanner();

        let msg = JsonRpcMessage {
            jsonrpc: Some("2.0".into()),
            id: Some(serde_json::json!(1)),
            method: Some("tools/call".into()),
            params: Some(serde_json::json!({"name": "read_file"})),
            result: None,
            error: None,
        };

        process_message(&msg, "test-server", &scanner, &tx);

        let event = rx.try_recv().unwrap();
        match event {
            StdioEvent::ToolCall { server, tool, .. } => {
                assert_eq!(server, "test-server");
                assert_eq!(tool, "read_file");
            }
            _ => panic!("expected ToolCall event"),
        }
    }

    #[test]
    fn test_process_message_no_event_for_response() {
        let (tx, mut rx) = broadcast::channel(16);
        let scanner = empty_scanner();

        let msg = JsonRpcMessage {
            jsonrpc: Some("2.0".into()),
            id: Some(serde_json::json!(1)),
            method: None,
            params: None,
            result: Some(serde_json::json!({"tools": []})),
            error: None,
        };

        process_message(&msg, "test-server", &scanner, &tx);

        // Should not get a ToolCall event
        match rx.try_recv() {
            Err(broadcast::error::TryRecvError::Empty) => {}
            Ok(StdioEvent::ToolCall { .. }) => {
                panic!("should not emit ToolCall for a response");
            }
            _ => {}
        }
    }

    #[test]
    fn test_interceptor_creation() {
        let scanner = empty_scanner();
        let (tx, _rx) = broadcast::channel(16);
        let interceptor = StdioInterceptor::new(scanner, tx);
        // Verify scanner is shared properly
        assert_eq!(Arc::strong_count(&interceptor.scanner), 1);
    }
}
