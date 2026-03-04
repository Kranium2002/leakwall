use crate::{
    McpError, McpServerConfig, SchemaProperty, ServerIdentity, ToolDefinition, ToolSchema,
};
use std::collections::HashMap;
use tracing::{debug, instrument, warn};

/// Extract server identity from config.
pub fn extract_identity(server: &McpServerConfig) -> ServerIdentity {
    let package_name = server.command.as_ref().and_then(|cmd| {
        if cmd.contains("npx") || cmd.contains("npm") {
            // Find the first arg that looks like a package name (skip flags like -y, --yes)
            server.args.iter().find(|a| !a.starts_with('-')).cloned()
        } else {
            Some(cmd.clone())
        }
    });

    ServerIdentity {
        name: server.name.clone(),
        version: None, // Would need to run server to get version
        package_name,
    }
}

/// Connect to an MCP server and list its tools.
///
/// The caller is responsible for deciding whether to call this function.
/// Pre-execution command analysis in `audit_mcp_server()` gates execution.
#[instrument(skip_all, fields(server = %server.name))]
pub async fn connect_and_list_tools(
    server: &McpServerConfig,
) -> Result<Vec<ToolDefinition>, McpError> {
    // For stdio-based servers, we'd need to spawn the process and
    // communicate via JSON-RPC over stdin/stdout.
    // For HTTP-based servers, we'd make HTTP requests.

    // For now, try to connect via stdio if command is available
    if let Some(ref command) = server.command {
        debug!(command = %command, "attempting stdio connection");
        match connect_stdio(command, &server.args, &server.env).await {
            Ok(tools) => return Ok(tools),
            Err(e) => {
                warn!(error = %e, "stdio connection failed, returning empty tools");
            }
        }
    }

    if let Some(ref url) = server.url {
        debug!(url = %url, "attempting HTTP connection");
        match connect_http(url).await {
            Ok(tools) => return Ok(tools),
            Err(e) => {
                warn!(error = %e, "HTTP connection failed, returning empty tools");
            }
        }
    }

    Ok(vec![])
}

/// Connect to an MCP server via stdio (spawn process, JSON-RPC).
async fn connect_stdio(
    command: &str,
    args: &[String],
    env: &HashMap<String, String>,
) -> Result<Vec<ToolDefinition>, McpError> {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;

    let mut cmd = Command::new(command);
    cmd.args(args)
        .envs(env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let mut child = cmd
        .spawn()
        .map_err(|e| McpError::Connection(format!("failed to spawn {command}: {e}")))?;

    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| McpError::Connection("failed to get stdin".into()))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| McpError::Connection("failed to get stdout".into()))?;

    // Send initialize request
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "aegis",
                "version": "0.1.0"
            }
        }
    });

    let msg = format!(
        "{}\n",
        serde_json::to_string(&init_req).map_err(|e| { McpError::Serialization(e.to_string()) })?
    );
    stdin
        .write_all(msg.as_bytes())
        .await
        .map_err(|e| McpError::Connection(format!("write error: {e}")))?;

    let mut reader = BufReader::new(stdout);
    let mut line = String::new();

    // Read initialize response with timeout
    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_line(&mut line),
    )
    .await;

    match read_result {
        Ok(Ok(_)) => {
            debug!("received initialize response");
        }
        Ok(Err(e)) => {
            let _ = child.kill().await;
            return Err(McpError::Connection(format!("read error: {e}")));
        }
        Err(_) => {
            let _ = child.kill().await;
            return Err(McpError::Connection("initialize timeout".into()));
        }
    }

    // Send initialized notification
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| McpError::Connection("lost stdin".into()))?;
    let notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let msg = format!(
        "{}\n",
        serde_json::to_string(&notif).map_err(|e| { McpError::Serialization(e.to_string()) })?
    );
    stdin
        .write_all(msg.as_bytes())
        .await
        .map_err(|e| McpError::Connection(format!("write error: {e}")))?;

    // Send tools/list request
    let stdin = child
        .stdin
        .as_mut()
        .ok_or_else(|| McpError::Connection("lost stdin".into()))?;
    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    let msg = format!(
        "{}\n",
        serde_json::to_string(&list_req).map_err(|e| { McpError::Serialization(e.to_string()) })?
    );
    stdin
        .write_all(msg.as_bytes())
        .await
        .map_err(|e| McpError::Connection(format!("write error: {e}")))?;

    // Read tools/list response
    line.clear();
    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_line(&mut line),
    )
    .await;

    let _ = child.kill().await;

    match read_result {
        Ok(Ok(_)) => parse_tools_response(&line),
        Ok(Err(e)) => Err(McpError::Connection(format!("read error: {e}"))),
        Err(_) => Err(McpError::Connection("tools/list timeout".into())),
    }
}

/// Parse a JSON-RPC tools/list response into ToolDefinitions.
fn parse_tools_response(response: &str) -> Result<Vec<ToolDefinition>, McpError> {
    let value: serde_json::Value = serde_json::from_str(response)
        .map_err(|e| McpError::Serialization(format!("invalid JSON response: {e}")))?;

    let tools = value
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();

    let mut result = Vec::new();
    for tool in tools {
        let name = tool
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let description = tool
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let input_schema = tool.get("inputSchema").map(|schema| {
            let properties = schema
                .get("properties")
                .and_then(|p| p.as_object())
                .map(|obj| {
                    obj.iter()
                        .map(|(k, v)| {
                            let prop = SchemaProperty {
                                description: v
                                    .get("description")
                                    .and_then(|d| d.as_str())
                                    .map(String::from),
                                default: v.get("default").cloned(),
                                enum_values: v.get("enum").and_then(|e| e.as_array()).map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                }),
                            };
                            (k.clone(), prop)
                        })
                        .collect()
                })
                .unwrap_or_default();
            ToolSchema { properties }
        });

        result.push(ToolDefinition {
            name,
            description,
            input_schema,
        });
    }

    Ok(result)
}

/// Connect via HTTP (for HTTP-based MCP servers).
async fn connect_http(url: &str) -> Result<Vec<ToolDefinition>, McpError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| McpError::Connection(format!("HTTP client error: {e}")))?;

    // Send initialize JSON-RPC request
    let init_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "aegis",
                "version": "0.1.0"
            }
        }
    });

    let init_response = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "aegis/0.1.0")
        .json(&init_req)
        .send()
        .await
        .map_err(|e| McpError::Connection(format!("HTTP initialize request failed: {e}")))?;

    if !init_response.status().is_success() {
        return Err(McpError::Connection(format!(
            "HTTP initialize returned status {}",
            init_response.status()
        )));
    }

    // Parse initialize response to confirm server capabilities
    let _init_body: serde_json::Value = init_response
        .json()
        .await
        .map_err(|e| McpError::Connection(format!("failed to parse initialize response: {e}")))?;

    debug!("HTTP MCP server initialized");

    // Send initialized notification (fire and forget)
    let notif = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let _ = client
        .post(url)
        .header("Content-Type", "application/json")
        .json(&notif)
        .send()
        .await;

    // Send tools/list request
    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });

    let list_response = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("User-Agent", "aegis/0.1.0")
        .json(&list_req)
        .send()
        .await
        .map_err(|e| McpError::Connection(format!("HTTP tools/list request failed: {e}")))?;

    if !list_response.status().is_success() {
        return Err(McpError::Connection(format!(
            "HTTP tools/list returned status {}",
            list_response.status()
        )));
    }

    let body = list_response
        .text()
        .await
        .map_err(|e| McpError::Connection(format!("failed to read tools/list response: {e}")))?;

    parse_tools_response(&body)
}
