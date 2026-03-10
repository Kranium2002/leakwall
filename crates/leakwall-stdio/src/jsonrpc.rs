use crate::StdioError;
use serde::{Deserialize, Serialize};

/// A JSON-RPC 2.0 message used by the MCP protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcMessage {
    pub jsonrpc: Option<String>,
    pub id: Option<serde_json::Value>,
    pub method: Option<String>,
    pub params: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl JsonRpcMessage {
    /// Parse a single line of text as a JSON-RPC message.
    pub fn parse(line: &str) -> Result<Self, StdioError> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err(StdioError::JsonRpc("empty line".into()));
        }
        serde_json::from_str(trimmed)
            .map_err(|e| StdioError::JsonRpc(format!("invalid JSON-RPC: {e}")))
    }

    /// Returns true if this message is a `tools/call` request.
    pub fn is_tool_call(&self) -> bool {
        self.method.as_deref() == Some("tools/call")
    }

    /// Returns true if this message is a `tools/list` request.
    pub fn is_tool_list(&self) -> bool {
        self.method.as_deref() == Some("tools/list")
    }

    /// Extract the tool name from a `tools/call` request's params.
    pub fn tool_name(&self) -> Option<String> {
        if !self.is_tool_call() {
            return None;
        }
        self.params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .map(String::from)
    }

    /// Returns true if this is a JSON-RPC request (has method + id).
    pub fn is_request(&self) -> bool {
        self.method.is_some() && self.id.is_some()
    }

    /// Returns true if this is a JSON-RPC response (has result or error, plus id).
    pub fn is_response(&self) -> bool {
        self.id.is_some() && (self.result.is_some() || self.error.is_some())
    }

    /// Returns true if this is a JSON-RPC notification (has method but no id).
    pub fn is_notification(&self) -> bool {
        self.method.is_some() && self.id.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_tool_call() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "read_file", "arguments": { "path": "/tmp/x" } }
        }"#;
        let msg = JsonRpcMessage::parse(json).unwrap();
        assert_eq!(msg.jsonrpc.as_deref(), Some("2.0"));
        assert!(msg.is_tool_call());
        assert!(msg.is_request());
        assert!(!msg.is_notification());
        assert!(!msg.is_response());
        assert_eq!(msg.tool_name(), Some("read_file".into()));
    }

    #[test]
    fn test_is_tool_call_true() {
        let json = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"exec"}}"#;
        let msg = JsonRpcMessage::parse(json).unwrap();
        assert!(msg.is_tool_call());
    }

    #[test]
    fn test_tool_name_extraction() {
        let json =
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}"#;
        let msg = JsonRpcMessage::parse(json).unwrap();
        assert_eq!(msg.tool_name(), Some("get_weather".into()));
    }

    #[test]
    fn test_tool_name_none_for_non_tool_call() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let msg = JsonRpcMessage::parse(json).unwrap();
        assert!(msg.is_tool_list());
        assert_eq!(msg.tool_name(), None);
    }

    #[test]
    fn test_notification_vs_request() {
        // Notification: has method, no id
        let notif = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let msg = JsonRpcMessage::parse(notif).unwrap();
        assert!(msg.is_notification());
        assert!(!msg.is_request());
        assert!(!msg.is_response());

        // Request: has method + id
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let msg = JsonRpcMessage::parse(req).unwrap();
        assert!(msg.is_request());
        assert!(!msg.is_notification());
    }

    #[test]
    fn test_response_detection() {
        let resp = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let msg = JsonRpcMessage::parse(resp).unwrap();
        assert!(msg.is_response());
        assert!(!msg.is_request());
        assert!(!msg.is_notification());
    }

    #[test]
    fn test_error_response() {
        let resp = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Invalid"}}"#;
        let msg = JsonRpcMessage::parse(resp).unwrap();
        assert!(msg.is_response());
        assert!(msg.error.is_some());
        let err = msg.error.unwrap();
        assert_eq!(err.code, -32600);
        assert_eq!(err.message, "Invalid");
    }

    #[test]
    fn test_parse_empty_line() {
        assert!(JsonRpcMessage::parse("").is_err());
        assert!(JsonRpcMessage::parse("   ").is_err());
    }

    #[test]
    fn test_parse_invalid_json() {
        assert!(JsonRpcMessage::parse("not json").is_err());
    }
}
