use crate::{AgentType, ConfigScope, McpConfigLocation, McpError, McpServerConfig};
use std::path::Path;
use tracing::{debug, instrument};

/// Discover MCP configurations across all known agent types.
#[instrument(skip_all)]
pub fn discover_mcp_configs() -> Result<Vec<McpConfigLocation>, McpError> {
    let home = dirs::home_dir()
        .ok_or_else(|| McpError::Config("Could not determine home directory".into()))?;
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut configs = Vec::new();

    // Claude Desktop
    let claude_desktop = if cfg!(target_os = "macos") {
        home.join("Library/Application Support/Claude/claude_desktop_config.json")
    } else if cfg!(target_os = "windows") {
        home.join("AppData/Roaming/Claude/claude_desktop_config.json")
    } else {
        home.join(".config/claude/claude_desktop_config.json")
    };
    try_add(
        &mut configs,
        AgentType::ClaudeDesktop,
        &claude_desktop,
        ConfigScope::Global,
    );

    // Claude Code — global + project
    try_add(
        &mut configs,
        AgentType::ClaudeCode,
        &home.join(".claude/settings.json"),
        ConfigScope::Global,
    );
    // Claude Code stores per-project MCP servers in ~/.claude.json under
    // projects[<project-path>].mcpServers. We treat these as project-scoped.
    try_add_claude_json(&mut configs, &home.join(".claude.json"), &cwd);
    try_add(
        &mut configs,
        AgentType::ClaudeCode,
        &cwd.join(".mcp.json"),
        ConfigScope::Project,
    );
    try_add(
        &mut configs,
        AgentType::ClaudeCode,
        &cwd.join(".claude/settings.json"),
        ConfigScope::Project,
    );

    // Cursor — global + project
    try_add(
        &mut configs,
        AgentType::Cursor,
        &home.join(".cursor/mcp.json"),
        ConfigScope::Global,
    );
    try_add(
        &mut configs,
        AgentType::Cursor,
        &cwd.join(".cursor/mcp.json"),
        ConfigScope::Project,
    );

    // VS Code — global + project
    try_add(
        &mut configs,
        AgentType::VsCode,
        &home.join(".vscode/mcp.json"),
        ConfigScope::Global,
    );
    try_add(
        &mut configs,
        AgentType::VsCode,
        &cwd.join(".vscode/mcp.json"),
        ConfigScope::Project,
    );

    // Windsurf
    try_add(
        &mut configs,
        AgentType::Windsurf,
        &home.join(".windsurf/mcp.json"),
        ConfigScope::Global,
    );

    // Gemini CLI
    try_add(
        &mut configs,
        AgentType::GeminiCli,
        &home.join(".gemini/settings.json"),
        ConfigScope::Global,
    );

    // Continue.dev
    try_add(
        &mut configs,
        AgentType::ContinueDev,
        &home.join(".continue/config.json"),
        ConfigScope::Global,
    );

    debug!(count = configs.len(), "discovered MCP config locations");
    Ok(configs)
}

fn try_add(
    configs: &mut Vec<McpConfigLocation>,
    agent: AgentType,
    path: &Path,
    scope: ConfigScope,
) {
    if path.exists() {
        configs.push(McpConfigLocation {
            agent,
            path: path.to_path_buf(),
            scope,
        });
    }
}

/// Check `~/.claude.json` for per-project MCP servers matching the current working directory.
///
/// Claude Code stores per-project MCP servers in `~/.claude.json` under:
/// `{ "projects": { "/path/to/project": { "mcpServers": { ... } } } }`
///
/// We synthesize a virtual config location so `parse_mcp_servers` can handle it,
/// but since the file format is unique we handle parsing in `discover_all_servers` instead.
fn try_add_claude_json(configs: &mut Vec<McpConfigLocation>, path: &std::path::Path, _cwd: &Path) {
    if path.exists() {
        configs.push(McpConfigLocation {
            agent: AgentType::ClaudeCode,
            path: path.to_path_buf(),
            scope: ConfigScope::Project,
        });
    }
}

/// Parse MCP server configs from a discovered config location.
pub fn parse_mcp_servers(location: &McpConfigLocation) -> Result<Vec<McpServerConfig>, McpError> {
    let content = std::fs::read_to_string(&location.path).map_err(|e| {
        McpError::Discovery(format!("failed to read {}: {e}", location.path.display()))
    })?;

    let value: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        McpError::Discovery(format!(
            "failed to parse JSON {}: {e}",
            location.path.display()
        ))
    })?;

    let mut servers = Vec::new();

    // ~/.claude.json has a special per-project structure:
    // { "projects": { "/path/to/project": { "mcpServers": { ... } } } }
    let is_claude_json = location
        .path
        .file_name()
        .is_some_and(|f| f == ".claude.json");

    if is_claude_json {
        if let Some(projects) = value.get("projects").and_then(|p| p.as_object()) {
            let cwd = std::env::current_dir().unwrap_or_default();
            let cwd_str = cwd.to_string_lossy();
            for (project_path, project_val) in projects {
                // Match if the project path matches our cwd (normalize trailing slashes)
                let proj_normalized = project_path.trim_end_matches('/');
                let cwd_normalized = cwd_str.trim_end_matches('/');
                if proj_normalized != cwd_normalized {
                    continue;
                }
                if let Some(mcp_servers) = project_val.get("mcpServers").and_then(|v| v.as_object())
                {
                    for (name, config) in mcp_servers {
                        let server = parse_single_server(name, config, location);
                        servers.push(server);
                    }
                }
            }
        }
    } else {
        // Standard format: top-level "mcpServers" / "mcp_servers" / "servers"
        if let Some(mcp_servers) = value
            .get("mcpServers")
            .or_else(|| value.get("mcp_servers"))
            .or_else(|| value.get("servers"))
            .and_then(|v| v.as_object())
        {
            for (name, config) in mcp_servers {
                let server = parse_single_server(name, config, location);
                servers.push(server);
            }
        }
    }

    debug!(
        count = servers.len(),
        path = %location.path.display(),
        "parsed MCP servers"
    );
    Ok(servers)
}

fn parse_single_server(
    name: &str,
    config: &serde_json::Value,
    location: &McpConfigLocation,
) -> McpServerConfig {
    let command = config
        .get("command")
        .and_then(|v| v.as_str())
        .map(String::from);

    let args = config
        .get("args")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let env = config
        .get("env")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let url = config.get("url").and_then(|v| v.as_str()).map(String::from);

    McpServerConfig {
        name: name.to_string(),
        command,
        args,
        env,
        url,
        source: location.clone(),
    }
}

/// Discover all MCP servers across all agents and return them grouped by agent.
pub fn discover_all_servers() -> Result<Vec<McpServerConfig>, McpError> {
    let configs = discover_mcp_configs()?;
    let mut all_servers = Vec::new();

    for config in &configs {
        match parse_mcp_servers(config) {
            Ok(servers) => all_servers.extend(servers),
            Err(e) => {
                tracing::warn!(
                    path = %config.path.display(),
                    error = %e,
                    "failed to parse MCP config"
                );
            }
        }
    }

    Ok(all_servers)
}
