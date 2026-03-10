use anyhow::{Context, Result};
use colored::Colorize;
use leakwall_watch::{DaemonConfig, DaemonRequest, WatchConfig};
use std::path::Path;

/// Run the `leakwall watch` command — continuous monitoring daemon.
pub async fn run_watch(
    lw_dir: &Path,
    daemon: bool,
    foreground: bool,
    status: bool,
    stop: bool,
    quiet: bool,
) -> Result<()> {
    let config = DaemonConfig {
        pid_file: lw_dir.join("leakwall.pid"),
        log_file: lw_dir.join("daemon.log"),
        socket_path: lw_dir.join("leakwall.sock"),
    };

    if status {
        return query_status(&config).await;
    }

    if stop {
        return stop_daemon(&config).await;
    }

    // Build watch config from discovery
    let watch_config = build_watch_config(lw_dir)?;

    let mcp_count = watch_config.mcp_config_paths.len();
    let skills_count = watch_config.skills_directories.len();
    let secret_count = watch_config.secret_files.len();

    if daemon || foreground {
        if !quiet {
            println!("{}", "Starting leakwall daemon...".bold());
            println!(
                "  Watching: {} MCP configs, {} skills dirs, {} secret files",
                mcp_count, skills_count, secret_count
            );
            println!(
                "  Socket: {}",
                config.socket_path.display().to_string().cyan()
            );
            println!("  Log:    {}", config.log_file.display().to_string().cyan());
        }

        leakwall_watch::daemon::start_daemon(&config, watch_config)
            .await
            .context("daemon failed")?;
    } else {
        println!(
            "{}",
            "Usage: leakwall watch --daemon | --status | --stop".dimmed()
        );
        println!("  --daemon      Start background monitoring");
        println!("  --foreground  Start in foreground (for debugging)");
        println!("  --status      Query daemon status");
        println!("  --stop        Stop the daemon");
    }

    Ok(())
}

async fn query_status(config: &DaemonConfig) -> Result<()> {
    let response =
        leakwall_watch::daemon::send_daemon_command(&config.socket_path, DaemonRequest::Status)
            .await
            .context("leakwall daemon not running. Start with: leakwall watch --daemon")?;

    if response.success {
        println!("{}", "leakwall daemon running".green().bold());
        if let Some(uptime) = response.data.get("uptime_seconds") {
            let secs = uptime.as_u64().unwrap_or(0);
            let hours = secs / 3600;
            let mins = (secs % 3600) / 60;
            println!("  Uptime: {}h {}m", hours, mins);
        }
        if let Some(events) = response.data.get("events_detected") {
            println!("  Events detected: {}", events.as_u64().unwrap_or(0));
        }
    } else {
        println!(
            "{}: {}",
            "Error".red(),
            response.error.unwrap_or_else(|| "unknown error".into())
        );
    }

    Ok(())
}

async fn stop_daemon(config: &DaemonConfig) -> Result<()> {
    let response =
        leakwall_watch::daemon::send_daemon_command(&config.socket_path, DaemonRequest::Stop)
            .await
            .context("leakwall daemon not running. Nothing to stop.")?;

    if response.success {
        println!("{}", "leakwall daemon stopped.".green().bold());
    } else {
        println!(
            "{}: {}",
            "Error".red(),
            response.error.unwrap_or_else(|| "unknown error".into())
        );
    }

    Ok(())
}

fn build_watch_config(lw_dir: &Path) -> Result<WatchConfig> {
    let home = dirs::home_dir().unwrap_or_default();
    let cwd = std::env::current_dir().unwrap_or_default();

    // Discover MCP config paths
    let mcp_configs = leakwall_mcp::discover::discover_mcp_configs()
        .unwrap_or_default()
        .into_iter()
        .map(|loc| loc.path)
        .collect::<Vec<_>>();

    // Skills directories
    let mut skills_dirs = vec![];
    let claude_global = home.join(".claude/skills");
    if claude_global.is_dir() {
        skills_dirs.push(claude_global);
    }
    let claude_project = cwd.join(".claude/skills");
    if claude_project.is_dir() {
        skills_dirs.push(claude_project);
    }

    // Secret files
    let mut secret_files = vec![];
    for name in &[".env", ".env.local", ".env.production"] {
        let p = cwd.join(name);
        if p.exists() {
            secret_files.push(p);
        }
        let h = home.join(name);
        if h.exists() {
            secret_files.push(h);
        }
    }
    let aws_creds = home.join(".aws/credentials");
    if aws_creds.exists() {
        secret_files.push(aws_creds);
    }

    Ok(WatchConfig {
        mcp_config_paths: mcp_configs,
        skills_directories: skills_dirs,
        secret_files,
        agent_config_paths: vec![],
        tool_hash_file: lw_dir.join("tool_hashes.json"),
    })
}
