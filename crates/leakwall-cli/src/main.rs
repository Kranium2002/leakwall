mod cmd_monitor;
mod cmd_report;
mod cmd_run;
mod cmd_scan;
mod cmd_watch;
mod config;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "leakwall", version, about = "AI agent security platform")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Config file path (default: ./leakwall.toml or ~/.leakwall/config.toml)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit agent security posture (MCP servers, configs, skills, exposure)
    Scan {
        /// Force fresh registry lookups (ignore cache)
        #[arg(long)]
        refresh: bool,

        /// Output JSON report to file
        #[arg(long)]
        json: Option<PathBuf>,

        /// Trust and execute project-level MCP server configs
        #[arg(long)]
        trust_project: bool,

        /// Static analysis only — never execute MCP server commands
        #[arg(long)]
        no_exec: bool,
    },

    /// Run an agent with runtime protection proxy
    Run {
        /// Scan mode: warn, redact, or block
        #[arg(short, long)]
        mode: Option<String>,

        /// Proxy port
        #[arg(short, long)]
        port: Option<u16>,

        /// Show TUI dashboard instead of headless mode
        #[arg(short = 'T', long)]
        tui: bool,

        /// Command to run (after --)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },

    /// Monitor for security changes in real-time (daemon mode)
    Watch {
        /// Start the daemon in background
        #[arg(long)]
        daemon: bool,

        /// Start in foreground (for debugging)
        #[arg(long)]
        foreground: bool,

        /// Query daemon status
        #[arg(long)]
        status: bool,

        /// Stop the daemon
        #[arg(long)]
        stop: bool,

        /// Suppress desktop notifications
        #[arg(short, long)]
        quiet: bool,
    },

    /// Monitor all active sessions in real time (TUI over live log)
    Monitor,

    /// Generate reports (HTML, SARIF, JSON)
    Report {
        /// Generate HTML report
        #[arg(long)]
        html: bool,

        /// Auto-open report in browser
        #[arg(long)]
        open: bool,

        /// Output format: sarif, json
        #[arg(long)]
        format: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing — in headless mode, suppress non-error logs to avoid
    // interleaving with the child process's terminal output.
    let is_headless = matches!(&cli.command, Commands::Run { tui: false, .. });
    let filter = if cli.verbose {
        "leakwall=debug"
    } else if is_headless {
        "leakwall=error"
    } else {
        "leakwall=info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .with_target(false)
        .init();

    // Load configuration (CLI flags override config file values)
    let cfg = config::load_config(cli.config.as_ref());

    // Ensure ~/.leakwall directory exists
    let lw_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".leakwall");
    std::fs::create_dir_all(&lw_dir).context("failed to create ~/.leakwall directory")?;

    match cli.command {
        Commands::Scan {
            refresh,
            json,
            trust_project,
            no_exec,
        } => {
            cmd_scan::run_scan(&lw_dir, refresh, json.as_deref(), trust_project, no_exec)
                .await
                .context("leakwall scan failed")?;
        }
        Commands::Run {
            mode,
            port,
            tui,
            command,
        } => {
            let mode_str = mode.unwrap_or(cfg.mode);
            let port = port.unwrap_or(cfg.proxy_port);
            let scan_mode = match mode_str.to_lowercase().as_str() {
                "redact" => leakwall_proxy::ScanMode::Redact,
                "block" => leakwall_proxy::ScanMode::Block,
                _ => leakwall_proxy::ScanMode::WarnOnly,
            };
            let headless = !tui;
            cmd_run::run_proxy(&lw_dir, port, scan_mode, &command, headless)
                .await
                .context("leakwall run failed")?;
        }
        Commands::Watch {
            daemon,
            foreground,
            status,
            stop,
            quiet,
        } => {
            cmd_watch::run_watch(&lw_dir, daemon, foreground, status, stop, quiet)
                .await
                .context("leakwall watch failed")?;
        }
        Commands::Monitor => {
            cmd_monitor::run_monitor(&lw_dir)
                .await
                .context("leakwall monitor failed")?;
        }
        Commands::Report { html, open, format } => {
            cmd_report::run_report(&lw_dir, html, open, format.as_deref())
                .await
                .context("leakwall report failed")?;
        }
    }

    Ok(())
}
