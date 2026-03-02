mod cmd_run;
mod cmd_scan;
mod config;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "aegis", version, about = "AI agent security platform")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Config file path (default: ./aegis.toml or ~/.aegis/config.toml)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Audit agent security posture (MCP servers, configs, exposure)
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
    },

    /// Run an agent with runtime protection proxy
    Run {
        /// Scan mode: warn, redact, or block
        #[arg(short, long)]
        mode: Option<String>,

        /// Proxy port
        #[arg(short, long)]
        port: Option<u16>,

        /// Run without TUI dashboard (log to file + stderr)
        #[arg(short = 'H', long)]
        headless: bool,

        /// Command to run (after --)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing — in headless mode, suppress non-error logs to avoid
    // interleaving with the child process's terminal output.
    let is_headless = matches!(&cli.command, Commands::Run { headless: true, .. });
    let filter = if cli.verbose {
        "aegis=debug"
    } else if is_headless {
        "aegis=error"
    } else {
        "aegis=info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .with_target(false)
        .init();

    // Load configuration (CLI flags override config file values)
    let cfg = config::load_config(cli.config.as_ref());

    // Ensure ~/.aegis directory exists
    let aegis_dir = dirs::home_dir()
        .context("could not determine home directory")?
        .join(".aegis");
    std::fs::create_dir_all(&aegis_dir).context("failed to create ~/.aegis directory")?;

    match cli.command {
        Commands::Scan {
            refresh,
            json,
            trust_project,
        } => {
            cmd_scan::run_scan(&aegis_dir, refresh, json.as_deref(), trust_project)
                .await
                .context("aegis scan failed")?;
        }
        Commands::Run {
            mode,
            port,
            headless,
            command,
        } => {
            let mode_str = mode.unwrap_or(cfg.mode);
            let port = port.unwrap_or(cfg.proxy_port);
            let scan_mode = match mode_str.to_lowercase().as_str() {
                "redact" => aegis_proxy::ScanMode::Redact,
                "block" => aegis_proxy::ScanMode::Block,
                _ => aegis_proxy::ScanMode::WarnOnly,
            };
            cmd_run::run_proxy(&aegis_dir, port, scan_mode, &command, headless)
                .await
                .context("aegis run failed")?;
        }
    }

    Ok(())
}
