use anyhow::{Context, Result};
use chrono::Utc;
use leakwall_proxy::ca::load_or_generate_ca;
use leakwall_proxy::process::spawn_agent;
use leakwall_proxy::proxy::start_proxy;
use leakwall_proxy::{
    generate_proxy_token, ProxyEvent, ProxyState, ScanMode, DEFAULT_MAX_BODY_SIZE,
};
use leakwall_secrets::patterns::{compile_patterns, default_pattern_defs, load_patterns};
use leakwall_secrets::scanner::{KnownSecretInfo, SecretScanner};
use leakwall_tui::dashboard::run_dashboard;
use leakwall_tui::events::create_event_channel;
use leakwall_tui::report::{build_session_report, print_session_report, save_session_report};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

/// Run the `leakwall run` command — proxy + TUI + scanner.
pub async fn run_proxy(
    lw_dir: &Path,
    port: u16,
    mode: ScanMode,
    command: &[String],
    headless: bool,
) -> Result<()> {
    // 1. Load or generate CA certificate (key is already Zeroizing<String>)
    let (ca_cert_pem, ca_key_pem) =
        load_or_generate_ca(lw_dir).context("CA certificate setup failed")?;
    let ca_cert_path = lw_dir.join("ca.pem");

    // 2. Build the secret scanner
    let scanner = build_scanner(lw_dir)?;

    // 3. Create event channel
    let (event_tx, event_rx) = create_event_channel();

    // 4. Build reqwest client with TLS 1.2 minimum
    let http_client = reqwest::Client::builder()
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .context("build HTTP client")?;

    // 5. Build proxy state
    let proxy_token = generate_proxy_token();
    let shared_mode = Arc::new(RwLock::new(mode));
    let state = Arc::new(ProxyState {
        scanner: Arc::new(scanner),
        mode: Arc::clone(&shared_mode),
        event_tx: event_tx.clone(),
        session_log: Arc::new(RwLock::new(Vec::new())),
        cert_cache: Arc::new(dashmap::DashMap::new()),
        ca_cert_pem,
        ca_key_pem,
        proxy_port: port,
        max_body_size: DEFAULT_MAX_BODY_SIZE,
        http_client,
        proxy_token: proxy_token.clone(),
    });

    // 6. Start proxy in background with readiness signal
    let proxy_state = Arc::clone(&state);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let _proxy_handle = tokio::spawn(async move {
        if let Err(e) = start_proxy(proxy_state, Some(ready_tx)).await {
            tracing::error!(error = %e, "proxy error");
        }
    });

    // Wait for proxy to bind before spawning child — if it fails, bail out
    // instead of spawning a child that would connect to a wrong proxy.
    ready_rx
        .await
        .map_err(|_| anyhow::anyhow!("proxy task exited before signaling readiness"))?
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // 7. Spawn the agent process
    let mut child = spawn_agent(command, port, &ca_cert_path, lw_dir, &proxy_token)
        .context("failed to spawn agent")?;

    let pid = child.id();
    let command_str = command.join(" ");
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let start_time = Utc::now();

    // Notify TUI of agent start
    let _ = event_tx.send(ProxyEvent::AgentStarted {
        pid,
        command: command_str.clone(),
        cwd,
    });

    // 8. Run TUI dashboard (or headless consumer) and wait for agent in parallel
    if headless {
        let log_path = lw_dir.join("logs/live.log");
        eprintln!(
            "[leakwall] headless mode — live log: {}",
            log_path.display()
        );
        eprintln!(
            "[leakwall] tip: tail -f {} in another terminal",
            log_path.display()
        );
        tokio::spawn(run_headless_consumer(event_rx, log_path));
    } else {
        let tui_mode = Arc::clone(&shared_mode);
        let tui_command = command_str.clone();
        tokio::spawn(async move {
            if let Err(e) = run_dashboard(event_rx, tui_mode, tui_command).await {
                tracing::error!(error = %e, "TUI error");
            }
        });
    }

    // 9. Wait for agent to exit
    let exit_code = tokio::task::spawn_blocking(move || child.wait())
        .await
        .context("wait failed")?
        .context("agent process wait failed")?;

    let _ = event_tx.send(ProxyEvent::AgentExited {
        pid,
        exit_code: exit_code.code(),
    });

    // Give TUI time to render final state
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 10. Generate session report
    let logs = state.session_log.read().await.clone();
    let report = build_session_report(&logs, &command_str, Some(pid), start_time);

    print_session_report(&report);

    let log_dir = lw_dir.join("logs");
    match save_session_report(&report, &log_dir) {
        Ok(path) => {
            println!("Log: {}", path.display());
        }
        Err(e) => {
            eprintln!("Warning: failed to save session log: {e}");
        }
    }

    Ok(())
}

/// Headless event consumer: writes JSONL to live.log and emits warnings to stderr via tracing.
async fn run_headless_consumer(
    mut event_rx: tokio::sync::broadcast::Receiver<ProxyEvent>,
    log_path: PathBuf,
) {
    // Ensure parent directory exists
    if let Some(parent) = log_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }

    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .await;

    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "failed to open live log at {}", log_path.display());
            return;
        }
    };

    loop {
        match event_rx.recv().await {
            Ok(event) => {
                // In headless mode, only log to file — avoid stderr noise that
                // interleaves with the child process's terminal output.

                // Append JSONL line and flush so `tail -f` sees it immediately
                if let Ok(json) = serde_json::to_string(&event) {
                    let mut line = json.into_bytes();
                    line.push(b'\n');
                    if let Err(e) = file.write_all(&line).await {
                        tracing::error!(error = %e, "failed to write to live log");
                    } else if let Err(e) = file.flush().await {
                        tracing::error!(error = %e, "failed to flush live log");
                    }
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!("headless consumer lagged, skipped {n} events");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

/// Build the secret scanner from inline discovery (known secrets) + patterns (regex).
fn build_scanner(lw_dir: &Path) -> Result<SecretScanner> {
    // Discover secrets inline instead of loading from DB
    let home = dirs::home_dir().unwrap_or_default();
    let cwd = std::env::current_dir().unwrap_or_default();

    let secrets = leakwall_secrets::discovery::discover_secrets(&home, &cwd)
        .context("secret discovery failed")?;

    let known_fingerprints: Vec<_> = secrets
        .into_iter()
        .map(|s| {
            let info = KnownSecretInfo {
                name: s.name.clone(),
                secret_id: s.id.to_string(),
            };
            (info, s.fingerprints.clone())
        })
        .collect();

    // Load regex patterns
    let patterns_path = lw_dir.join("patterns.toml");
    let pattern_defs = if patterns_path.exists() {
        load_patterns(&patterns_path).unwrap_or_else(|_| default_pattern_defs())
    } else {
        default_pattern_defs()
    };
    let compiled = compile_patterns(&pattern_defs).context("compile patterns")?;

    let scanner = SecretScanner::new(known_fingerprints, compiled).context("build scanner")?;

    Ok(scanner)
}
