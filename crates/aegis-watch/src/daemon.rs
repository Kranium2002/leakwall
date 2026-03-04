use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{DaemonConfig, DaemonRequest, DaemonResponse, WatchConfig, WatchError, WatchEvent};

/// Maximum IPC message size (1 MB).
const MAX_IPC_SIZE: u64 = 1_048_576;

// ── PID file helpers ──────────────────────────────────────────

/// Write the current process ID to the PID file.
fn write_pid_file(path: &Path) -> Result<(), WatchError> {
    let pid = std::process::id();
    std::fs::write(path, pid.to_string())?;
    debug!(pid, path = %path.display(), "wrote PID file");
    Ok(())
}

/// Read the PID from a PID file. Returns None if the file does
/// not exist or cannot be parsed.
fn read_pid_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Remove the PID file, ignoring errors.
fn remove_pid_file(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        debug!(
            error = %e,
            path = %path.display(),
            "failed to remove PID file"
        );
    }
}

/// Check whether a process with the given PID is alive.
/// Uses `/proc/{pid}` which is Linux-specific (sufficient for Aegis's
/// primary target: Linux / WSL2).
#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    let proc_path = format!("/proc/{pid}");
    std::fs::metadata(&proc_path).is_ok()
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    false
}

// ── IPC ───────────────────────────────────────────────────────

/// Send a command to the daemon via its Unix socket and return the
/// response. Times out after 5 seconds.
#[cfg(unix)]
pub async fn send_daemon_command(
    socket_path: &Path,
    cmd: DaemonRequest,
) -> Result<DaemonResponse, WatchError> {
    use tokio::net::UnixStream;

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        UnixStream::connect(socket_path),
    )
    .await
    .map_err(|_| WatchError::Ipc("connection timed out".to_owned()))?
    .map_err(|e| WatchError::Ipc(format!("connect failed: {e}")))?;

    let payload = serde_json::to_vec(&cmd)?;
    let (reader, mut writer) = stream.into_split();

    writer.write_all(&payload).await?;
    writer.shutdown().await?;

    let mut buf = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reader.take(MAX_IPC_SIZE).read_to_end(&mut buf),
    )
    .await
    .map_err(|_| WatchError::Ipc("read timed out".to_owned()))??;

    let resp: DaemonResponse = serde_json::from_slice(&buf)?;
    Ok(resp)
}

#[cfg(not(unix))]
pub async fn send_daemon_command(
    _socket_path: &Path,
    _cmd: DaemonRequest,
) -> Result<DaemonResponse, WatchError> {
    Err(WatchError::Ipc(
        "daemon IPC is only supported on Unix".to_owned(),
    ))
}

/// Listen on a Unix domain socket and handle incoming daemon
/// commands. Runs until the stop_rx signal fires.
#[cfg(unix)]
async fn serve_ipc(
    socket_path: &Path,
    stop_tx: tokio::sync::watch::Sender<bool>,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), WatchError> {
    use tokio::net::UnixListener;

    // Remove stale socket file
    let _ = std::fs::remove_file(socket_path);

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)
        .map_err(|e| WatchError::Ipc(format!("bind failed: {e}")))?;

    // chmod 600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(socket_path, perms)?;
    }

    info!(
        path = %socket_path.display(),
        "IPC socket listening"
    );

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
                        let stopped =
                            *stop_rx.borrow();
                        let stop = stop_tx.clone();
                        tokio::spawn(
                            handle_ipc_connection(
                                stream, stopped, stop,
                            ),
                        );
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "IPC accept error"
                        );
                    }
                }
            }
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    info!("IPC server shutting down");
                    break;
                }
            }
        }
    }

    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

/// Handle a single IPC connection: read a request, produce a
/// response.
#[cfg(unix)]
async fn handle_ipc_connection(
    stream: tokio::net::UnixStream,
    stopped: bool,
    stop_tx: tokio::sync::watch::Sender<bool>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut buf = Vec::new();

    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reader.take(MAX_IPC_SIZE).read_to_end(&mut buf),
    )
    .await;

    let buf = match read_result {
        Ok(Ok(_)) => buf,
        Ok(Err(e)) => {
            debug!(error = %e, "IPC read error");
            return;
        }
        Err(_) => {
            debug!("IPC read timed out");
            return;
        }
    };

    let request: DaemonRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            debug!(error = %e, "invalid IPC request");
            return;
        }
    };

    let response = match request {
        DaemonRequest::Status => DaemonResponse {
            success: true,
            data: serde_json::json!({
                "status": if stopped {
                    "stopped"
                } else {
                    "running"
                },
                "pid": std::process::id(),
            }),
            error: None,
        },
        DaemonRequest::Stop => {
            info!("stop command received via IPC");
            let _ = stop_tx.send(true);
            DaemonResponse {
                success: true,
                data: serde_json::json!({"message": "stopping"}),
                error: None,
            }
        }
        DaemonRequest::Pause => DaemonResponse {
            success: true,
            data: serde_json::json!({"message": "paused"}),
            error: None,
        },
        DaemonRequest::Resume => DaemonResponse {
            success: true,
            data: serde_json::json!({"message": "resumed"}),
            error: None,
        },
        DaemonRequest::TriggerScan => DaemonResponse {
            success: true,
            data: serde_json::json!({"message": "scan triggered"}),
            error: None,
        },
        DaemonRequest::GetEvents { .. } => DaemonResponse {
            success: true,
            data: serde_json::json!({"events": []}),
            error: None,
        },
    };

    if let Ok(resp_bytes) = serde_json::to_vec(&response) {
        let _ = writer.write_all(&resp_bytes).await;
        let _ = writer.shutdown().await;
    }
}

// ── Daemon lifecycle ──────────────────────────────────────────

/// Start the daemon. Blocks until shutdown is signaled.
pub async fn start_daemon(
    config: &DaemonConfig,
    watch_config: WatchConfig,
) -> Result<(), WatchError> {
    // TODO: implement log rotation (tracing-appender) to prevent unbounded growth

    // Ensure parent directories exist
    if let Some(parent) = config.pid_file.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Try to acquire exclusive lock on PID file
    use fs2::FileExt;

    let pid_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&config.pid_file)?;

    match pid_file.try_lock_exclusive() {
        Ok(()) => {
            // Check if stale PID exists
            if let Some(pid) = read_pid_file(&config.pid_file) {
                if process_alive(pid) {
                    return Err(WatchError::Daemon(format!(
                        "daemon already running with PID {pid}"
                    )));
                }
            }
        }
        Err(_) => {
            return Err(WatchError::Daemon(
                "another daemon instance holds the PID file lock".to_owned(),
            ));
        }
    }

    write_pid_file(&config.pid_file)?;

    // Channel for watch events
    let (event_tx, mut event_rx) = mpsc::channel::<WatchEvent>(256);

    // Stop signal
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);

    // Set up file watchers
    let _debouncer = crate::watcher::setup_watchers(&watch_config, event_tx).map_err(|e| {
        remove_pid_file(&config.pid_file);
        e
    })?;

    // Start IPC server
    #[cfg(unix)]
    let ipc_handle = {
        let socket_path = config.socket_path.clone();
        let ipc_stop_tx = stop_tx.clone();
        let ipc_stop_rx = stop_rx.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_ipc(&socket_path, ipc_stop_tx, ipc_stop_rx).await {
                error!(error = %e, "IPC server error");
            }
        })
    };

    info!(pid = std::process::id(), "aegis daemon started");

    // Main event loop
    loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
                info!(?event, "watch event received");
                // Future: feed events to notifier, trigger
                // re-scans, etc.
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal (ctrl-c)");
                let _ = stop_tx.send(true);
                break;
            }
            _ = stop_rx.changed() => {
                if *stop_rx.borrow() {
                    info!("received shutdown signal (IPC)");
                    break;
                }
            }
        }
    }

    // Cleanup
    #[cfg(unix)]
    {
        ipc_handle.abort();
    }
    remove_pid_file(&config.pid_file);
    let _ = std::fs::remove_file(&config.socket_path);
    drop(pid_file); // Release PID file lock

    info!("daemon stopped");
    Ok(())
}

/// Stop a running daemon by sending a Stop command via IPC.
pub async fn stop_daemon(config: &DaemonConfig) -> Result<(), WatchError> {
    let resp = send_daemon_command(&config.socket_path, DaemonRequest::Stop).await?;

    if resp.success {
        info!("daemon stop command accepted");
        Ok(())
    } else {
        Err(WatchError::Daemon(
            resp.error.unwrap_or_else(|| "unknown error".to_owned()),
        ))
    }
}

/// Query the daemon's current status via IPC.
pub async fn daemon_status(config: &DaemonConfig) -> Result<DaemonResponse, WatchError> {
    send_daemon_command(&config.socket_path, DaemonRequest::Status).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_pid_file_write_read() {
        let tmp = TempDir::new().expect("create temp dir");
        let pid_path = tmp.path().join("aegis.pid");

        write_pid_file(&pid_path).expect("write PID");
        let pid = read_pid_file(&pid_path);
        assert_eq!(pid, Some(std::process::id()));
    }

    #[test]
    fn test_pid_file_cleanup() {
        let tmp = TempDir::new().expect("create temp dir");
        let pid_path = tmp.path().join("aegis.pid");

        write_pid_file(&pid_path).expect("write PID");
        assert!(pid_path.exists());

        remove_pid_file(&pid_path);
        assert!(!pid_path.exists());
    }

    #[test]
    fn test_read_pid_file_missing() {
        let path = Path::new("/tmp/aegis_nonexistent_pid_xyz");
        assert!(read_pid_file(path).is_none());
    }

    #[test]
    fn test_process_alive_current() {
        // Our own process should be alive
        let pid = std::process::id();
        #[cfg(unix)]
        assert!(process_alive(pid));
        #[cfg(not(unix))]
        assert!(!process_alive(pid));
    }

    #[test]
    fn test_process_alive_nonexistent() {
        // PID 999999 is very unlikely to be running
        #[cfg(unix)]
        assert!(!process_alive(999_999));
    }
}
