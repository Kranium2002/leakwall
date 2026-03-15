use anyhow::{Context, Result};
use std::path::Path;

/// Run the `leakwall monitor` command — real-time session TUI over the live log.
pub async fn run_monitor(lw_dir: &Path) -> Result<()> {
    let log_path = lw_dir.join("logs/live.log");
    if !log_path.exists() {
        eprintln!(
            "[leakwall] waiting for live log — run `leakwall run -- <cmd>` in another terminal"
        );
    }
    leakwall_tui::monitor::run_monitor(log_path)
        .await
        .context("monitor TUI failed")
}
