use std::path::{Path, PathBuf};

use notify::{RecursiveMode, Watcher};
use notify_debouncer_full::{new_debouncer, DebounceEventResult, Debouncer, FileIdMap};
use tracing::{debug, info, warn};

use crate::{WatchConfig, WatchError, WatchEvent};

/// Set up file system watchers for all configured paths.
///
/// Returns a debouncer handle that must be kept alive for the
/// watchers to continue operating. Dropping it stops all watches.
pub fn setup_watchers(
    config: &WatchConfig,
    event_tx: tokio::sync::mpsc::Sender<WatchEvent>,
) -> Result<Debouncer<notify::RecommendedWatcher, FileIdMap>, WatchError> {
    let mcp_paths = config.mcp_config_paths.clone();
    let skills_dirs = config.skills_directories.clone();
    let secret_files = config.secret_files.clone();

    let mut debouncer = new_debouncer(
        std::time::Duration::from_secs(2),
        None,
        move |result: DebounceEventResult| match result {
            Ok(events) => {
                for event in events {
                    for path in &event.paths {
                        if let Some(watch_event) =
                            classify_event(path, &mcp_paths, &skills_dirs, &secret_files)
                        {
                            if event_tx.blocking_send(watch_event).is_err() {
                                debug!("event channel closed");
                                return;
                            }
                        }
                    }
                }
            }
            Err(errors) => {
                for e in errors {
                    warn!(error = %e, "watcher error");
                }
            }
        },
    )
    .map_err(|e| WatchError::Watcher(format!("failed to create debouncer: {e}")))?;

    // Watch MCP config files (non-recursive on parent dirs)
    for path in &config.mcp_config_paths {
        let watch_path = watch_target(path);
        if watch_path.exists() {
            if let Err(e) = debouncer
                .watcher()
                .watch(&watch_path, RecursiveMode::NonRecursive)
            {
                warn!(
                    path = %watch_path.display(),
                    error = %e,
                    "failed to watch MCP config"
                );
            } else {
                info!(
                    path = %watch_path.display(),
                    "watching MCP config"
                );
            }
        } else {
            debug!(
                path = %watch_path.display(),
                "skipping non-existent MCP config path"
            );
        }
    }

    // Watch skills directories (recursive)
    for path in &config.skills_directories {
        if path.exists() {
            if let Err(e) = debouncer.watcher().watch(path, RecursiveMode::Recursive) {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to watch skills directory"
                );
            } else {
                info!(
                    path = %path.display(),
                    "watching skills directory"
                );
            }
        } else {
            debug!(
                path = %path.display(),
                "skipping non-existent skills directory"
            );
        }
    }

    // Watch secret files (non-recursive on parent dirs)
    for path in &config.secret_files {
        let watch_path = watch_target(path);
        if watch_path.exists() {
            if let Err(e) = debouncer
                .watcher()
                .watch(&watch_path, RecursiveMode::NonRecursive)
            {
                warn!(
                    path = %watch_path.display(),
                    error = %e,
                    "failed to watch secret file"
                );
            } else {
                info!(
                    path = %watch_path.display(),
                    "watching secret file"
                );
            }
        } else {
            debug!(
                path = %watch_path.display(),
                "skipping non-existent secret file path"
            );
        }
    }

    Ok(debouncer)
}

/// For file paths, we watch the parent directory (non-recursive).
/// For directories, we watch the directory itself.
fn watch_target(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| path.to_path_buf())
    }
}

/// Classify a filesystem event path into a WatchEvent based on
/// which monitored path set it belongs to.
fn classify_event(
    path: &Path,
    mcp_paths: &[PathBuf],
    skills_dirs: &[PathBuf],
    secret_files: &[PathBuf],
) -> Option<WatchEvent> {
    // Check if path matches an MCP config
    for mcp_path in mcp_paths {
        if path == mcp_path.as_path() {
            let agent = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "unknown".to_owned());
            return Some(WatchEvent::McpConfigChanged {
                path: path.to_path_buf(),
                agent,
                change: crate::ConfigChange::ServerModified {
                    name: "unknown".to_owned(),
                },
            });
        }
    }

    // Check if path is under a skills directory
    for skills_dir in skills_dirs {
        if path.starts_with(skills_dir) {
            let change = crate::skills_monitor::classify_skill_change(path, path.exists());
            return Some(WatchEvent::SkillChanged {
                path: path.to_path_buf(),
                change,
            });
        }
    }

    // Check if path matches a secret file
    for secret_path in secret_files {
        if path == secret_path.as_path() {
            let count = crate::secret_monitor::count_secrets_in_file(path).unwrap_or(0);
            return Some(WatchEvent::SecretFileChanged {
                path: path.to_path_buf(),
                new_secret_count: count,
            });
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_event_mcp() {
        let mcp_path = PathBuf::from("/home/user/.cursor/mcp.json");
        let event = classify_event(&mcp_path, &[mcp_path.clone()], &[], &[]);
        assert!(matches!(event, Some(WatchEvent::McpConfigChanged { .. })));
    }

    #[test]
    fn test_classify_event_skills() {
        let skills_dir = PathBuf::from("/home/user/skills");
        let file_path = PathBuf::from("/home/user/skills/my_skill.json");
        let event = classify_event(&file_path, &[], &[skills_dir], &[]);
        assert!(matches!(event, Some(WatchEvent::SkillChanged { .. })));
    }

    #[test]
    fn test_classify_event_no_match() {
        let path = PathBuf::from("/tmp/unrelated.txt");
        let event = classify_event(&path, &[], &[], &[]);
        assert!(event.is_none());
    }

    #[test]
    fn test_watch_target_file() {
        let path = PathBuf::from("/home/user/.env");
        let target = watch_target(&path);
        assert_eq!(target, PathBuf::from("/home/user"));
    }
}
