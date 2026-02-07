//! Scopes configuration with optional file watching for live reload.
//!
//! This module provides access to scope configuration, with optional
//! inotify-based file watching for runtime reload. This enables tools like
//! devaipod to update scopes without restarting the server.
//!
//! # Platform Support
//!
//! File watching uses Linux inotify directly via rustix. It is Linux-only,
//! which is appropriate for the Kubernetes/container use case. Static scopes
//! (from config file or CLI) work on all platforms.
//!
//! # Usage
//!
//! ```ignore
//! use service_gator::config_watcher::{watch_scopes, static_scopes};
//!
//! // Static scopes (no file watching)
//! let rx = static_scopes(config);
//!
//! // Dynamic scopes from a watched file
//! let rx = watch_scopes("/path/to/scopes.json").await?;
//!
//! // Get current config (no async needed!)
//! let config = rx.borrow().clone();
//! ```

use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use eyre::{Context, Result};
use rustix::fs::inotify::{self, CreateFlags, WatchFlags};
use tokio::sync::watch;

use crate::scope::ScopeConfig;

/// Create a receiver for static scope configuration (no file watching).
///
/// Returns a `watch::Receiver` that always contains the provided config.
/// The config will never change since there's no file watcher.
pub fn static_scopes(config: ScopeConfig) -> watch::Receiver<ScopeConfig> {
    let (tx, rx) = watch::channel(config);
    // Drop the sender - the receiver will always return the initial value
    drop(tx);
    rx
}

/// Watch a JSON file for scope configuration changes.
///
/// Returns a `watch::Receiver` that always contains the current config.
/// A background task watches the file with inotify and updates the config
/// when changes are detected.
///
/// # File Format
///
/// The file should contain a JSON object with the following structure:
/// ```json
/// {
///   "scopes": {
///     "gh": {
///       "repos": {
///         "owner/repo": {
///           "read": true,
///           "push-new-branch": true
///         }
///       }
///     }
///   }
/// }
/// ```
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed initially.
pub async fn watch_scopes(path: impl AsRef<Path>) -> Result<watch::Receiver<ScopeConfig>> {
    let path = path.as_ref().to_path_buf();

    // Read and parse the initial config
    let config = load_scope_file(&path)?;
    tracing::info!(path = %path.display(), "loaded scope configuration file");

    let (tx, rx) = watch::channel(config);

    // Spawn the file watcher task
    tokio::spawn(async move {
        if let Err(e) = watch_config_file(path, tx).await {
            tracing::error!(error = %e, "config file watcher exited with error");
        }
    });

    Ok(rx)
}

/// Wrapper struct for JSON deserialization that matches the expected file format.
#[derive(Debug, serde::Deserialize)]
struct ScopeFileWrapper {
    /// The scopes configuration (required)
    scopes: ScopeConfig,
}

/// Load and parse a scope configuration file.
fn load_scope_file(path: &Path) -> Result<ScopeConfig> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;

    // Try parsing as the wrapper format first (with "scopes" key)
    if let Ok(wrapper) = serde_json::from_str::<ScopeFileWrapper>(&content) {
        return Ok(wrapper.scopes);
    }

    // Fall back to direct ScopeConfig format (for TOML compatibility or alternative JSON format)
    let config: ScopeConfig = serde_json::from_str(&content)
        .with_context(|| format!("parsing {} as JSON", path.display()))?;

    Ok(config)
}

/// Watch a config file for changes and send updates via the channel.
///
/// Uses Linux inotify to efficiently watch for file modifications.
/// Watches the parent directory to handle Kubernetes ConfigMap-style
/// atomic symlink replacements.
async fn watch_config_file(path: PathBuf, tx: watch::Sender<ScopeConfig>) -> Result<()> {
    // Create inotify instance
    let inotify_fd = inotify::init(CreateFlags::CLOEXEC | CreateFlags::NONBLOCK)
        .context("creating inotify instance")?;

    // For Kubernetes ConfigMap-style mounts, we need to watch the parent directory
    // because the file is often a symlink that gets atomically replaced.
    let watch_path = path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    // Watch for modifications, creates, moves, and deletes in the directory
    let watch_flags = WatchFlags::MODIFY
        | WatchFlags::CREATE
        | WatchFlags::MOVED_TO
        | WatchFlags::DELETE
        | WatchFlags::CLOSE_WRITE;

    let _wd = inotify::add_watch(&inotify_fd, &watch_path, watch_flags)
        .with_context(|| format!("adding watch on {}", watch_path.display()))?;

    tracing::info!(
        path = %path.display(),
        watch_path = %watch_path.display(),
        "started watching scope configuration file for changes"
    );

    // Buffer for reading inotify events
    // Each event is at least 16 bytes (inotify_event struct) plus filename
    let mut event_buf: [MaybeUninit<u8>; 4096] = [MaybeUninit::uninit(); 4096];

    // Create an async file descriptor for the inotify instance
    let async_fd = tokio::io::unix::AsyncFd::new(inotify_fd.as_raw_fd())
        .context("creating async fd for inotify")?;

    let target_filename = path
        .file_name()
        .and_then(|s| std::ffi::CString::new(s.as_encoded_bytes()).ok());

    loop {
        // Wait for inotify events
        let readable = async_fd.readable().await;
        let mut guard = readable.context("waiting for inotify readable")?;

        // Read events from inotify using the Reader API
        let mut reader = inotify::Reader::new(&inotify_fd, &mut event_buf);
        let mut should_reload = false;

        loop {
            match reader.next() {
                Ok(event) => {
                    // Check if this event is for our target file
                    let is_relevant = match (&target_filename, event.file_name()) {
                        (Some(target), Some(name)) => name == target.as_c_str(),
                        (None, None) => true, // watching file directly
                        _ => false,
                    };

                    if is_relevant {
                        tracing::debug!(
                            event_name = ?event.file_name(),
                            "inotify event for config file"
                        );
                        should_reload = true;
                    }
                }
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    // No more events available
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "error reading inotify event");
                    break;
                }
            }
        }

        if should_reload {
            // Small delay to handle atomic writes (temp file + rename)
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

            match load_scope_file(&path) {
                Ok(new_config) => {
                    // Send returns error only if all receivers are dropped
                    if tx.send(new_config).is_err() {
                        tracing::debug!("all scope receivers dropped, stopping watcher");
                        break;
                    }
                    tracing::info!(path = %path.display(), "reloaded scope configuration");
                }
                Err(e) => {
                    // Log error but keep the old config
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "failed to reload scope configuration, keeping previous config"
                    );
                }
            }
        }

        // Clear the readiness so we wait for more events
        guard.clear_ready();
    }

    Ok(())
}

/// Merge source config into target (source values override target).
pub fn merge_scope_config(target: &mut ScopeConfig, source: ScopeConfig) {
    // Merge GitHub global read
    if source.gh.read {
        target.gh.read = true;
    }

    // Merge GitHub repos
    for (repo, perm) in source.gh.repos {
        target.gh.repos.insert(repo, perm);
    }

    // Merge GitHub PRs
    for (pr, perm) in source.gh.prs {
        target.gh.prs.insert(pr, perm);
    }

    // Merge GitHub issues
    for (issue, perm) in source.gh.issues {
        target.gh.issues.insert(issue, perm);
    }

    // Override GraphQL if set to non-default
    if source.gh.graphql != crate::scope::GraphQlPermission::None {
        target.gh.graphql = source.gh.graphql;
    }

    // Merge GitLab projects
    for (project, perm) in source.gitlab.projects {
        target.gitlab.projects.insert(project, perm);
    }

    // Merge GitLab MRs
    for (mr, perm) in source.gitlab.mrs {
        target.gitlab.mrs.insert(mr, perm);
    }

    // Merge GitLab issues
    for (issue, perm) in source.gitlab.issues {
        target.gitlab.issues.insert(issue, perm);
    }

    // Override GitLab host if set
    if source.gitlab.host.is_some() {
        target.gitlab.host = source.gitlab.host;
    }

    // Override GitLab GraphQL if set to non-default
    if source.gitlab.graphql != crate::scope::GraphQlPermission::None {
        target.gitlab.graphql = source.gitlab.graphql;
    }

    // Merge Forgejo scopes
    for source_scope in source.forgejo {
        // Find existing scope for this host or add new
        if let Some(target_scope) = target
            .forgejo
            .iter_mut()
            .find(|s| s.host == source_scope.host)
        {
            // Merge repos into existing host
            for (repo, perm) in source_scope.repos {
                target_scope.repos.insert(repo, perm);
            }
            for (pr, perm) in source_scope.prs {
                target_scope.prs.insert(pr, perm);
            }
            for (issue, perm) in source_scope.issues {
                target_scope.issues.insert(issue, perm);
            }
            if source_scope.token.is_some() {
                target_scope.token = source_scope.token;
            }
        } else {
            // Add new host
            target.forgejo.push(source_scope);
        }
    }

    // Merge JIRA config
    if source.jira.host.is_some() {
        target.jira.host = source.jira.host;
    }
    if source.jira.username.is_some() {
        target.jira.username = source.jira.username;
    }
    if source.jira.token.is_some() {
        target.jira.token = source.jira.token;
    }

    // Merge JIRA projects
    for (project, perm) in source.jira.projects {
        target.jira.projects.insert(project, perm);
    }

    // Merge JIRA issues
    for (issue, perm) in source.jira.issues {
        target.jira.issues.insert(issue, perm);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write content to a file atomically (write to temp + rename).
    /// This simulates how Kubernetes ConfigMaps update files.
    fn atomic_write(path: &std::path::Path, content: &str) {
        use cap_std_ext::cap_std;
        use cap_std_ext::prelude::CapStdExtDirExt;
        let dir = cap_std::fs::Dir::open_ambient_dir(
            path.parent().unwrap(),
            cap_std::ambient_authority(),
        )
        .unwrap();
        dir.atomic_write(path.file_name().unwrap(), content)
            .unwrap();
    }

    #[test]
    fn test_load_scope_file_wrapper_format_with_push_new_branch() {
        // Test the JSON format as specified in the requirements
        let json = r#"{
            "scopes": {
                "gh": {
                    "repos": {
                        "owner/repo": {
                            "read": true,
                            "push-new-branch": true,
                            "create-draft": true
                        }
                    }
                }
            }
        }"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("scopes.json");
        std::fs::write(&file_path, json).unwrap();

        let config = load_scope_file(&file_path).unwrap();
        assert!(config.gh.repos.contains_key("owner/repo"));
        let perm = config.gh.repos.get("owner/repo").unwrap();
        assert!(perm.read);
        assert!(perm.push_new_branch);
        assert!(perm.create_draft);
    }

    #[test]
    fn test_load_scope_file_wrapper_format() {
        let json = r#"{
            "scopes": {
                "gh": {
                    "repos": {
                        "owner/repo": {
                            "read": true,
                            "push-new-branch": true
                        }
                    }
                }
            }
        }"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("scopes.json");
        std::fs::write(&file_path, json).unwrap();

        let config = load_scope_file(&file_path).unwrap();
        assert!(config.gh.repos.contains_key("owner/repo"));
        let perm = config.gh.repos.get("owner/repo").unwrap();
        assert!(perm.read);
        assert!(perm.push_new_branch);
    }

    #[test]
    fn test_load_scope_file_direct_format() {
        let json = r#"{
            "gh": {
                "repos": {
                    "owner/repo": {
                        "read": true
                    }
                }
            }
        }"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("scopes.json");
        std::fs::write(&file_path, json).unwrap();

        let config = load_scope_file(&file_path).unwrap();
        assert!(config.gh.repos.contains_key("owner/repo"));
    }

    #[test]
    fn test_merge_scope_config() {
        let mut target = ScopeConfig::default();
        target.gh.repos.insert(
            "owner/existing".to_string(),
            crate::scope::GhRepoPermission::read_only(),
        );

        let mut source = ScopeConfig::default();
        source.gh.repos.insert(
            "owner/new".to_string(),
            crate::scope::GhRepoPermission::with_push_new_branch(),
        );
        source.gh.read = true;

        merge_scope_config(&mut target, source);

        assert!(target.gh.repos.contains_key("owner/existing"));
        assert!(target.gh.repos.contains_key("owner/new"));
        assert!(target.gh.read);
    }

    #[test]
    fn test_static_scopes() {
        let config = ScopeConfig::default();
        let rx = static_scopes(config);

        let snapshot = rx.borrow().clone();
        assert!(snapshot.gh.repos.is_empty());
    }

    #[tokio::test]
    async fn test_watch_scopes_initial_load() {
        let json = r#"{
            "scopes": {
                "gh": {
                    "repos": {
                        "test/repo": {
                            "read": true,
                            "create-draft": true
                        }
                    }
                }
            }
        }"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("scopes.json");
        std::fs::write(&file_path, json).unwrap();

        let rx = watch_scopes(&file_path).await.unwrap();
        let snapshot = rx.borrow().clone();

        assert!(snapshot.gh.repos.contains_key("test/repo"));
    }

    #[tokio::test]
    async fn test_watch_scopes_live_reload() {
        // Create initial config
        let initial_json = r#"{
            "scopes": {
                "gh": {
                    "repos": {
                        "initial/repo": {
                            "read": true
                        }
                    }
                }
            }
        }"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("scopes.json");
        std::fs::write(&file_path, initial_json).unwrap();

        let rx = watch_scopes(&file_path).await.unwrap();

        // Give the file watcher time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Verify initial state
        let snapshot = rx.borrow().clone();
        assert!(snapshot.gh.repos.contains_key("initial/repo"));
        assert!(!snapshot.gh.repos.contains_key("new/repo"));

        // Update the file atomically (simulates ConfigMap update)
        let updated_json = r#"{
            "scopes": {
                "gh": {
                    "repos": {
                        "initial/repo": {
                            "read": true
                        },
                        "new/repo": {
                            "read": true,
                            "push-new-branch": true
                        }
                    }
                }
            }
        }"#;
        atomic_write(&file_path, updated_json);

        // Wait for the file watcher to pick up the change
        // The watcher has a 50ms delay to handle atomic writes, plus inotify latency
        // Retry several times with delay to handle timing variations
        let mut reload_detected = false;
        for _ in 0..20 {
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            let snapshot = rx.borrow().clone();
            if snapshot.gh.repos.contains_key("new/repo") {
                reload_detected = true;
                break;
            }
        }

        assert!(reload_detected, "live reload should detect file changes");

        // Verify the reload content
        let snapshot = rx.borrow().clone();
        assert!(snapshot.gh.repos.contains_key("initial/repo"));
        assert!(snapshot.gh.repos.contains_key("new/repo"));
        let new_perm = snapshot.gh.repos.get("new/repo").unwrap();
        assert!(new_perm.read);
        assert!(new_perm.push_new_branch);
    }

    #[tokio::test]
    async fn test_watch_scopes_bad_json_keeps_old_config() {
        // Create initial valid config
        let initial_json = r#"{
            "scopes": {
                "gh": {
                    "repos": {
                        "good/repo": {
                            "read": true
                        }
                    }
                }
            }
        }"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("scopes.json");
        std::fs::write(&file_path, initial_json).unwrap();

        let rx = watch_scopes(&file_path).await.unwrap();

        // Give the file watcher time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Verify initial state
        let snapshot = rx.borrow().clone();
        assert!(snapshot.gh.repos.contains_key("good/repo"));

        // Write invalid JSON atomically
        atomic_write(&file_path, "{ invalid json ");

        // Wait for the file watcher to process the invalid file
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Should still have the old valid config
        let snapshot = rx.borrow().clone();
        assert!(
            snapshot.gh.repos.contains_key("good/repo"),
            "old config should be preserved when new config is invalid"
        );
    }
}
