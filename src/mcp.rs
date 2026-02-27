//! MCP (Model Context Protocol) server for service-gator.
//!
//! This module exposes service-gator as an MCP server, allowing AI agents
//! to call CLI tools through the MCP protocol over HTTP/SSE.
//!
//! # Usage
//!
//! ```sh
//! service-gator --mcp-server 127.0.0.1:8080
//! ```
//!
//! The server exposes tools for each configured service (gh, jira, etc.).
//!
//! # Token Authentication
//!
//! When configured with a secret, the server supports JWT-based authentication:
//! - `POST /admin/mint-token` - Create new scoped tokens (requires admin key)
//! - `POST /token/rotate` - Refresh an existing token (requires valid Bearer token)
//! - `/mcp` - MCP endpoint, requires Bearer token when auth mode is "required"

use std::process::Stdio;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use eyre::Result;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::Extension;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, Implementation, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::auth::{
    AuthError, AuthMode, MintError, MintRequest, RotateError, RotateRequest, ServerConfig,
    TokenAuthority, TokenError,
};
use tokio::sync::watch;

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
use crate::forgejo;
use crate::forgejo_client::{self, ForgejoClient};
use crate::git::{BranchDescription, CommitSha, PullRequestNumber, RepoName};
use crate::github::{self, PendingReviewOp, REVIEW_MARKER_TOKEN, REVIEW_TOOL_HELP};
use crate::gitlab;
use crate::jira::{self, JiraSubcommand};
use crate::jira_client::JiraClient;
use crate::logging::LoggingState;
use crate::scope::{GhOpType, OpType, ScopeConfig};

/// Input schema for GitHub API tool.
///
/// Provides read/write access to the GitHub REST API.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GithubApiInput {
    /// The API endpoint path (e.g., "repos/owner/repo/pulls")
    pub endpoint: String,
    /// HTTP method: GET (default), POST, PUT, PATCH, DELETE
    #[serde(default)]
    pub method: Option<String>,
    /// Request body as JSON (for POST/PUT/PATCH)
    #[serde(default)]
    pub body: Option<serde_json::Value>,
    /// Optional jq expression to filter output
    #[serde(default)]
    pub jq: Option<String>,
}

/// Input schema for the combined GitHub push + optional draft PR operation.
///
/// This tool pushes a local commit to a remote branch and optionally creates a
/// draft PR. This is the recommended way to submit work for review on GitHub.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GithubPushInput {
    /// Path to the local git repository (e.g., "/workspaces/myproject")
    /// Must be under /workspaces.
    pub repo_path: crate::net::WorkspacePath,
    /// The commit SHA to push (must exist in the local repo)
    pub commit_sha: CommitSha,
    /// GitHub repository in "owner/repo" format
    pub repo: RepoName,
    /// Branch description (e.g., "fix-typo"). Will be prefixed with "agent-" automatically.
    pub description: BranchDescription,
    /// Whether to create a draft PR after pushing (default: true).
    /// Set to false if you only want to push the branch without creating a PR.
    #[serde(default = "default_true")]
    pub create_draft_pr: bool,
    /// The branch you want the changes pulled into (usually "main").
    /// Required when create_draft_pr is true.
    #[serde(default)]
    pub base: Option<String>,
    /// The title of the pull request.
    /// Required when create_draft_pr is true.
    #[serde(default)]
    pub title: Option<String>,
    /// The body/description of the pull request.
    #[serde(default)]
    pub body: Option<String>,
    /// If true, push to the authenticated user's fork of the repo instead of the
    /// upstream. The fork is discovered automatically via a GraphQL query. A draft
    /// PR is still created on the *upstream* repo with a cross-repo head ref.
    /// Default: false (push directly to the upstream repo).
    #[serde(default)]
    pub use_fork: bool,
}

fn default_true() -> bool {
    true
}

/// Input schema for managing pending PR reviews.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GithubPendingReviewInput {
    /// The operation to perform: "list", "create", "get", "update", "delete",
    /// or "extended-help"
    pub operation: String,
    /// Repository in "owner/repo" format
    pub repo: String,
    /// Pull request number
    pub pull_number: u64,
    /// Review ID (required for get/update/delete operations)
    #[serde(default)]
    pub review_id: Option<u64>,
    /// Review body text (required for create, optional for update)
    #[serde(default)]
    pub body: Option<String>,
    /// Review comments for create operation
    #[serde(default)]
    pub comments: Option<Vec<ReviewComment>>,
    /// If true, validate the inputs without submitting (create operation only).
    #[serde(default)]
    pub dry_run: bool,
    /// If true, delete any existing pending service-gator review before
    /// creating a new one (create operation only). Without this, create
    /// will fail if a pending review already exists.
    #[serde(default)]
    pub replace: bool,
}

/// Input schema for GitLab CLI tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GlToolInput {
    /// Command line arguments for the `glab` CLI (e.g., ["api", "projects/group%2Fproject/merge_requests"])
    /// Only the `api` subcommand is supported for read-only access.
    pub args: Vec<String>,
}

/// Input schema for JIRA CLI tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct JiraToolInput {
    /// Command arguments (e.g., ["issue", "view", "PROJ-123"])
    pub args: Vec<String>,
}

/// Input schema for Forgejo CLI tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ForgejoToolInput {
    /// Command line arguments for the Forgejo API (e.g., ["api", "/api/v1/repos/owner/repo/pulls"])
    /// Only the `api` subcommand is supported for read-only access.
    pub args: Vec<String>,
    /// Forgejo host (e.g., "codeberg.org") - required if multiple hosts configured
    #[serde(default)]
    pub host: Option<String>,
}

/// Input schema for creating a new agent branch on GitHub.
///
/// This is for `create-draft` permission level. Branch names are enforced
/// to start with `agent-` prefix and the branch must NOT already exist.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GhCreateBranchInput {
    /// Repository in "owner/repo" format
    pub repo: RepoName,
    /// The commit SHA to create the branch at
    pub commit_sha: CommitSha,
    /// Optional issue number this branch relates to (e.g., 42)
    /// If provided, branch will be named `agent-42-<description>`
    #[serde(default)]
    pub issue_number: Option<u64>,
    /// Short description for the branch name (e.g., "fix-typo").
    /// Branch will be named `agent-[issue-]<description>`
    pub description: BranchDescription,
}

/// Input schema for updating an existing PR's head branch.
///
/// This allows pushing new commits to a PR that the agent has access to.
/// The agent cannot specify the branch name directly - it's looked up from the PR.
/// This prevents arbitrary branch manipulation.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GhUpdatePrHeadInput {
    /// Repository in "owner/repo" format
    pub repo: RepoName,
    /// Pull request number
    pub pull_number: PullRequestNumber,
    /// The commit SHA to update the PR head to
    pub commit_sha: CommitSha,
}

/// Input schema for pushing a local commit to a remote git repository.
///
/// This tool safely pushes commits from an agent's local repository to a remote.
/// It works by creating a temporary trusted clone (using the agent's repo as a
/// reference for object borrowing) and pushing from there. This avoids executing
/// any hooks or config from the agent's potentially untrusted repository.
///
/// **NOTE**: Requires service-gator to have filesystem access to the agent's repo.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GitPushLocalInput {
    /// Path to the local git repository (e.g., "/workspaces/myproject")
    /// Must be under /workspaces.
    pub repo_path: crate::net::WorkspacePath,
    /// The commit SHA to push (must exist in the local repo)
    pub commit_sha: CommitSha,
    /// Target repository scope in "forge:path" format.
    ///
    /// Examples:
    /// - `github:owner/repo` for GitHub
    /// - `gitlab:group/project` or `gitlab:group/subgroup/project` for GitLab
    /// - `forgejo:owner/repo` for Forgejo/Gitea
    ///
    /// Must have `push-new-branch` or higher permission in the corresponding scope.
    pub target: String,
    /// Branch name to push to (e.g., "fix-typo").
    /// Will be prefixed with "agent-" automatically.
    /// The full branch name will be `agent-<description>`.
    pub description: BranchDescription,
}

/// A review comment on a specific file/line.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ReviewComment {
    /// The relative path to the file
    pub path: String,
    /// The line number in the file (new version)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// The side of the diff (LEFT or RIGHT)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side: Option<String>,
    /// The comment body
    pub body: String,
}

/// Input schema for overall status command.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct StatusToolInput {
    // No parameters needed for overall status
}

/// Resolved scopes for a request.
///
/// This is injected into HTTP request extensions by the auth middleware, containing
/// either the token's embedded scopes or the server's default scopes.
/// Handlers extract this from `http::request::Parts` extensions.
#[derive(Clone)]
pub struct ResolvedScopes(pub ScopeConfig);

/// Helper to extract resolved scopes from HTTP request parts.
///
/// Returns the scopes from the `ResolvedScopes` extension if present,
/// or returns an internal error if not found. The middleware should always
/// set this, so failure indicates a configuration or routing issue.
fn get_scopes_from_parts(parts: &http::request::Parts) -> Result<ScopeConfig, McpError> {
    parts
        .extensions
        .get::<ResolvedScopes>()
        .map(|r| r.0.clone())
        .ok_or_else(|| {
            tracing::error!(
                "ResolvedScopes not found in request extensions - auth middleware not configured?"
            );
            McpError::internal_error("internal server error", None)
        })
}

/// The MCP server handler for service-gator.
///
/// Scopes are resolved per-request by the auth middleware and injected as
/// `ResolvedScopes` into request extensions. Handlers extract scopes from there.
#[derive(Clone)]
pub struct ServiceGatorServer {
    tool_router: ToolRouter<Self>,
    logging: LoggingState,
}

impl ServiceGatorServer {
    /// Create a new server with default (new) logging state.
    pub fn new() -> Self {
        Self::with_logging(LoggingState::new())
    }

    /// Create a new server with shared logging state.
    ///
    /// This allows multiple server instances (one per session) to share
    /// the same logging state for aggregated read operation counting.
    pub fn with_logging(logging: LoggingState) -> Self {
        Self {
            tool_router: Self::tool_router(),
            logging,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{GhRepoPermission, GithubScope, ScopeConfig};
    use std::collections::HashMap;

    /// Helper function to create a test ScopeConfig with specific GitHub permissions
    fn create_test_scope_config(gh_repo_perms: Vec<(&str, GhRepoPermission)>) -> ScopeConfig {
        ScopeConfig {
            gh: GithubScope {
                read: false,
                repos: gh_repo_perms
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                prs: HashMap::new(),
                issues: HashMap::new(),
                graphql: crate::scope::GraphQlPermission::None,
            },
            gitlab: Default::default(),
            forgejo: Vec::new(),
            jira: Default::default(),
        }
    }

    #[test]
    fn test_github_push_permission_enforcement() {
        // Test that github_push correctly enforces push-new-branch permission

        // Case 1: No push-new-branch permission should fail
        let scope_no_push = create_test_scope_config(vec![(
            "owner/repo",
            GhRepoPermission {
                read: true,
                create_draft: true,
                pending_review: false,
                push_new_branch: false,
                write: false,
            },
        )]);

        // We can't easily test the full async function without setting up tokio runtime,
        // but we can test the permission logic that drives the MCP handlers
        assert!(!scope_no_push
            .gh
            .is_allowed("owner/repo", GhOpType::PushNewBranch, None));

        // Case 2: With push-new-branch permission should not fail on permission check
        let scope_with_push = create_test_scope_config(vec![(
            "owner/repo",
            GhRepoPermission {
                read: true,
                create_draft: true,
                pending_review: false,
                push_new_branch: true,
                write: false,
            },
        )]);

        assert!(scope_with_push
            .gh
            .is_allowed("owner/repo", GhOpType::PushNewBranch, None));
    }

    #[test]
    fn test_gh_create_branch_permission_enforcement() {
        // Test that gh_create_branch correctly enforces push-new-branch permission

        // Case 1: No push-new-branch permission should be denied
        let scope_no_push = create_test_scope_config(vec![(
            "owner/repo",
            GhRepoPermission {
                read: true,
                create_draft: true,
                pending_review: false,
                push_new_branch: false,
                write: false,
            },
        )]);

        assert!(!scope_no_push
            .gh
            .is_allowed("owner/repo", GhOpType::PushNewBranch, None));

        // Case 2: With push-new-branch permission should be allowed
        let scope_with_push = create_test_scope_config(vec![(
            "owner/repo",
            GhRepoPermission {
                read: true,
                create_draft: true,
                pending_review: false,
                push_new_branch: true,
                write: false,
            },
        )]);

        assert!(scope_with_push
            .gh
            .is_allowed("owner/repo", GhOpType::PushNewBranch, None));

        // Case 3: Write permission should also allow push-new-branch
        let scope_with_write =
            create_test_scope_config(vec![("owner/repo", GhRepoPermission::full_write())]);

        assert!(scope_with_write
            .gh
            .is_allowed("owner/repo", GhOpType::PushNewBranch, None));
    }

    #[test]
    fn test_permission_error_message_triggers() {
        // Test that permission denial produces the conditions that trigger specific error messages
        // The actual MCP handlers would return errors like:
        // - "push-new-branch permission not granted for repository: owner/repo"
        // - "push-new-branch permission not granted for github:owner/repo"

        let scope_no_push = create_test_scope_config(vec![(
            "owner/repo",
            GhRepoPermission {
                read: true,
                create_draft: true,
                pending_review: false,
                push_new_branch: false,
                write: false,
            },
        )]);

        // These operations should be denied, triggering error messages
        assert!(!scope_no_push
            .gh
            .is_allowed("owner/repo", GhOpType::PushNewBranch, None));

        // Unknown repository should also be denied
        assert!(!scope_no_push
            .gh
            .is_allowed("unknown/repo", GhOpType::PushNewBranch, None));
        assert!(!scope_no_push
            .gh
            .is_allowed("unknown/repo", GhOpType::Read, None));
    }

    #[test]
    fn test_git_push_local_permission_enforcement() {
        // Test permission enforcement logic for git_push_local
        // (The actual implementation checks GitLab and Forgejo scopes)

        // Test GitLab permission checking
        let gitlab_scope = crate::scope::GitLabScope {
            projects: [
                (
                    "group/allowed".to_string(),
                    crate::scope::GlProjectPermission::with_push_new_branch(),
                ),
                (
                    "group/denied".to_string(),
                    crate::scope::GlProjectPermission::read_only(),
                ),
            ]
            .into(),
            mrs: HashMap::new(),
            issues: HashMap::new(),
            graphql: crate::scope::GraphQlPermission::None,
            host: None,
        };

        assert!(gitlab_scope.is_allowed(
            "group/allowed",
            crate::scope::GlOpType::PushNewBranch,
            None
        ));
        assert!(!gitlab_scope.is_allowed(
            "group/denied",
            crate::scope::GlOpType::PushNewBranch,
            None
        ));
        assert!(!gitlab_scope.is_allowed(
            "group/unknown",
            crate::scope::GlOpType::PushNewBranch,
            None
        ));

        // Test Forgejo permission checking
        let forgejo_scopes = vec![crate::scope::ForgejoScope {
            host: "codeberg.org".to_string(),
            token: None,
            repos: [
                (
                    "user/allowed".to_string(),
                    crate::scope::ForgejoRepoPermission::with_push_new_branch(),
                ),
                (
                    "user/denied".to_string(),
                    crate::scope::ForgejoRepoPermission::read_only(),
                ),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
        }];

        assert!(forgejo_scopes[0].is_allowed(
            "user/allowed",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));
        assert!(!forgejo_scopes[0].is_allowed(
            "user/denied",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));
        assert!(!forgejo_scopes[0].is_allowed(
            "user/unknown",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));
    }
}

impl Default for ServiceGatorServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceGatorServer {
    /// Execute a command and capture output.
    async fn exec_command(&self, command: &str, args: &[String]) -> Result<String, String> {
        let mut child = Command::new(command)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn {}: {}", command, e))?;

        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        let mut stdout_reader = BufReader::new(stdout).lines();
        let mut stderr_reader = BufReader::new(stderr).lines();

        let mut output = String::new();

        // Read stdout and stderr
        loop {
            tokio::select! {
                line = stdout_reader.next_line() => {
                    match line {
                        Ok(Some(l)) => {
                            output.push_str(&l);
                            output.push('\n');
                        }
                        Ok(None) => break,
                        Err(e) => return Err(format!("Error reading stdout: {}", e)),
                    }
                }
                line = stderr_reader.next_line() => {
                    match line {
                        Ok(Some(l)) => {
                            output.push_str("[stderr] ");
                            output.push_str(&l);
                            output.push('\n');
                        }
                        Ok(None) => {}
                        Err(e) => return Err(format!("Error reading stderr: {}", e)),
                    }
                }
            }
        }

        // Drain remaining stderr
        while let Ok(Some(line)) = stderr_reader.next_line().await {
            output.push_str("[stderr] ");
            output.push_str(&line);
            output.push('\n');
        }

        let status = child
            .wait()
            .await
            .map_err(|e| format!("Failed to wait for {}: {}", command, e))?;

        if !status.success() {
            output.push_str(&format!("[exit code: {}]", status.code().unwrap_or(-1)));
        }

        Ok(output)
    }

    /// Execute a command with stdin input and capture output.
    async fn exec_command_with_stdin(
        &self,
        command: &str,
        args: &[String],
        stdin_data: &str,
    ) -> Result<String, String> {
        use tokio::io::AsyncWriteExt;

        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn {}: {}", command, e))?;

        // Write to stdin
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_data.as_bytes())
                .await
                .map_err(|e| format!("Failed to write to stdin: {}", e))?;
            // stdin is dropped here, closing it
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| format!("Failed to wait for {}: {}", command, e))?;

        let mut result = String::from_utf8_lossy(&output.stdout).to_string();

        if !output.stderr.is_empty() {
            result.push_str("\n[stderr] ");
            result.push_str(&String::from_utf8_lossy(&output.stderr));
        }

        if !output.status.success() {
            result.push_str(&format!(
                "\n[exit code: {}]",
                output.status.code().unwrap_or(-1)
            ));
        }

        Ok(result)
    }

    /// Execute a command in a specific directory and capture output.
    async fn exec_command_in_dir(
        &self,
        command: &str,
        args: &[String],
        dir: &camino::Utf8Path,
    ) -> Result<String, String> {
        let output = Command::new(command)
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| format!("Failed to spawn {}: {}", command, e))?;

        let mut result = String::from_utf8_lossy(&output.stdout).to_string();

        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(&stderr);
        }

        if !output.status.success() {
            return Err(format!(
                "{}\n[exit code: {}]",
                result,
                output.status.code().unwrap_or(-1)
            ));
        }

        Ok(result)
    }

    /// Inner implementation for git_push_local that returns Result for cleaner error handling.
    async fn git_push_local_inner(
        &self,
        config: &ScopeConfig,
        input: &GitPushLocalInput,
    ) -> Result<String, String> {
        tracing::info!(
            operation = "git_push_local",
            target = %input.target,
            commit = %input.commit_sha,
            branch_desc = %input.description,
            "starting git push operation"
        );

        // Parse the target scope (e.g., "github:owner/repo", "gitlab:group/project")
        let (forge, repo_path) = input.target.split_once(':').ok_or_else(|| {
            let err = format!(
                "Invalid target format '{}'. Expected 'forge:path' (e.g., 'github:owner/repo')",
                input.target
            );
            tracing::error!(operation = "git_push_local", error = %err);
            err
        })?;

        // Validate and get credentials based on forge type
        let (remote_url, display_target) = match forge {
            "github" => {
                // For GitHub, use the dedicated github_push tool instead
                return Err("Use the 'github_push' tool for GitHub repositories. \
                     git_push_local is for GitLab and Forgejo only."
                    .to_string());
            }
            "gitlab" => {
                // Permission check - GitLab requires push-new-branch permission
                if !config
                    .gitlab
                    .is_allowed(repo_path, crate::scope::GlOpType::PushNewBranch, None)
                {
                    return Err(format!(
                        "push-new-branch permission not granted for gitlab:{}",
                        repo_path
                    ));
                }
                let token = crate::core::get_token_trimmed("GITLAB_TOKEN", None)
                    .ok_or("No GitLab token available (GITLAB_TOKEN not set)")?;
                // Use configured host or default to gitlab.com
                let host = config.gitlab.host.as_deref().unwrap_or("gitlab.com");

                let url = format!("https://oauth2:{}@{}/{}.git", token, host, repo_path);
                (url, format!("gitlab:{}", repo_path))
            }
            "forgejo" => {
                // Find the matching Forgejo scope with push-new-branch permission
                let scope = config
                    .forgejo
                    .iter()
                    .find(|s| {
                        s.is_allowed(repo_path, crate::scope::ForgejoOpType::PushNewBranch, None)
                    })
                    .ok_or_else(|| {
                        format!(
                            "push-new-branch permission not granted for forgejo:{}",
                            repo_path
                        )
                    })?;
                let token = scope
                    .token
                    .as_ref()
                    .map(|t| t.expose_secret().to_string())
                    .or_else(|| std::env::var("FORGEJO_TOKEN").ok())
                    .filter(|t| !t.is_empty())
                    .ok_or("No Forgejo token available")?;

                let url = format!(
                    "https://{}:{}@{}/{}.git",
                    "token", token, scope.host, repo_path
                );
                (url, format!("forgejo:{}", repo_path))
            }
            _ => {
                return Err(format!(
                    "Unknown forge '{}'. Supported: gitlab, forgejo (use github_push for GitHub)",
                    forge
                ));
            }
        };

        // repo_path is already validated to be under /workspaces by the WorkspacePath type
        let agent_repo_path = input.repo_path.as_path();

        // Verify the path exists and is a git repository
        let git_dir = agent_repo_path.join(".git");
        if !git_dir.exists() {
            return Err(format!(
                "Not a git repository (no .git directory): {}",
                agent_repo_path
            ));
        }

        // Build the branch name with agent- prefix
        let branch = format!("agent-{}", input.description);

        // Create a temporary directory for the trusted clone
        let temp_dir = tempfile::TempDir::new()
            .map_err(|e| format!("Failed to create temp directory: {e}"))?;
        let trusted_clone_path = temp_dir.path();
        let trusted_clone_path_utf8 = camino::Utf8Path::from_path(trusted_clone_path)
            .ok_or("Temporary directory path is not valid UTF-8")?;

        // Clone from the remote using the agent's repo as a reference for object borrowing.
        // This is safe because --reference only reads object data, not hooks/config.
        // We use --dissociate to copy objects and remove the alternates link after clone.
        // We use --no-checkout since we only need to push, not checkout files.
        // We use --filter=blob:none for a blobless clone (we'll fetch specific objects).
        let clone_args = vec![
            "clone".to_string(),
            "--reference".to_string(),
            agent_repo_path.to_string(),
            "--dissociate".to_string(),
            "--no-checkout".to_string(),
            "--filter=blob:none".to_string(),
            remote_url.clone(),
            ".".to_string(),
        ];

        self.exec_command_in_dir("git", &clone_args, trusted_clone_path_utf8)
            .await
            .map_err(|e| {
                tracing::error!(
                    operation = "git_push_local",
                    step = "clone",
                    target = %display_target,
                    error = %e,
                    "failed to create trusted clone"
                );
                format!("Failed to create trusted clone: {e}")
            })?;

        // Fetch the specific commit from the agent's repo into our trusted clone.
        // This is safe because fetching only transfers git objects (blobs, trees, commits),
        // not hooks or config.
        // Note: safe.directory is configured globally at startup to allow reading from
        // workspace repos that may be owned by a different uid.
        let fetch_args = vec![
            "fetch".to_string(),
            agent_repo_path.to_string(),
            input.commit_sha.to_string(),
        ];

        self.exec_command_in_dir("git", &fetch_args, trusted_clone_path_utf8)
            .await
            .map_err(|e| {
                tracing::error!(
                    operation = "git_push_local",
                    step = "fetch",
                    target = %display_target,
                    commit = %input.commit_sha,
                    error = %e,
                    "failed to fetch commit from agent repo"
                );
                format!(
                    "Failed to fetch commit {} from agent repo: {e}. \
                     Make sure the commit exists in the local repository.",
                    input.commit_sha
                )
            })?;

        // Push the commit to the remote branch from our trusted clone.
        // This is safe because we're running git in our own trusted clone directory.
        let refspec = format!("{}:refs/heads/{}", input.commit_sha, branch);
        let push_args = vec!["push".to_string(), "origin".to_string(), refspec];

        self.exec_command_in_dir("git", &push_args, trusted_clone_path_utf8)
            .await
            .map_err(|e| {
                tracing::error!(
                    operation = "git_push_local",
                    step = "push",
                    target = %display_target,
                    commit = %input.commit_sha,
                    branch = %branch,
                    error = %e,
                    "git push failed"
                );
                format!("Git push failed: {e}")
            })?;

        tracing::info!(
            operation = "git_push_local",
            target = %display_target,
            commit = %input.commit_sha,
            branch = %branch,
            "git push completed successfully"
        );

        Ok(format!(
            "Successfully pushed commit {} to branch '{}' on {}. \
             You can now create a draft PR from this branch.",
            input.commit_sha, branch, display_target
        ))
        // temp_dir is automatically cleaned up when dropped
    }

    /// Inner implementation for GitHub push with optional draft PR creation.
    ///
    /// Pushes a commit to GitHub and optionally creates a draft PR.
    async fn github_push_inner(
        &self,
        config: &ScopeConfig,
        input: &GithubPushInput,
    ) -> Result<String, String> {
        let repo_string = input.repo.as_str();
        let repo = repo_string.as_str();

        // When using a fork, PushNewBranch is checked on the fork repo (discovered
        // below) rather than the upstream. Without a fork, check it on upstream.
        if !input.use_fork && !config.gh.is_allowed(repo, GhOpType::PushNewBranch, None) {
            return Err(format!(
                "push-new-branch permission not granted for github:{}",
                repo
            ));
        }

        // CreateDraft permission is always checked on the upstream repo
        if input.create_draft_pr && !config.gh.is_allowed(repo, GhOpType::CreateDraft, None) {
            return Err(format!(
                "create-draft permission not granted for github:{}. \
                 For github_push with create_draft_pr=true, both push-new-branch \
                 and create-draft permissions are required.",
                repo
            ));
        }

        // Validate PR fields if creating a draft PR
        let (base, title) = if input.create_draft_pr {
            let base = input
                .base
                .as_ref()
                .ok_or("base is required when create_draft_pr is true (e.g., \"main\")")?;
            let title = input
                .title
                .as_ref()
                .ok_or("title is required when create_draft_pr is true")?;
            (Some(base.as_str()), Some(title.as_str()))
        } else {
            (None, None)
        };

        tracing::info!(
            operation = "github_push",
            repo = %repo,
            commit = %input.commit_sha,
            branch_desc = %input.description,
            create_draft_pr = %input.create_draft_pr,
            use_fork = %input.use_fork,
            "starting GitHub push operation"
        );

        // Get GitHub token
        let token = crate::core::get_token_trimmed("GH_TOKEN", Some("GITHUB_TOKEN"))
            .ok_or("No GitHub token available (GH_TOKEN or GITHUB_TOKEN not set)")?;

        // If use_fork is set, discover the authenticated user's fork via GraphQL
        // and push there instead of the upstream.
        let (push_repo, fork_owner) = if input.use_fork {
            let (upstream_owner, upstream_name) = repo
                .split_once('/')
                .ok_or_else(|| format!("Invalid repo format: {repo}"))?;

            let graphql_query = serde_json::json!({
                "query": "query($owner: String!, $repo: String!) { \
                    repository(owner: $owner, name: $repo) { \
                        forks(affiliations: [OWNER], first: 1) { \
                            nodes { nameWithOwner url } \
                        } \
                    } \
                }",
                "variables": {
                    "owner": upstream_owner,
                    "repo": upstream_name,
                }
            });

            let gql_args = vec![
                "api".to_string(),
                "graphql".to_string(),
                "--input".to_string(),
                "-".to_string(),
            ];

            let gql_payload = graphql_query.to_string();
            let gql_output = self
                .exec_command_with_stdin("gh", &gql_args, &gql_payload)
                .await
                .map_err(|e| format!("Failed to query for fork: {e}"))?;

            // Check for process failure (exec_command_with_stdin returns Ok
            // even on non-zero exit)
            if gql_output.contains("[exit code:") {
                return Err(format!("Fork discovery GraphQL query failed: {gql_output}"));
            }

            let gql_value: serde_json::Value = serde_json::from_str(&gql_output)
                .map_err(|e| format!("Failed to parse fork query response: {e}"))?;

            // Check for GraphQL-level errors (returned with HTTP 200)
            if let Some(errors) = gql_value.get("errors") {
                return Err(format!(
                    "Fork discovery GraphQL query returned errors: {errors}"
                ));
            }

            // Check that the repository was found
            if gql_value.pointer("/data/repository").is_none() {
                return Err(format!(
                    "Repository {repo} not found or not accessible with the current token"
                ));
            }

            let fork_node = gql_value
                .pointer("/data/repository/forks/nodes/0")
                .ok_or_else(|| {
                    format!(
                        "No fork of {repo} found owned by the authenticated user. \
                         Create a fork first."
                    )
                })?;

            let name_with_owner = fork_node
                .get("nameWithOwner")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "Fork response missing nameWithOwner field".to_string())?;

            let fork_owner = name_with_owner
                .split_once('/')
                .map(|(owner, _)| owner)
                .ok_or_else(|| format!("Invalid fork nameWithOwner format: {name_with_owner}"))?;

            // Check PushNewBranch permission on the fork repo.
            // Note: the fork repo must be in the scope config (e.g. via
            // --gh-repo 'fork-owner/repo:push-new-branch' or a wildcard
            // like 'fork-owner/*:push-new-branch').
            if !config
                .gh
                .is_allowed(name_with_owner, GhOpType::PushNewBranch, None)
            {
                return Err(format!(
                    "push-new-branch permission not granted for fork github:{}. \
                     Add it to the scope config (e.g. --gh-repo '{}:push-new-branch').",
                    name_with_owner, name_with_owner
                ));
            }

            tracing::info!(
                operation = "github_push",
                upstream = %repo,
                fork = %name_with_owner,
                "discovered user fork"
            );

            (name_with_owner.to_string(), Some(fork_owner.to_string()))
        } else {
            (repo.to_string(), None)
        };

        let remote_url = format!(
            "https://x-access-token:{}@github.com/{}.git",
            token, push_repo
        );

        // Validate local repository
        let agent_repo_path = input.repo_path.as_path();
        let git_dir = agent_repo_path.join(".git");
        if !git_dir.exists() {
            return Err(format!(
                "Not a git repository (no .git directory): {}",
                agent_repo_path
            ));
        }

        // Build the branch name with agent- prefix
        let branch = format!("agent-{}", input.description);

        // Create a temporary directory for the trusted clone
        let temp_dir = tempfile::TempDir::new()
            .map_err(|e| format!("Failed to create temp directory: {e}"))?;
        let trusted_clone_path = temp_dir.path();
        let trusted_clone_path_utf8 = camino::Utf8Path::from_path(trusted_clone_path)
            .ok_or("Temporary directory path is not valid UTF-8")?;

        // Clone from the remote using the agent's repo as a reference
        let clone_args = vec![
            "clone".to_string(),
            "--reference".to_string(),
            agent_repo_path.to_string(),
            "--dissociate".to_string(),
            "--no-checkout".to_string(),
            "--filter=blob:none".to_string(),
            remote_url.clone(),
            ".".to_string(),
        ];

        self.exec_command_in_dir("git", &clone_args, trusted_clone_path_utf8)
            .await
            .map_err(|e| {
                tracing::error!(
                    operation = "github_push",
                    step = "clone",
                    repo = %repo,
                    error = %e,
                    "failed to create trusted clone"
                );
                format!("Failed to create trusted clone: {e}")
            })?;

        // Fetch the specific commit from the agent's repo.
        // Note: safe.directory is configured globally at startup to allow reading from
        // workspace repos that may be owned by a different uid.
        let fetch_args = vec![
            "fetch".to_string(),
            agent_repo_path.to_string(),
            input.commit_sha.to_string(),
        ];

        self.exec_command_in_dir("git", &fetch_args, trusted_clone_path_utf8)
            .await
            .map_err(|e| {
                tracing::error!(
                    operation = "github_push",
                    step = "fetch",
                    repo = %repo,
                    commit = %input.commit_sha,
                    error = %e,
                    "failed to fetch commit from agent repo"
                );
                format!(
                    "Failed to fetch commit {} from agent repo: {e}. \
                     Make sure the commit exists in the local repository.",
                    input.commit_sha
                )
            })?;

        // Push the commit to the remote branch
        let refspec = format!("{}:refs/heads/{}", input.commit_sha, branch);
        let push_args = vec!["push".to_string(), "origin".to_string(), refspec];

        self.exec_command_in_dir("git", &push_args, trusted_clone_path_utf8)
            .await
            .map_err(|e| {
                tracing::error!(
                    operation = "github_push",
                    step = "push",
                    repo = %repo,
                    commit = %input.commit_sha,
                    branch = %branch,
                    error = %e,
                    "git push failed"
                );
                format!("Git push failed: {e}")
            })?;

        tracing::info!(
            operation = "github_push",
            repo = %repo,
            commit = %input.commit_sha,
            branch = %branch,
            "push completed successfully"
        );

        // If not creating a draft PR, return now
        if !input.create_draft_pr {
            return Ok(format!(
                "Successfully pushed commit {} to branch '{}' on github:{}",
                input.commit_sha, branch, push_repo
            ));
        }

        // Create the draft PR
        tracing::info!(
            operation = "github_push",
            repo = %repo,
            branch = %branch,
            "creating draft PR"
        );

        // If no body was provided, use the commit message body.
        // This matches the GitHub web UI behavior for single-commit PRs.
        let pr_body = match &input.body {
            Some(b) => b.clone(),
            None => {
                let log_args = vec![
                    "log".to_string(),
                    "-1".to_string(),
                    "--format=%b".to_string(),
                    input.commit_sha.to_string(),
                ];
                self.exec_command_in_dir("git", &log_args, trusted_clone_path_utf8)
                    .await
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            }
        };

        // When pushing to a fork, GitHub requires the head ref in cross-repo
        // format: "{fork_owner}:{branch}". Otherwise just the branch name.
        let pr_head = match &fork_owner {
            Some(owner) => format!("{owner}:{branch}"),
            None => branch.clone(),
        };

        let endpoint = format!("repos/{}/pulls", repo);
        let payload = serde_json::json!({
            "title": title.unwrap(),
            "head": pr_head,
            "base": base.unwrap(),
            "body": pr_body,
            "draft": true,
        });

        let args = vec![
            "api".to_string(),
            "--method=POST".to_string(),
            endpoint,
            "--input".to_string(),
            "-".to_string(),
        ];

        let payload_str = payload.to_string();
        let pr_output = self
            .exec_command_with_stdin("gh", &args, &payload_str)
            .await
            .map_err(|e| {
                tracing::error!(
                    operation = "github_push",
                    step = "create_pr",
                    repo = %repo,
                    branch = %branch,
                    error = %e,
                    "failed to create draft PR"
                );
                format!("Push succeeded but failed to create draft PR: {e}")
            })?;

        // Check if the PR creation response indicates an error
        let is_error = pr_output.contains("[exit code:")
            || pr_output.contains("\"message\":")
            || pr_output.contains("\"errors\":");

        if is_error {
            tracing::error!(
                operation = "github_push",
                step = "create_pr",
                repo = %repo,
                branch = %branch,
                response = %pr_output,
                "draft PR creation failed"
            );
            return Err(format!(
                "Push succeeded to branch '{}' but draft PR creation failed: {}",
                branch, pr_output
            ));
        }

        tracing::info!(
            operation = "github_push",
            repo = %repo,
            branch = %branch,
            "draft PR created successfully"
        );

        // Parse the PR URL from the response for a nicer message
        let pr_url = serde_json::from_str::<serde_json::Value>(&pr_output)
            .ok()
            .and_then(|v| v.get("html_url").and_then(|u| u.as_str()).map(String::from));

        match pr_url {
            Some(url) => Ok(format!(
                "Successfully pushed commit {} to branch '{}' and created draft PR: {}",
                input.commit_sha, branch, url
            )),
            None => Ok(format!(
                "Successfully pushed commit {} to branch '{}' and created draft PR.\n\nResponse:\n{}",
                input.commit_sha, branch, pr_output
            )),
        }
    }

    /// Handle the GitHub API operation.
    async fn github_api_impl(
        &self,
        config: &ScopeConfig,
        endpoint: &str,
        method: Option<&str>,
        body: Option<serde_json::Value>,
        jq: Option<&str>,
    ) -> Result<CallToolResult, McpError> {
        // Normalize method (default to GET) and validate against whitelist
        let method = method
            .map(|m| m.to_uppercase())
            .unwrap_or_else(|| "GET".to_string());
        const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE"];
        if !ALLOWED_METHODS.contains(&method.as_str()) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Invalid HTTP method: {method}. Allowed methods: GET, POST, PUT, PATCH, DELETE"
            ))]));
        }
        let is_write = method != "GET";

        // For GraphQL endpoint, reject writes (mutations should use dedicated tools)
        if endpoint == "graphql" {
            if is_write {
                return Ok(CallToolResult::error(vec![Content::text(
                    "GraphQL mutations are not supported via api operation. Use dedicated tools.",
                )]));
            }
            if !config.gh.graphql_read_allowed() {
                return Ok(CallToolResult::error(vec![Content::text(
                    "GraphQL read access not allowed. Set `read = true` or `graphql = \"read\"` in [gh] config.",
                )]));
            }
        }

        // Extract repo from endpoint path (may be None for global endpoints like /search, /gists)
        let repo = github::extract_repo_from_api_path(endpoint);

        // Extract resource ref (e.g., "pr/123" or "issue/456") for scoped write permissions
        let resource_ref = github::extract_resource_from_api_path(endpoint);

        // Permission check
        if is_write {
            // For writes, we require a repo
            let repo = match repo {
                Some(r) => r,
                None => {
                    return Ok(CallToolResult::error(vec![Content::text(
                        "Write operations require a repository path. \
                         Use path like repos/owner/repo/...",
                    )]));
                }
            };
            // Check WriteResource permission (can be scoped to PR/issue)
            if !config
                .gh
                .is_allowed(&repo, GhOpType::WriteResource, resource_ref.as_deref())
            {
                let scope_msg = if let Some(ref res) = resource_ref {
                    format!(" (resource: {})", res)
                } else {
                    String::new()
                };
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Write access not allowed for repository: {repo}{scope_msg}"
                ))]));
            }
            // Log write operation
            tracing::info!(
                operation = "github_api",
                method = %method,
                repo = %repo,
                endpoint = %endpoint,
                resource = resource_ref.as_deref().unwrap_or("-"),
                "github API write operation"
            );
        } else {
            // For reads, check permission based on whether we have a repo
            match repo {
                Some(ref repo) => {
                    // Have a repo - check per-repo or global permission
                    if !config.gh.is_read_allowed(repo) {
                        return Ok(CallToolResult::error(vec![Content::text(format!(
                            "Read access not allowed for repository: {repo}"
                        ))]));
                    }
                }
                None => {
                    // No repo in path (e.g., /search, /gists, /user) - require global read
                    if !config.gh.global_read_allowed() {
                        return Ok(CallToolResult::error(vec![Content::text(
                            "This endpoint requires global read access. \
                             Set `read = true` in [gh] config, or use /repos/owner/repo/... paths.",
                        )]));
                    }
                }
            }
            // Count read operation (logged in aggregate)
            self.logging.read_ops.increment();
        }

        // Build the gh api command args
        let mut args = vec![
            "api".to_string(),
            format!("--method={}", method),
            endpoint.to_string(),
        ];

        if let Some(jq_expr) = jq {
            args.push("--jq".to_string());
            args.push(jq_expr.to_string());
        }

        // Execute with or without body
        if let Some(body_value) = body {
            args.push("--input".to_string());
            args.push("-".to_string());
            let body_str = body_value.to_string();
            match self.exec_command_with_stdin("gh", &args, &body_str).await {
                Ok(output) => {
                    if output.is_empty() {
                        Ok(CallToolResult::success(vec![Content::text("(no output)")]))
                    } else {
                        Ok(CallToolResult::success(vec![Content::text(output)]))
                    }
                }
                Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
            }
        } else {
            match self.exec_command("gh", &args).await {
                Ok(output) => {
                    if output.is_empty() {
                        Ok(CallToolResult::success(vec![Content::text("(no output)")]))
                    } else {
                        Ok(CallToolResult::success(vec![Content::text(output)]))
                    }
                }
                Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
            }
        }
    }

    /// Handle pending review operations.
    #[allow(clippy::too_many_arguments)]
    async fn github_pending_review_impl(
        &self,
        config: &ScopeConfig,
        operation: &str,
        repo: &str,
        pull_number: u64,
        review_id: Option<u64>,
        body: Option<&str>,
        comments: Option<Vec<ReviewComment>>,
        dry_run: bool,
        replace: bool,
    ) -> Result<CallToolResult, McpError> {
        // Check permission
        if !config
            .gh
            .is_allowed(repo, GhOpType::ManagePendingReview, None)
        {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "pending-review permission not granted for repository: {repo}"
            ))]));
        }

        // Parse operation
        let op = match operation.to_lowercase().as_str() {
            "list" => PendingReviewOp::List,
            "create" => PendingReviewOp::Create,
            "get" => PendingReviewOp::Get,
            "update" => PendingReviewOp::Update,
            "delete" => PendingReviewOp::Delete,
            other => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Unknown operation: {other}. \
                     Use: list, create, get, update, delete, extended-help"
                ))]));
            }
        };

        // dry_run and replace only valid for create
        if dry_run && op != PendingReviewOp::Create {
            return Ok(CallToolResult::error(vec![Content::text(
                "dry_run is only supported with the 'create' operation",
            )]));
        }
        if replace && op != PendingReviewOp::Create {
            return Ok(CallToolResult::error(vec![Content::text(
                "replace is only supported with the 'create' operation",
            )]));
        }

        // Validate review_id for operations that need it
        if matches!(
            op,
            PendingReviewOp::Get | PendingReviewOp::Update | PendingReviewOp::Delete
        ) && review_id.is_none()
        {
            return Ok(CallToolResult::error(vec![Content::text(
                "review_id is required for get/update/delete operations",
            )]));
        }

        // Build the endpoint path
        let endpoint = match review_id {
            Some(id) => format!("repos/{}/pulls/{}/reviews/{}", repo, pull_number, id),
            None => format!("repos/{}/pulls/{}/reviews", repo, pull_number),
        };

        // For update/delete, first fetch the review to validate marker token
        if matches!(op, PendingReviewOp::Update | PendingReviewOp::Delete) {
            let get_args = vec![
                "api".to_string(),
                "--method=GET".to_string(),
                endpoint.clone(),
            ];

            let review_json = match self.exec_command("gh", &get_args).await {
                Ok(output) => output,
                Err(e) => return Ok(CallToolResult::error(vec![Content::text(e)])),
            };

            let review: serde_json::Value = match serde_json::from_str(&review_json) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Failed to parse review JSON: {e}"
                    ))]));
                }
            };

            // Validate marker token
            if let Err(e) = github::validate_review_marker(&review) {
                return Ok(CallToolResult::error(vec![Content::text(format!("{e:#}"))]));
            }

            // Validate pending state
            if let Err(e) = github::validate_review_pending(&review) {
                return Ok(CallToolResult::error(vec![Content::text(format!("{e:#}"))]));
            }
        }

        // Execute the operation
        match op {
            PendingReviewOp::List | PendingReviewOp::Get => {
                // Read operations - count for aggregated logging
                self.logging.read_ops.increment();
                let args = vec!["api".to_string(), "--method=GET".to_string(), endpoint];
                match self.exec_command("gh", &args).await {
                    Ok(output) => Ok(CallToolResult::success(vec![Content::text(output)])),
                    Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
                }
            }

            PendingReviewOp::Create => {
                let body_text = body.unwrap_or("");
                let body_with_marker = if body_text.contains(REVIEW_MARKER_TOKEN) {
                    body_text.to_string()
                } else {
                    format!("{}\n\n{}", REVIEW_MARKER_TOKEN, body_text)
                };

                let mut payload = serde_json::json!({
                    "body": body_with_marker,
                });

                if let Some(ref comments) = comments {
                    payload["comments"] = serde_json::to_value(comments).unwrap_or_default();
                }

                let comment_count = comments.as_ref().map_or(0, |c| c.len());

                // Dry run: return a summary without submitting
                if dry_run {
                    return Ok(CallToolResult::success(vec![Content::text(format!(
                        "Dry run: would create pending review on {repo}#{pull_number}\n\
                         Body: {} chars\n\
                         Comments: {comment_count}",
                        body_text.len(),
                    ))]));
                }

                // Check for existing pending service-gator reviews.
                let list_endpoint = format!("repos/{}/pulls/{}/reviews", repo, pull_number);
                let list_args = vec!["api".to_string(), "--method=GET".to_string(), list_endpoint];

                let existing_ids: Vec<u64> = match self.exec_command("gh", &list_args).await {
                    Ok(output) => serde_json::from_str::<Vec<serde_json::Value>>(&output)
                        .unwrap_or_default()
                        .iter()
                        .filter_map(|r| {
                            let state = r.get("state")?.as_str()?;
                            let rbody = r.get("body")?.as_str()?;
                            let id = r.get("id")?.as_u64()?;
                            if state == "PENDING" && github::review_has_marker(rbody) {
                                Some(id)
                            } else {
                                None
                            }
                        })
                        .collect(),
                    Err(ref e) => {
                        tracing::warn!(
                            operation = "github_pending_review",
                            action = "list_existing",
                            repo = %repo,
                            pull_number = pull_number,
                            error = %e,
                            "failed to list existing reviews, proceeding with create"
                        );
                        Vec::new()
                    }
                };

                if !existing_ids.is_empty() && !replace {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "A pending service-gator review already exists on \
                         {repo}#{pull_number} (review id: {}). \
                         Set replace=true to delete it and create a new one.",
                        existing_ids[0]
                    ))]));
                }

                // Delete existing reviews if replace is set
                for old_id in &existing_ids {
                    tracing::info!(
                        operation = "github_pending_review",
                        action = "replace_delete",
                        repo = %repo,
                        pull_number = pull_number,
                        review_id = old_id,
                        "deleting existing pending review (replace=true)"
                    );
                    let del_endpoint =
                        format!("repos/{}/pulls/{}/reviews/{}", repo, pull_number, old_id);
                    let del_args = vec![
                        "api".to_string(),
                        "--method=DELETE".to_string(),
                        del_endpoint,
                    ];
                    if let Err(e) = self.exec_command("gh", &del_args).await {
                        return Ok(CallToolResult::error(vec![Content::text(format!(
                            "Failed to delete existing review {old_id}: {e}"
                        ))]));
                    }
                }

                tracing::info!(
                    operation = "github_pending_review",
                    action = "create",
                    repo = %repo,
                    pull_number = pull_number,
                    comment_count = comment_count,
                    "creating pending review"
                );

                let args = vec![
                    "api".to_string(),
                    "--method=POST".to_string(),
                    endpoint,
                    "--input".to_string(),
                    "-".to_string(),
                ];

                let payload_str = payload.to_string();
                match self
                    .exec_command_with_stdin("gh", &args, &payload_str)
                    .await
                {
                    Ok(output) => Ok(CallToolResult::success(vec![Content::text(output)])),
                    Err(e) => {
                        tracing::error!(
                            operation = "github_pending_review",
                            action = "create",
                            repo = %repo,
                            pull_number = pull_number,
                            error = %e,
                            "failed to create pending review"
                        );
                        Ok(CallToolResult::error(vec![Content::text(e)]))
                    }
                }
            }

            PendingReviewOp::Update => {
                tracing::info!(
                    operation = "github_pending_review",
                    action = "update",
                    repo = %repo,
                    pull_number = pull_number,
                    review_id = ?review_id,
                    "updating pending review"
                );

                let body_text = match body {
                    Some(b) => b,
                    None => {
                        return Ok(CallToolResult::error(vec![Content::text(
                            "body is required for update operation",
                        )]));
                    }
                };

                let body_with_marker = if body_text.contains(REVIEW_MARKER_TOKEN) {
                    body_text.to_string()
                } else {
                    format!("{}\n\n{}", REVIEW_MARKER_TOKEN, body_text)
                };

                let payload = serde_json::json!({
                    "body": body_with_marker,
                });

                let args = vec![
                    "api".to_string(),
                    "--method=PUT".to_string(),
                    endpoint,
                    "--input".to_string(),
                    "-".to_string(),
                ];

                let payload_str = payload.to_string();
                match self
                    .exec_command_with_stdin("gh", &args, &payload_str)
                    .await
                {
                    Ok(output) => Ok(CallToolResult::success(vec![Content::text(output)])),
                    Err(e) => {
                        tracing::error!(
                            operation = "github_pending_review",
                            action = "update",
                            repo = %repo,
                            pull_number = pull_number,
                            error = %e,
                            "failed to update pending review"
                        );
                        Ok(CallToolResult::error(vec![Content::text(e)]))
                    }
                }
            }

            PendingReviewOp::Delete => {
                tracing::info!(
                    operation = "github_pending_review",
                    action = "delete",
                    repo = %repo,
                    pull_number = pull_number,
                    review_id = ?review_id,
                    "deleting pending review"
                );

                let args = vec!["api".to_string(), "--method=DELETE".to_string(), endpoint];

                match self.exec_command("gh", &args).await {
                    Ok(output) => {
                        if output.is_empty() {
                            Ok(CallToolResult::success(vec![Content::text(
                                "Review deleted successfully",
                            )]))
                        } else {
                            Ok(CallToolResult::success(vec![Content::text(output)]))
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            operation = "github_pending_review",
                            action = "delete",
                            repo = %repo,
                            pull_number = pull_number,
                            error = %e,
                            "failed to delete pending review"
                        );
                        Ok(CallToolResult::error(vec![Content::text(e)]))
                    }
                }
            }
        }
    }
}

/// Tool definitions for the MCP server.
#[tool_router]
impl ServiceGatorServer {
    /// GitHub REST API access.
    ///
    /// Supports both read (GET) and write (POST/PUT/PATCH/DELETE) operations.
    /// Write operations require appropriate permissions for the target repository.
    #[tool(description = "GitHub REST API access. \
        Use endpoint like 'repos/owner/repo/pulls' for repository operations. \
        Supports GET (default), POST, PUT, PATCH, DELETE methods. \
        Write operations require write permission for the target repository. \
        Use the 'status' tool to view your current permissions.")]
    async fn github_api_tool(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<GithubApiInput>,
    ) -> Result<CallToolResult, McpError> {
        let config = get_scopes_from_parts(&parts)?;
        self.github_api_impl(
            &config,
            &input.endpoint,
            input.method.as_deref(),
            input.body,
            input.jq.as_deref(),
        )
        .await
    }

    /// Manage pending PR reviews on GitHub.
    ///
    /// Supports operations: list, create, get, update, delete, extended-help.
    /// The create operation errors if a pending service-gator review already
    /// exists; set replace=true to delete and recreate.
    /// Requires pending-review permission for the target repository.
    #[tool(description = "Manage pending PR reviews on GitHub. \
        Operations: list, create, get, update, delete, extended-help. \
        The 'create' operation errors if a pending review already exists; \
        set replace=true to delete and recreate. \
        Set dry_run=true to validate without submitting. \
        Use 'extended-help' for detailed documentation. \
        Requires pending-review permission for the target repository. \
        Use the 'status' tool to view your current permissions.")]
    async fn github_pending_review_tool(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<GithubPendingReviewInput>,
    ) -> Result<CallToolResult, McpError> {
        let config = get_scopes_from_parts(&parts)?;

        if input.operation.eq_ignore_ascii_case("extended-help") {
            return Ok(CallToolResult::success(vec![Content::text(
                REVIEW_TOOL_HELP,
            )]));
        }

        self.github_pending_review_impl(
            &config,
            &input.operation,
            &input.repo,
            input.pull_number,
            input.review_id,
            input.body.as_deref(),
            input.comments,
            input.dry_run,
            input.replace,
        )
        .await
    }

    /// Create a new agent branch on GitHub.
    ///
    /// This tool allows sandboxed AI agents to create new branches for PRs.
    /// Branch names are enforced to use the `agent-` prefix for safety.
    #[tool(
        description = "Create a new branch for a draft PR. Branch names are enforced to start with 'agent-' prefix (e.g., 'agent-42-fix-typo' or 'agent-add-feature'). The branch must NOT already exist. Requires push-new-branch permission."
    )]
    async fn gh_create_branch(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<GhCreateBranchInput>,
    ) -> Result<CallToolResult, McpError> {
        let config = get_scopes_from_parts(&parts)?;
        let repo_str = input.repo.to_string();

        // Check permission - requires push-new-branch or higher
        if !config
            .gh
            .is_allowed(&repo_str, GhOpType::PushNewBranch, None)
        {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "push-new-branch permission not granted for repository: {}",
                repo_str
            ))]));
        }

        // Input validation is handled by the newtypes (CommitSha, BranchDescription, RepoName)
        // during deserialization - if we get here, the inputs are valid.

        // Build the enforced branch name: agent-[issue-]description
        let branch = match input.issue_number {
            Some(issue) => format!("agent-{}-{}", issue, input.description),
            None => format!("agent-{}", input.description),
        };

        // Check if the branch already exists (MUST NOT exist for create-draft)
        let ref_path = format!("repos/{}/git/refs/heads/{}", repo_str, branch);
        let check_args = vec![
            "api".to_string(),
            "--method=GET".to_string(),
            ref_path.clone(),
        ];

        let ref_exists = match self.exec_command("gh", &check_args).await {
            Ok(output) => {
                // If we get valid JSON with "ref" field, the ref exists
                !output.contains("Not Found") && output.contains("\"ref\"")
            }
            Err(_) => false,
        };

        if ref_exists {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Branch '{}' already exists. For push-new-branch permission, \
                 you can only create NEW branches. Use a different description \
                 or issue number.",
                branch
            ))]));
        }

        tracing::info!(
            operation = "gh_create_branch",
            repo = %repo_str,
            branch = %branch,
            commit = %input.commit_sha,
            issue_number = ?input.issue_number,
            "creating new agent branch"
        );

        // Create new ref: POST /repos/{owner}/{repo}/git/refs
        let create_path = format!("repos/{}/git/refs", repo_str);
        let payload = serde_json::json!({
            "ref": format!("refs/heads/{}", branch),
            "sha": input.commit_sha.as_str()
        });

        let args = vec![
            "api".to_string(),
            "--method=POST".to_string(),
            create_path,
            "--input".to_string(),
            "-".to_string(),
        ];

        let payload_str = payload.to_string();
        match self
            .exec_command_with_stdin("gh", &args, &payload_str)
            .await
        {
            Ok(output) => {
                if output.contains("\"ref\"") {
                    tracing::info!(
                        operation = "gh_create_branch",
                        repo = %repo_str,
                        branch = %branch,
                        commit = %input.commit_sha,
                        "branch created successfully"
                    );
                    Ok(CallToolResult::success(vec![Content::text(format!(
                        "Successfully created branch '{}' at commit {}. \
                         You can now create a draft PR from this branch.",
                        branch, input.commit_sha
                    ))]))
                } else {
                    Ok(CallToolResult::error(vec![Content::text(format!(
                        "Failed to create branch: {}",
                        output
                    ))]))
                }
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    /// Update the head of an existing PR's branch.
    ///
    /// This tool allows pushing new commits to a PR that the agent has access to.
    /// The branch name is looked up from the PR - agents cannot specify arbitrary branches.
    #[tool(
        description = "Update an existing PR's head branch with a new commit. The branch is looked up from the PR number - you cannot specify arbitrary branch names. Requires push-new-branch or write permission on the repository."
    )]
    async fn gh_update_pr_head(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<GhUpdatePrHeadInput>,
    ) -> Result<CallToolResult, McpError> {
        let config = get_scopes_from_parts(&parts)?;
        let repo_str = input.repo.to_string();

        // Check permission first - need push-new-branch or write access to update a PR head
        let has_write = config.gh.is_allowed(&repo_str, GhOpType::Write, None);
        let has_push_new_branch = config
            .gh
            .is_allowed(&repo_str, GhOpType::PushNewBranch, None);

        if !(has_write || has_push_new_branch) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Cannot update PR #{} branch. push-new-branch permission not granted for repo {}",
                input.pull_number, repo_str
            ))]));
        }

        // Now look up the PR to get the branch name
        let pr_endpoint = format!("repos/{}/pulls/{}", repo_str, input.pull_number);
        let pr_args = vec!["api".to_string(), "--method=GET".to_string(), pr_endpoint];

        let pr_json = match self.exec_command("gh", &pr_args).await {
            Ok(output) => output,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to fetch PR #{}: {}",
                    input.pull_number, e
                ))]));
            }
        };

        // Parse PR JSON to get branch name
        let pr_data: serde_json::Value = match serde_json::from_str(&pr_json) {
            Ok(v) => v,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to parse PR data: {}",
                    e
                ))]));
            }
        };

        let branch_name = match pr_data["head"]["ref"].as_str() {
            Some(name) => name.to_string(),
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Could not find branch name in PR data".to_string(),
                )]));
            }
        };

        // For fork-based PRs, the head branch lives in the fork repo, not the
        // base repo. Use head.repo.full_name so this works for both same-repo
        // and cross-repo (fork) PRs.
        let head_repo = match pr_data["head"]["repo"]["full_name"].as_str() {
            Some(name) => name.to_string(),
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Could not find head repository (head.repo.full_name) in PR data".to_string(),
                )]));
            }
        };

        // If the head repo differs from the input repo (fork-based PR), verify
        // we also have push permission on the fork.
        if head_repo != repo_str {
            let fork_has_write = config.gh.is_allowed(&head_repo, GhOpType::Write, None);
            let fork_has_push = config
                .gh
                .is_allowed(&head_repo, GhOpType::PushNewBranch, None);
            if !(fork_has_write || fork_has_push) {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "PR #{} head branch is in fork repo '{}', but push-new-branch permission is not granted for that repo",
                    input.pull_number, head_repo
                ))]));
            }
        }

        tracing::info!(
            operation = "gh_update_pr_head",
            repo = %repo_str,
            head_repo = %head_repo,
            pull_number = %input.pull_number,
            branch = %branch_name,
            commit = %input.commit_sha,
            "updating PR head branch"
        );

        // Update the branch ref in the head repo (which may be a fork)
        let ref_path = format!("repos/{}/git/refs/heads/{}", head_repo, branch_name);
        let payload = serde_json::json!({
            "sha": input.commit_sha.as_str(),
            "force": true
        });

        let args = vec![
            "api".to_string(),
            "--method=PATCH".to_string(),
            ref_path,
            "--input".to_string(),
            "-".to_string(),
        ];

        let payload_str = payload.to_string();
        match self
            .exec_command_with_stdin("gh", &args, &payload_str)
            .await
        {
            Ok(output) => {
                if output.contains("\"ref\"") {
                    tracing::info!(
                        operation = "gh_update_pr_head",
                        repo = %repo_str,
                        head_repo = %head_repo,
                        pull_number = %input.pull_number,
                        branch = %branch_name,
                        commit = %input.commit_sha,
                        "PR head updated successfully"
                    );
                    Ok(CallToolResult::success(vec![Content::text(format!(
                        "Successfully updated PR #{} branch '{}' in repo '{}' to commit {}.",
                        input.pull_number, branch_name, head_repo, input.commit_sha
                    ))]))
                } else {
                    tracing::error!(
                        operation = "gh_update_pr_head",
                        repo = %repo_str,
                        head_repo = %head_repo,
                        pull_number = %input.pull_number,
                        error = %output,
                        "failed to update PR head"
                    );
                    Ok(CallToolResult::error(vec![Content::text(format!(
                        "Failed to update branch: {}",
                        output
                    ))]))
                }
            }
            Err(e) => {
                tracing::error!(
                    operation = "gh_update_pr_head",
                    repo = %repo_str,
                    head_repo = %head_repo,
                    pull_number = %input.pull_number,
                    error = %e,
                    "failed to update PR head"
                );
                Ok(CallToolResult::error(vec![Content::text(e)]))
            }
        }
    }

    /// Push a local commit to a remote git repository.
    ///
    /// This tool safely pushes commits from an agent's local repository to GitLab
    /// or Forgejo. For GitHub, use the `github_push` tool instead.
    ///
    /// It creates a temporary trusted clone (using the agent's repo only as a
    /// reference for object borrowing via `--reference`) and pushes from there.
    /// This ensures no hooks, config, or other code execution vectors from the
    /// agent's repository are ever executed.
    ///
    /// Branch names are automatically prefixed with `agent-` to enforce the agent
    /// branch naming convention.
    #[tool(
        description = "Push a local git commit to GitLab or Forgejo (for GitHub use github_push). \
                       The branch will be named 'agent-<description>'. Uses a safe push mechanism \
                       that doesn't execute any code from the local repository. \
                       NOTE: Requires service-gator to have filesystem access to the local git repo."
    )]
    async fn git_push_local(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<GitPushLocalInput>,
    ) -> Result<CallToolResult, McpError> {
        let config = get_scopes_from_parts(&parts)?;

        match self.git_push_local_inner(&config, &input).await {
            Ok(msg) => Ok(CallToolResult::success(vec![Content::text(msg)])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    /// Push a local commit to GitHub, optionally creating a draft PR.
    ///
    /// This is the recommended way for agents to submit work for review on GitHub.
    /// By default, it pushes and creates a draft PR. Set `create_draft_pr: false`
    /// to only push the branch without creating a PR.
    #[tool(
        description = "Push a local git commit to GitHub and optionally create a draft PR. \
                       By default creates a draft PR (set create_draft_pr=false to skip). \
                       The branch will be named 'agent-<description>'. Uses a safe push \
                       mechanism that doesn't execute any code from the local repository. \
                       Set use_fork=true to push to the authenticated user's fork \
                       (discovered automatically via GraphQL) instead of the upstream; \
                       the PR is always created on the upstream. \
                       NOTE: Requires service-gator to have filesystem access to the local git repo."
    )]
    async fn github_push(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<GithubPushInput>,
    ) -> Result<CallToolResult, McpError> {
        let config = get_scopes_from_parts(&parts)?;

        match self.github_push_inner(&config, &input).await {
            Ok(msg) => Ok(CallToolResult::success(vec![Content::text(msg)])),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    /// Execute a GitLab API command within configured scopes.
    /// Operations are restricted by scope permissions (read, draft-mr, approve, write).
    #[tool(
        description = "Execute GitLab API commands within configured scope permissions. Use 'glab api <endpoint> [--jq <expr>]' for API access. Write operations (draft MRs, approvals) available if permitted by scope. Use the 'status' tool to view current capabilities."
    )]
    async fn gl(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<GlToolInput>,
    ) -> Result<CallToolResult, McpError> {
        let args = input.args;
        let config = get_scopes_from_parts(&parts)?;

        // Only allow `glab api` subcommand
        let first_arg = args.first().map(|s| s.as_str());
        if first_arg != Some("api") {
            return Ok(CallToolResult::error(vec![Content::text(
                "Only `glab api` is supported. Use `glab api projects/GROUP%2FPROJECT/...` to access the REST API. For capability information, use the 'status' tool.",
            )]));
        }

        // Parse and validate the API command using clap
        let api = match gitlab::parse_api(&args) {
            Ok(a) => a,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "{e:#}. Only endpoint path and --jq option are allowed."
                ))]));
            }
        };

        // Check per-project permission
        let project = match &api.project {
            Some(p) => p,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Could not determine target project from API path. \
                     Use path like /projects/group%2Fproject/...",
                )]));
            }
        };

        if !config.gitlab.is_read_allowed(project) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Read access not allowed for project: {project}"
            ))]));
        }

        // Build final args with forced GET method and optional hostname
        let final_args = gitlab::build_api_args_with_host(&api.args, config.gitlab.host.as_deref());

        // Count read operation for aggregated logging
        self.logging.read_ops.increment();

        // Execute
        match self.exec_command("glab", &final_args).await {
            Ok(output) => {
                if output.is_empty() {
                    Ok(CallToolResult::success(vec![Content::text("(no output)")]))
                } else {
                    Ok(CallToolResult::success(vec![Content::text(output)]))
                }
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
        }
    }

    /// Execute a Forgejo API command within configured scopes.
    /// Operations are restricted by scope permissions (read, draft-pr, pending-review, write).
    #[tool(
        description = "Execute Forgejo/Gitea API commands within configured scope permissions. Use 'api <endpoint>' for API access. Write operations (draft PRs, pending reviews) available if permitted by scope. For Codeberg, use host 'codeberg.org'. Use the 'status' tool to view current capabilities."
    )]
    async fn forgejo(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<ForgejoToolInput>,
    ) -> Result<CallToolResult, McpError> {
        let args = input.args;
        let config = get_scopes_from_parts(&parts)?;

        // Only allow `api` subcommand
        let first_arg = args.first().map(|s| s.as_str());
        if first_arg != Some("api") {
            return Ok(CallToolResult::error(vec![Content::text(
                "Only `api` is supported. Use `api /api/v1/repos/OWNER/REPO/...` to access the REST API. For capability information, use the 'status' tool.",
            )]));
        }

        // Parse and validate the API command using clap
        let api = match forgejo::parse_api(&args) {
            Ok(a) => a,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "{e:#}. Only endpoint path is allowed."
                ))]));
            }
        };

        // The --jq option is not supported with the native client
        // (we return JSON directly which can be processed by the caller)
        if api.args.jq.is_some() {
            return Ok(CallToolResult::error(vec![Content::text(
                "The --jq option is not supported. The API returns JSON directly.",
            )]));
        }

        // Check per-repo permission
        let repo = match &api.repo {
            Some(r) => r,
            None => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "Could not determine target repository from API path. \
                     Use path like /api/v1/repos/owner/repo/...",
                )]));
            }
        };

        // Find the right ForgejoScope by host
        let forgejo_scope = match find_forgejo_scope(&config.forgejo, input.host.as_deref()) {
            Ok(scope) => scope,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(e)]));
            }
        };

        if !forgejo_scope.is_read_allowed(repo) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Read access not allowed for repository: {repo} on host: {}",
                forgejo_scope.host
            ))]));
        }

        let host = forgejo_scope.host.clone();
        let token = forgejo_scope.token.clone();

        // Count read operation for aggregated logging
        self.logging.read_ops.increment();

        // Create native Forgejo API client
        let client = match ForgejoClient::new(&host, token.as_ref().map(|t| t.expose_secret())) {
            Ok(c) => c,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to create Forgejo client: {e:#}"
                ))]));
            }
        };

        // Execute the API request using the native client
        match forgejo_client::execute_api_path(&client, &api.args.endpoint).await {
            Ok(json_value) => {
                // Pretty-print the JSON response
                let output = serde_json::to_string_pretty(&json_value)
                    .unwrap_or_else(|_| json_value.to_string());
                if output.is_empty() || output == "null" {
                    Ok(CallToolResult::success(vec![Content::text("(no output)")]))
                } else {
                    Ok(CallToolResult::success(vec![Content::text(output)]))
                }
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!("{e:#}"))])),
        }
    }

    /// Execute a JIRA CLI command within configured scopes.
    ///
    /// Only explicitly allowed commands and options are permitted.
    /// Unknown commands or options are rejected for security.
    #[tool(
        description = "Execute JIRA commands within configured scopes. Allowed commands: issue (list/show/create/transition/assign), project list, version list, search. Only explicitly allowed options are permitted. Use the 'status' tool to view current capabilities.\n\nSearch requires explicit project(s): search -p PROJECT [-p PROJECT2] -q JQL"
    )]
    async fn jira(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<JiraToolInput>,
    ) -> Result<CallToolResult, McpError> {
        let args = input.args;
        let config = get_scopes_from_parts(&parts)?;

        // Parse and validate the command using clap - rejects unknown commands/options
        let validated = match jira::parse_command(&args) {
            Ok(cmd) => cmd,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Invalid command: {:#}\n\n\
                     Allowed commands:\n  \
                     issue list -p PROJECT\n  \
                     issue show -i ISSUE-KEY\n  \
                     issue create -p PROJECT -s SUMMARY [-d DESC] [-t TYPE]\n  \
                     issue transition -i ISSUE-KEY [-t TRANSITION]\n  \
                     issue assign -i ISSUE-KEY [-a ASSIGNEE]\n  \
                     project list\n  \
                     version list -p PROJECT\n  \
                     search -p PROJECT [-p PROJECT2] -q JQL\n\n\
                     For capability information, use the 'status' tool.",
                    e
                ))]));
            }
        };

        // Get the operation type
        let op_type = jira::classify_command(&validated);

        // For project list, we don't need a specific project
        let is_project_list = matches!(validated.command.command, JiraSubcommand::Project(_));

        // Determine target project for permission checking
        let project = validated
            .project
            .as_deref()
            .or_else(|| validated.issue.as_ref().and_then(|i| i.split('-').next()))
            .map(|s| s.to_string());

        // Verify JIRA is configured
        // Supports either:
        // - Basic auth: host + username + token
        // - Bearer auth: host + token (no username)
        let (host, username, token) = match (
            config.jira.host.as_ref(),
            config.jira.username.as_ref(),
            config.jira.token.as_ref(),
        ) {
            (Some(h), username, Some(t)) => (h.clone(), username.cloned(), t.clone()),
            _ => {
                return Ok(CallToolResult::error(vec![Content::text(
                    "JIRA not configured. Set host and token (and optionally username) in the scope config.",
                )]));
            }
        };

        // For search, validate read permissions for each explicitly listed project
        if let JiraSubcommand::Search(ref search_cmd) = validated.command.command {
            for project_key in &search_cmd.projects {
                if !config
                    .jira
                    .is_allowed(project_key.as_str(), OpType::Read, None)
                {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Read access not allowed for project: {}",
                        project_key
                    ))]));
                }
            }
        } else if is_project_list {
            // For project list, just check that at least one project is configured
            if config.jira.projects.is_empty() {
                return Ok(CallToolResult::error(vec![Content::text(
                    "No JIRA projects configured",
                )]));
            }
        } else {
            // For other commands, check specific project permission
            let project_key_str = match &project {
                Some(p) => p,
                None => {
                    return Ok(CallToolResult::error(vec![Content::text(
                        "Could not determine target project. Use -p PROJECT or -i ISSUE-KEY.",
                    )]));
                }
            };

            // Parse project key to look up permissions
            let project_key = match project_key_str.parse::<crate::jira_types::JiraProjectKey>() {
                Ok(k) => k,
                Err(e) => {
                    return Ok(CallToolResult::error(vec![Content::text(format!(
                        "Invalid project key '{}': {}",
                        project_key_str, e
                    ))]));
                }
            };

            let project_perms = config.jira.projects.get(&project_key);
            let allowed = match op_type {
                OpType::Read => project_perms.map(|p| p.can_read()).unwrap_or(false),
                OpType::Write => {
                    if let Some(issue_str) = &validated.issue {
                        // Try to parse the issue key for permission lookup
                        let issue_key_result = issue_str.parse::<crate::jira_types::JiraIssueKey>();
                        if let Ok(issue_key) = issue_key_result {
                            if let Some(issue_perm) = config.jira.issues.get(&issue_key) {
                                if issue_perm.write {
                                    true
                                } else {
                                    project_perms.map(|p| p.can_write()).unwrap_or(false)
                                }
                            } else {
                                project_perms.map(|p| p.can_write()).unwrap_or(false)
                            }
                        } else {
                            // Invalid issue key format, fall back to project permission
                            project_perms.map(|p| p.can_write()).unwrap_or(false)
                        }
                    } else {
                        project_perms.map(|p| p.can_write()).unwrap_or(false)
                    }
                }
            };

            if !allowed {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Operation not allowed: {} on {}",
                    validated.description, project_key
                ))]));
            }
        }

        // Create the JIRA client
        // Use bearer auth if no username, otherwise basic auth
        let client = match &username {
            Some(user) => JiraClient::new(&host, user, token.expose_secret()),
            None => JiraClient::with_bearer_token(&host, token.expose_secret()),
        };
        let client = match client {
            Ok(c) => c,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Failed to create JIRA client: {:#}",
                    e
                ))]));
            }
        };

        // Execute the command using the native client
        let result = execute_jira_command(&client, &validated).await;

        match result {
            Ok(output) => {
                if output.is_empty() {
                    Ok(CallToolResult::success(vec![Content::text("(no output)")]))
                } else {
                    Ok(CallToolResult::success(vec![Content::text(output)]))
                }
            }
            Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                "{:#}",
                e
            ))])),
        }
    }

    /// Get overall status of all services and their authentication.
    /// Shows which tools are available and which are missing credentials.
    #[tool(
        description = "Show overall status of all services including authentication status, available tools, and missing credentials."
    )]
    async fn status(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(_input): Parameters<StatusToolInput>,
    ) -> Result<CallToolResult, McpError> {
        let config = get_scopes_from_parts(&parts)?;
        Ok(generate_overall_status(&config))
    }
}

/// Execute a validated JIRA command using the native client.
async fn execute_jira_command(
    client: &JiraClient,
    validated: &jira::ValidatedJiraCommand,
) -> eyre::Result<String> {
    use jira::{IssueAction, ProjectAction, VersionAction};

    match &validated.command.command {
        JiraSubcommand::Issue(issue_cmd) => match &issue_cmd.action {
            IssueAction::List(args) => {
                let results = client.list_issues(args.project.as_str()).await?;
                Ok(serde_json::to_string_pretty(&results)?)
            }
            IssueAction::Show(args) => {
                let issue_key = args
                    .effective_issue()
                    .ok_or_else(|| eyre::eyre!("Issue key required"))?;
                let issue = client.get_issue(&issue_key.to_string()).await?;
                Ok(serde_json::to_string_pretty(&issue)?)
            }
            IssueAction::Create(args) => {
                tracing::info!(
                    operation = "jira_create_issue",
                    project = %args.project,
                    summary = %args.summary,
                    issue_type = args.issue_type.as_deref().unwrap_or("default"),
                    "creating JIRA issue"
                );
                let created = client
                    .create_issue(
                        args.project.as_str(),
                        &args.summary,
                        args.description.as_deref(),
                        args.issue_type.as_deref(),
                    )
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            operation = "jira_create_issue",
                            project = %args.project,
                            error = %e,
                            "failed to create JIRA issue"
                        );
                        e
                    })?;
                tracing::info!(
                    operation = "jira_create_issue",
                    project = %args.project,
                    issue_key = %created.key,
                    "JIRA issue created successfully"
                );
                Ok(serde_json::json!({
                    "id": created.id,
                    "key": created.key,
                    "url": created.url,
                })
                .to_string())
            }
            IssueAction::Transition(args) => {
                let issue_key = args
                    .effective_issue()
                    .ok_or_else(|| eyre::eyre!("Issue key required"))?;

                match &args.transition {
                    Some(transition_name) => {
                        tracing::info!(
                            operation = "jira_transition_issue",
                            issue = %issue_key,
                            transition = %transition_name,
                            "transitioning JIRA issue"
                        );
                        client
                            .transition_issue(&issue_key.to_string(), transition_name)
                            .await
                            .map_err(|e| {
                                tracing::error!(
                                    operation = "jira_transition_issue",
                                    issue = %issue_key,
                                    transition = %transition_name,
                                    error = %e,
                                    "failed to transition JIRA issue"
                                );
                                e
                            })?;
                        Ok(format!(
                            "Successfully transitioned {} to {}",
                            issue_key, transition_name
                        ))
                    }
                    None => {
                        // List available transitions (read operation)
                        let transitions = client.get_transitions(&issue_key.to_string()).await?;
                        Ok(serde_json::to_string_pretty(&transitions)?)
                    }
                }
            }
            IssueAction::Assign(args) => {
                let issue_key = args
                    .effective_issue()
                    .ok_or_else(|| eyre::eyre!("Issue key required"))?;
                tracing::info!(
                    operation = "jira_assign_issue",
                    issue = %issue_key,
                    assignee = args.assignee.as_deref().unwrap_or("(unassign)"),
                    "assigning JIRA issue"
                );
                client
                    .assign_issue(&issue_key.to_string(), args.assignee.as_deref())
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            operation = "jira_assign_issue",
                            issue = %issue_key,
                            error = %e,
                            "failed to assign JIRA issue"
                        );
                        e
                    })?;
                match &args.assignee {
                    Some(user) => Ok(format!("Successfully assigned {} to {}", issue_key, user)),
                    None => Ok(format!("Successfully unassigned {}", issue_key)),
                }
            }
        },
        JiraSubcommand::Project(project_cmd) => match &project_cmd.action {
            ProjectAction::List(_) => {
                let projects = client.list_projects().await?;
                Ok(serde_json::to_string_pretty(&projects)?)
            }
        },
        JiraSubcommand::Version(version_cmd) => match &version_cmd.action {
            VersionAction::List(args) => {
                let versions = client.list_versions(args.project.as_str()).await?;
                Ok(serde_json::to_string_pretty(&versions)?)
            }
        },
        JiraSubcommand::Search(search_cmd) => {
            // Use effective_jql() which prepends the authorized project filter
            let jql = search_cmd.effective_jql();
            let results = client.search(&jql).await?;
            Ok(serde_json::to_string_pretty(&results)?)
        }
    }
}

// Implement the ServerHandler trait
#[tool_handler]
impl ServerHandler for ServiceGatorServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "service-gator".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                title: Some("Scoped CLI access for AI agents".into()),
                icons: None,
                website_url: Some("https://github.com/cgwalters/service-gator".into()),
            },
            instructions: Some(
                "service-gator: Scoped CLI access for AI agents with comprehensive capability introspection. \
                 \
                 Capability discovery: Use the 'status' tool to get a comprehensive overview of all services: \
                 - Which services are available vs unavailable \
                 - Authentication status and missing credentials \
                 - Detailed permissions for each service (GitHub, GitLab, Forgejo, JIRA) \
                 - Repository/project access with permission levels \
                 - Configuration guidance and usage examples \
                 \
                 Available tools: \
                 - status: Overall service availability and authentication status \
                 - github_api_tool: GitHub REST API access (read/write depending on permissions) \
                 - github_push: Push commits to GitHub and optionally create draft PR (recommended for GitHub) \
                 - github_pending_review_tool: Manage pending PR reviews on GitHub \
                 - gl: GitLab API access (scope-restricted: read/draft-mr/approve/write permissions) \
                 - forgejo: Forgejo/Gitea API access (scope-restricted: read/draft-pr/pending-review/write permissions) \
                 - gh_create_branch: Create new agent branches (requires create-draft permission, enforces agent- prefix) \
                 - gh_update_pr_head: Update existing PR branch with new commits (looks up branch from PR) \
                 - git_push_local: Push commits to GitLab/Forgejo (for GitHub use github_push) \
                 - jira: JIRA operations (scope-restricted: read/create/write permissions) \
                 \
                 Git workflow for sandboxed agents: For GitHub, use github_push which pushes your commit and \
                 optionally creates a draft PR. For GitLab/Forgejo, use git_push_local. \
                 Do NOT try to use the forge APIs directly for pushing - use these MCP tools instead. \
                 \
                 Security: All operations are scope-restricted. Each tool operates within its configured permissions. \
                 Write operations (draft PR/MR creation, pending review management, approvals) require explicit scope permissions."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

/// Generate an overall status report showing all services and their authentication status.
fn generate_overall_status(config: &ScopeConfig) -> CallToolResult {
    let mut status_lines = vec![
        format!("Service-Gator v{}", env!("CARGO_PKG_VERSION")),
        "============================".to_string(),
        "".to_string(),
    ];

    // Check each service availability
    let mut available_services = Vec::new();
    let mut unavailable_services = Vec::new();

    // GitHub
    let gh_status = check_github_availability(config);
    if gh_status.available {
        available_services.push(("GitHub", gh_status.details));
    } else {
        unavailable_services.push(("GitHub", gh_status.details));
    }

    // GitLab
    let gl_status = check_gitlab_availability(config);
    if gl_status.available {
        available_services.push(("GitLab", gl_status.details));
    } else {
        unavailable_services.push(("GitLab", gl_status.details));
    }

    // Forgejo
    let forgejo_status = check_forgejo_availability(config);
    if forgejo_status.available {
        available_services.push(("Forgejo/Gitea", forgejo_status.details));
    } else {
        unavailable_services.push(("Forgejo/Gitea", forgejo_status.details));
    }

    // JIRA
    let jira_status = check_jira_availability(config);
    if jira_status.available {
        available_services.push(("JIRA", jira_status.details));
    } else {
        unavailable_services.push(("JIRA", jira_status.details));
    }

    // Show available services
    if !available_services.is_empty() {
        status_lines.push("Available services:".to_string());
        for (service, details) in &available_services {
            status_lines.push(format!("   {} - {}", service, details));
        }
        status_lines.push("".to_string());
    }

    // Show unavailable services
    if !unavailable_services.is_empty() {
        status_lines.push("Unavailable services:".to_string());
        for (service, details) in &unavailable_services {
            status_lines.push(format!("   {} - {}", service, details));
        }
        status_lines.push("".to_string());
    }

    // Service-specific status commands
    if !available_services.is_empty() {
        status_lines.push("Detailed status commands:".to_string());
        for (service, _) in &available_services {
            let cmd = match service {
                s if s.contains("GitHub") => "gh status",
                s if s.contains("GitLab") => "glab status",
                s if s.contains("Forgejo") => "status (in forgejo tool)",
                s if s.contains("JIRA") => "jira status",
                _ => "status",
            };
            status_lines.push(format!("   {} detailed status: {}", service, cmd));
        }
        status_lines.push("".to_string());
    }

    // Configuration guidance
    if !unavailable_services.is_empty() {
        status_lines.push("Configuration guidance:".to_string());
        status_lines.push("   Set these environment variables to enable services:".to_string());

        for (service, _details) in &unavailable_services {
            if service.contains("GitHub") {
                status_lines.push("   - GitHub: Authentication token required".to_string());
            } else if service.contains("GitLab") {
                status_lines.push("   - GitLab: Authentication token required".to_string());
            } else if service.contains("Forgejo") {
                status_lines
                    .push("   - Forgejo/Gitea: Host configuration and token required".to_string());
            } else if service.contains("JIRA") {
                status_lines.push("   - JIRA: Host and API token required".to_string());
            }
        }
    }

    CallToolResult::success(vec![Content::text(status_lines.join("\n"))])
}

/// Service availability status
struct ServiceStatus {
    available: bool,
    details: String,
}

/// Check GitHub service availability
fn check_github_availability(config: &ScopeConfig) -> ServiceStatus {
    // Check for GH_TOKEN environment variable
    let has_token = std::env::var("GH_TOKEN").is_ok();

    // Check if global read is enabled
    let has_global_read = config.gh.global_read_allowed();

    // Check if any repos are configured
    let has_repos = !config.gh.repos.is_empty();

    // Check if GraphQL is enabled (either via global read or explicit graphql setting)
    let has_graphql = config.gh.graphql_read_allowed();

    if has_token && has_global_read {
        let mut details =
            "Authenticated, global read access (all repos, search, gists)".to_string();
        if has_graphql {
            details.push_str(" + GraphQL");
        }
        ServiceStatus {
            available: true,
            details,
        }
    } else if has_token && has_repos {
        let repo_count = config.gh.repos.len();
        let mut details = format!("Authenticated, {} repositories in scope", repo_count);
        if has_graphql {
            details.push_str(" + GraphQL");
        }
        ServiceStatus {
            available: true,
            details,
        }
    } else if has_token {
        ServiceStatus {
            available: false,
            details: "Token available but no repositories configured (set `read = true` in [gh] for global access)".to_string(),
        }
    } else if has_repos || has_global_read {
        ServiceStatus {
            available: false,
            details: "Configuration present but missing GH_TOKEN".to_string(),
        }
    } else {
        ServiceStatus {
            available: false,
            details: "Missing GH_TOKEN and configuration".to_string(),
        }
    }
}

/// Check GitLab service availability  
fn check_gitlab_availability(config: &ScopeConfig) -> ServiceStatus {
    // Check for GITLAB_TOKEN environment variable
    let has_token = std::env::var("GITLAB_TOKEN").is_ok();

    // Check if any projects are configured
    let has_projects = !config.gitlab.projects.is_empty();

    // Check host configuration
    let host = config.gitlab.host.as_deref().unwrap_or("gitlab.com");

    if has_token && has_projects {
        let project_count = config.gitlab.projects.len();
        ServiceStatus {
            available: true,
            details: format!(
                "Authenticated on {}, {} projects in scope",
                host, project_count
            ),
        }
    } else if has_token {
        ServiceStatus {
            available: false,
            details: "Token available but no projects configured".to_string(),
        }
    } else if has_projects {
        ServiceStatus {
            available: false,
            details: "Projects configured but missing GITLAB_TOKEN".to_string(),
        }
    } else {
        ServiceStatus {
            available: false,
            details: "Missing GITLAB_TOKEN and project configuration".to_string(),
        }
    }
}

/// Check Forgejo service availability
fn check_forgejo_availability(config: &ScopeConfig) -> ServiceStatus {
    // Check for tokens
    let has_forgejo_token = std::env::var("FORGEJO_TOKEN").is_ok();
    let has_gitea_token = std::env::var("GITEA_TOKEN").is_ok();
    let has_token = has_forgejo_token || has_gitea_token;

    // Check if any hosts are configured
    if config.forgejo.is_empty() {
        return ServiceStatus {
            available: false,
            details: "No Forgejo/Gitea hosts configured".to_string(),
        };
    }

    let host_count = config.forgejo.len();
    let total_repos: usize = config.forgejo.iter().map(|f| f.repos.len()).sum();

    if has_token && total_repos > 0 {
        let hosts: Vec<_> = config.forgejo.iter().map(|f| f.host.as_str()).collect();
        ServiceStatus {
            available: true,
            details: format!(
                "Authenticated, {} hosts configured ({}), {} repositories",
                host_count,
                hosts.join(", "),
                total_repos
            ),
        }
    } else if has_token {
        ServiceStatus {
            available: false,
            details: "Token available but no repositories configured".to_string(),
        }
    } else {
        ServiceStatus {
            available: false,
            details: "Missing FORGEJO_TOKEN or GITEA_TOKEN".to_string(),
        }
    }
}

/// Check JIRA service availability
fn check_jira_availability(config: &ScopeConfig) -> ServiceStatus {
    // Check environment variables
    let has_host = std::env::var("JIRA_HOST").is_ok() || config.jira.host.is_some();
    let has_token = std::env::var("JIRA_API_TOKEN").is_ok() || config.jira.token.is_some();
    let has_username = std::env::var("JIRA_USERNAME").is_ok() || config.jira.username.is_some();

    // Check if any projects are configured
    let has_projects = !config.jira.projects.is_empty();

    let host_string = config
        .jira
        .host
        .clone()
        .or_else(|| std::env::var("JIRA_HOST").ok())
        .unwrap_or_else(|| "not configured".to_string());
    let host = host_string.as_str();

    if has_host && has_token && has_projects {
        let project_count = config.jira.projects.len();
        let auth_method = if has_username {
            "Basic auth"
        } else {
            "Bearer token"
        };
        ServiceStatus {
            available: true,
            details: format!(
                "Connected to {} ({}), {} projects in scope",
                host, auth_method, project_count
            ),
        }
    } else {
        let mut missing = Vec::new();
        if !has_host {
            missing.push("JIRA_HOST");
        }
        if !has_token {
            missing.push("JIRA_API_TOKEN");
        }
        if !has_projects {
            missing.push("project configuration");
        }

        ServiceStatus {
            available: false,
            details: format!("Missing: {}", missing.join(", ")),
        }
    }
}
/// Find the appropriate ForgejoScope based on the provided host.
///
/// - If only one Forgejo host is configured, use it (host parameter optional)
/// - If multiple hosts are configured, host parameter is required
/// - If no hosts are configured, return an error
fn find_forgejo_scope<'a>(
    scopes: &'a [crate::scope::ForgejoScope],
    host: Option<&str>,
) -> Result<&'a crate::scope::ForgejoScope, String> {
    if scopes.is_empty() {
        return Err("No Forgejo hosts configured".to_string());
    }

    match host {
        Some(h) => {
            // Find the scope matching the host
            scopes
                .iter()
                .find(|s| s.host == h)
                .ok_or_else(|| format!("Forgejo host '{}' not configured", h))
        }
        None => {
            // If only one host configured, use it
            if scopes.len() == 1 {
                Ok(&scopes[0])
            } else {
                let hosts: Vec<_> = scopes.iter().map(|s| s.host.as_str()).collect();
                Err(format!(
                    "Multiple Forgejo hosts configured, please specify one: {}",
                    hosts.join(", ")
                ))
            }
        }
    }
}

/// Shared state for the auth endpoints.
#[derive(Clone)]
pub struct AppState {
    /// Token authority for signing/validating JWTs.
    pub token_authority: Option<Arc<TokenAuthority>>,
    /// Server authentication configuration (mode, rotation, etc.).
    pub server_config: Arc<ServerConfig>,
    /// Scopes configuration receiver (updated by file watcher if enabled).
    pub scopes: watch::Receiver<ScopeConfig>,
}

/// Start the MCP server on the given address.
///
/// This is the legacy entry point that accepts just `ScopeConfig`.
/// For token auth support, use `start_server_with_config`.
pub async fn start_server(bind_addr: &str, config: ScopeConfig) -> Result<()> {
    start_server_with_config(bind_addr, ServerConfig::from_scopes(config)).await
}

/// Start the MCP server with full configuration including auth.
pub async fn start_server_with_config(bind_addr: &str, config: ServerConfig) -> Result<()> {
    let scopes = crate::config_watcher::static_scopes(config.scopes.clone());
    start_mcp_server(bind_addr, config, scopes).await
}

/// Start the MCP server with scopes configuration.
///
/// The `scopes` receiver provides access to scope configuration,
/// and may be updated by a file watcher for live reload.
pub async fn start_mcp_server(
    bind_addr: &str,
    config: ServerConfig,
    scopes: watch::Receiver<ScopeConfig>,
) -> Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::time::Duration;

    let ct = tokio_util::sync::CancellationToken::new();

    // Create token authority if secret is configured
    let token_authority = config.effective_secret().map(|secret| {
        tracing::info!(mode = ?config.server.mode, "Token authentication enabled");
        Arc::new(TokenAuthority::new(secret.expose_secret()))
    });

    if token_authority.is_none() && config.server.mode != AuthMode::None {
        tracing::warn!(mode = ?config.server.mode, "Auth mode set but no secret configured");
    }

    // Create shared logging state for all server instances
    let logging_state = LoggingState::new();

    // Start background logging task (logs aggregated read operations every 5 seconds)
    let _logging_handle = logging_state
        .clone()
        .spawn_background_logger(Duration::from_secs(5));

    let logging_for_factory = logging_state.clone();
    let mcp_service = StreamableHttpService::new(
        move || {
            Ok(ServiceGatorServer::with_logging(
                logging_for_factory.clone(),
            ))
        },
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig {
            cancellation_token: ct.child_token(),
            ..Default::default()
        },
    );

    let app_state = AppState {
        token_authority,
        server_config: Arc::new(config),
        scopes,
    };

    // Build the MCP service route with auth middleware
    // The middleware injects TokenClaims into request extensions for handlers to use
    let mcp_router = axum::Router::new()
        .nest_service("/mcp", mcp_service)
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ))
        .with_state(app_state.clone());

    // Build the router with auth endpoints, health check, and MCP service
    // Note: /admin/mint-token and /token/rotate have their own auth logic
    let router = axum::Router::new()
        .route("/healthz", axum::routing::get(health_handler))
        .route("/admin/mint-token", axum::routing::post(mint_token_handler))
        .route("/token/rotate", axum::routing::post(rotate_token_handler))
        .merge(mcp_router)
        .with_state(app_state);

    let tcp_listener = tokio::net::TcpListener::bind(bind_addr).await?;

    tracing::info!(address = %bind_addr, "MCP server listening");

    axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            tracing::info!("Shutting down MCP server");
            ct.cancel();
            // Signal the logging task to flush and stop
            logging_state.shutdown();
        })
        .await?;

    Ok(())
}

/// Wait for shutdown signal (SIGTERM or SIGINT/ctrl-c).
///
/// In Kubernetes, pods receive SIGTERM for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// Health check endpoint for Kubernetes liveness/readiness probes.
async fn health_handler() -> impl IntoResponse {
    StatusCode::OK
}

/// Handler for POST /admin/mint-token
async fn mint_token_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MintRequest>,
) -> impl IntoResponse {
    // Check that token auth is enabled
    let authority = match &state.token_authority {
        Some(a) => a,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AuthError::new("token authentication not configured")),
            )
                .into_response();
        }
    };

    // Validate admin key
    let expected_admin_key = match state.server_config.effective_admin_key() {
        Some(k) => k,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AuthError::new("admin key not configured")),
            )
                .into_response();
        }
    };

    let provided_key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Use constant-time comparison to prevent timing attacks
    if !constant_time_eq(
        provided_key.as_bytes(),
        expected_admin_key.expose_secret().as_bytes(),
    ) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthError::new("invalid admin key")),
        )
            .into_response();
    }

    // Mint the token
    match authority.mint(&req, &state.server_config.server.rotation) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(MintError::ExpiresTooShort { min }) => (
            StatusCode::BAD_REQUEST,
            Json(AuthError::new(format!(
                "expires_in must be at least {min} seconds"
            ))),
        )
            .into_response(),
        Err(MintError::ExpiresTooLong { max }) => (
            StatusCode::BAD_REQUEST,
            Json(AuthError::new(format!(
                "expires_in must be at most {max} seconds"
            ))),
        )
            .into_response(),
        Err(MintError::Signing(e)) => {
            tracing::error!(error = %e, "Token signing failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuthError::new("token creation failed")),
            )
                .into_response()
        }
    }
}

/// Handler for POST /token/rotate
async fn rotate_token_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RotateRequest>,
) -> impl IntoResponse {
    // Check that token auth is enabled
    let authority = match &state.token_authority {
        Some(a) => a,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(AuthError::new("token authentication not configured")),
            )
                .into_response();
        }
    };

    // Extract and validate Bearer token
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(AuthError::new("missing or invalid Authorization header")),
            )
                .into_response();
        }
    };

    let claims = match authority.validate(token) {
        Ok(c) => c,
        Err(TokenError::Expired) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(AuthError::new("token has expired")),
            )
                .into_response();
        }
        Err(TokenError::InvalidSignature) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(AuthError::new("invalid token signature")),
            )
                .into_response();
        }
        Err(e) => {
            tracing::debug!("Token validation failed during rotation: {e:?}");
            return (
                StatusCode::UNAUTHORIZED,
                Json(AuthError::new("invalid token")),
            )
                .into_response();
        }
    };

    // Rotate the token
    match authority.rotate(&claims, &req) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(RotateError::RotationDisabled) => (
            StatusCode::FORBIDDEN,
            Json(AuthError::new("token rotation not permitted")),
        )
            .into_response(),
        Err(RotateError::ExceedsMaxLifetime { .. }) => (
            StatusCode::BAD_REQUEST,
            Json(AuthError::new(
                "requested expiration exceeds maximum allowed",
            )),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuthError::new(e.to_string())),
        )
            .into_response(),
    }
}

/// Extract Bearer token from Authorization header.
fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Get the current scopes snapshot.
fn get_scopes_snapshot(state: &AppState) -> ScopeConfig {
    state.scopes.borrow().clone()
}

/// Middleware that validates JWT tokens and injects resolved scopes into request extensions.
///
/// This middleware handles the three AuthMode variants:
/// - `Required`: Rejects requests without a valid Bearer token
/// - `Optional`: Validates tokens if present, uses fallback scopes for unauthenticated requests
/// - `None`: Uses fallback scopes for all requests (no auth)
///
/// When dynamic scopes are configured (via --scope-file), they are merged with the
/// static scopes for each request, enabling live reload of permissions.
///
/// On success, injects `ResolvedScopes` into the request extensions for handlers to use.
async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let mode = state.server_config.server.mode;

    // For AuthMode::None, use fallback scopes directly (with dynamic merge)
    if mode == AuthMode::None {
        let fallback_scopes = get_scopes_snapshot(&state);
        req.extensions_mut().insert(ResolvedScopes(fallback_scopes));
        return next.run(req).await;
    }

    // Extract Bearer token from Authorization header
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match (token, &state.token_authority) {
        // Token present and authority configured - validate and inject token scopes
        (Some(token), Some(authority)) => match authority.validate(token) {
            Ok(claims) => {
                req.extensions_mut()
                    .insert(ResolvedScopes(claims.scopes.clone()));
                next.run(req).await
            }
            Err(TokenError::Expired) => {
                tracing::debug!("Rejected request with expired token");
                (
                    StatusCode::UNAUTHORIZED,
                    Json(AuthError::new("token has expired")),
                )
                    .into_response()
            }
            Err(TokenError::InvalidSignature) => {
                tracing::debug!("Rejected request with invalid token signature");
                (
                    StatusCode::UNAUTHORIZED,
                    Json(AuthError::new("invalid token")),
                )
                    .into_response()
            }
            Err(_) => {
                tracing::debug!("Rejected request with invalid token");
                (
                    StatusCode::UNAUTHORIZED,
                    Json(AuthError::new("invalid token")),
                )
                    .into_response()
            }
        },
        // No token but mode is Optional - use fallback scopes
        (None, _) if mode == AuthMode::Optional => {
            let fallback_scopes = get_scopes_snapshot(&state);
            req.extensions_mut().insert(ResolvedScopes(fallback_scopes));
            next.run(req).await
        }
        // No token and mode is Required - reject
        (None, _) if mode == AuthMode::Required => {
            tracing::debug!("Rejected request without token in Required mode");
            (
                StatusCode::UNAUTHORIZED,
                Json(AuthError::new("authentication required")),
            )
                .into_response()
        }
        // Token present but no authority configured - reject without revealing config state
        (Some(_), None) => {
            tracing::warn!("Token provided but token authority not configured");
            (
                StatusCode::UNAUTHORIZED,
                Json(AuthError::new("authentication failed")),
            )
                .into_response()
        }
        // No token with any authority config - this handles edge cases not covered above
        // (e.g., AuthMode is somehow not Required/Optional after the None check, or
        // authority is configured but no token and mode isn't matched above)
        (None, _) => {
            // Use fallback scopes - this is safe since AuthMode::Required is already handled
            let fallback_scopes = get_scopes_snapshot(&state);
            req.extensions_mut().insert(ResolvedScopes(fallback_scopes));
            next.run(req).await
        }
    }
}
