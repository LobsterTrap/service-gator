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
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
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

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
use crate::forgejo;
use crate::forgejo_client::{self, ForgejoClient};
use crate::github::{self, PendingReviewOp, REVIEW_MARKER_TOKEN};
use crate::gitlab;
use crate::jira::{self, JiraSubcommand};
use crate::jira_client::JiraClient;
use crate::scope::{GhOpType, OpType, ScopeConfig};

/// Input schema for GitHub CLI tool.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GhToolInput {
    /// Command arguments for `gh api` (e.g., ["api", "repos/owner/repo/pulls"])
    /// Only the `api` subcommand is supported for read-only access.
    pub args: Vec<String>,
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

/// Input schema for pending review operations.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct PendingReviewInput {
    /// The operation to perform: "list", "create", "get", "update", "delete"
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
}

/// A review comment on a specific file/line.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ReviewComment {
    /// The relative path to the file
    pub path: String,
    /// The line number in the file (new version)
    #[serde(default)]
    pub line: Option<u32>,
    /// The side of the diff (LEFT or RIGHT)
    #[serde(default)]
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
}

impl ServiceGatorServer {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
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
}

/// Tool definitions for the MCP server.
#[tool_router]
impl ServiceGatorServer {
    /// Execute a GitHub API command within configured scopes.
    /// Operations are restricted by scope permissions (read, draft-pr, pending-review, write).
    #[tool(
        description = "Execute GitHub API commands within configured scope permissions. Use 'gh api <endpoint> [--jq <expr>]' for API access. Write operations (draft PRs, pending reviews) available if permitted by scope. Use the 'status' tool to view current capabilities."
    )]
    async fn gh(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<GhToolInput>,
    ) -> Result<CallToolResult, McpError> {
        let args = input.args;
        let config = get_scopes_from_parts(&parts)?;

        // Only allow `gh api` subcommand
        let first_arg = args.first().map(|s| s.as_str());
        if first_arg != Some("api") {
            return Ok(CallToolResult::error(vec![Content::text(
                "Only `gh api` is supported. Use `gh api repos/OWNER/REPO/...` to access the REST API. For capability information, use the 'status' tool.",
            )]));
        }

        // Parse and validate the API command using clap
        let api = match github::parse_api(&args) {
            Ok(a) => a,
            Err(e) => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "{e:#}. Only endpoint path and --jq option are allowed."
                ))]));
            }
        };

        // Permission check: GraphQL vs REST
        if api.is_graphql {
            // GraphQL permission check (global, not per-repo)
            // Note: Mutations are already rejected in parse_api()
            if !config.gh.graphql_read_allowed() {
                return Ok(CallToolResult::error(vec![Content::text(
                    "GraphQL read access not allowed. Set `graphql = \"read\"` or `graphql = true` in [gh] config.",
                )]));
            }
        } else {
            // REST API - check per-repo permission
            let repo = match &api.repo {
                Some(r) => r,
                None => {
                    return Ok(CallToolResult::error(vec![Content::text(
                        "Could not determine target repository from API path. \
                         Use path like /repos/owner/repo/...",
                    )]));
                }
            };

            if !config.gh.is_read_allowed(repo) {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Read access not allowed for repository: {repo}"
                ))]));
            }
        }

        // Build final args with forced GET method
        let final_args = github::build_api_args(&api);

        // Execute
        match self.exec_command("gh", &final_args).await {
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

        // Create native Forgejo API client
        let client = match ForgejoClient::new(&host, token.as_deref()) {
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

    /// Manage pending PR reviews with marker token validation.
    #[tool(
        description = "Create, update, or delete pending PR reviews. Reviews are created with a marker token and must remain in PENDING state until human submission. Operations: list, create, get, update, delete."
    )]
    async fn gh_pending_review(
        &self,
        Extension(parts): Extension<http::request::Parts>,
        Parameters(input): Parameters<PendingReviewInput>,
    ) -> Result<CallToolResult, McpError> {
        let config = get_scopes_from_parts(&parts)?;

        // Check permission
        if !config
            .gh
            .is_allowed(&input.repo, GhOpType::ManagePendingReview, None)
        {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "pending-review permission not granted for repository: {}",
                input.repo
            ))]));
        }

        // Parse operation
        let op = match input.operation.to_lowercase().as_str() {
            "list" => PendingReviewOp::List,
            "create" => PendingReviewOp::Create,
            "get" => PendingReviewOp::Get,
            "update" => PendingReviewOp::Update,
            "delete" => PendingReviewOp::Delete,
            other => {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "Unknown operation: {}. Use: list, create, get, update, delete",
                    other
                ))]));
            }
        };

        // Validate review_id for operations that need it
        if matches!(
            op,
            PendingReviewOp::Get | PendingReviewOp::Update | PendingReviewOp::Delete
        ) && input.review_id.is_none()
        {
            return Ok(CallToolResult::error(vec![Content::text(
                "review_id is required for get/update/delete operations",
            )]));
        }

        // Build the endpoint path
        let endpoint = match input.review_id {
            Some(id) => format!(
                "repos/{}/pulls/{}/reviews/{}",
                input.repo, input.pull_number, id
            ),
            None => format!("repos/{}/pulls/{}/reviews", input.repo, input.pull_number),
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
                        "Failed to parse review JSON: {}",
                        e
                    ))]));
                }
            };

            // Validate marker token
            if let Err(e) = github::validate_review_marker(&review) {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "{:#}",
                    e
                ))]));
            }

            // Validate pending state
            if let Err(e) = github::validate_review_pending(&review) {
                return Ok(CallToolResult::error(vec![Content::text(format!(
                    "{:#}",
                    e
                ))]));
            }
        }

        // Execute the operation
        match op {
            PendingReviewOp::List | PendingReviewOp::Get => {
                let args = vec!["api".to_string(), "--method=GET".to_string(), endpoint];
                match self.exec_command("gh", &args).await {
                    Ok(output) => Ok(CallToolResult::success(vec![Content::text(output)])),
                    Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
                }
            }

            PendingReviewOp::Create => {
                // Build review body with marker token
                let body_text = input.body.as_deref().unwrap_or("");
                let body_with_marker = if body_text.contains(REVIEW_MARKER_TOKEN) {
                    body_text.to_string()
                } else {
                    format!("{}\n\n{}", REVIEW_MARKER_TOKEN, body_text)
                };

                let mut payload = serde_json::json!({
                    "body": body_with_marker,
                });

                // Add comments if provided
                if let Some(comments) = &input.comments {
                    payload["comments"] = serde_json::to_value(comments).unwrap_or_default();
                }

                // Note: We don't set "event" field, which means PENDING state

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
                    Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
                }
            }

            PendingReviewOp::Update => {
                let body_text = match &input.body {
                    Some(b) => b.clone(),
                    None => {
                        return Ok(CallToolResult::error(vec![Content::text(
                            "body is required for update operation",
                        )]));
                    }
                };

                // Ensure marker token is preserved
                let body_with_marker = if body_text.contains(REVIEW_MARKER_TOKEN) {
                    body_text
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
                    Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
                }
            }

            PendingReviewOp::Delete => {
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
                    Err(e) => Ok(CallToolResult::error(vec![Content::text(e)])),
                }
            }
        }
    }

    /// Execute a JIRA CLI command within configured scopes.
    ///
    /// Only explicitly allowed commands and options are permitted.
    /// Unknown commands or options are rejected for security.
    #[tool(
        description = "Execute JIRA commands within configured scopes. Allowed commands: issue (list/show/create/transition/assign), project list, version list, search. Only explicitly allowed options are permitted. Use the 'status' tool to view current capabilities."
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
                     search -q JQL\n\n\
                     For capability information, use the 'status' tool.",
                    e
                ))]));
            }
        };

        // Get the operation type
        let op_type = jira::classify_command(&validated);

        // For project list and search, we don't need a specific project
        let is_project_list = matches!(validated.command.command, JiraSubcommand::Project(_));
        let is_search = matches!(validated.command.command, JiraSubcommand::Search(_));

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

        // For project list and search, just check that at least one project is configured
        if is_project_list || is_search {
            if config.jira.projects.is_empty() {
                return Ok(CallToolResult::error(vec![Content::text(
                    "No JIRA projects configured",
                )]));
            }
        } else {
            // For other commands, check specific project permission
            let project_key = match &project {
                Some(p) => p,
                None => {
                    return Ok(CallToolResult::error(vec![Content::text(
                        "Could not determine target project. Use -p PROJECT or -i ISSUE-KEY.",
                    )]));
                }
            };

            let project_perms = config.jira.projects.get(project_key);
            let allowed = match op_type {
                OpType::Read => project_perms.map(|p| p.can_read()).unwrap_or(false),
                OpType::Write => {
                    if let Some(issue) = &validated.issue {
                        if let Some(issue_perm) = config.jira.issues.get(issue) {
                            if issue_perm.write {
                                true
                            } else {
                                project_perms.map(|p| p.can_write()).unwrap_or(false)
                            }
                        } else {
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
            Some(user) => JiraClient::new(&host, user, &token),
            None => JiraClient::with_bearer_token(&host, &token),
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
                let results = client.list_issues(&args.project).await?;
                Ok(serde_json::to_string_pretty(&results)?)
            }
            IssueAction::Show(args) => {
                let issue_key = args
                    .effective_issue()
                    .ok_or_else(|| eyre::eyre!("Issue key required"))?;
                let issue = client.get_issue(issue_key).await?;
                Ok(serde_json::to_string_pretty(&issue)?)
            }
            IssueAction::Create(args) => {
                let created = client
                    .create_issue(
                        &args.project,
                        &args.summary,
                        args.description.as_deref(),
                        args.issue_type.as_deref(),
                    )
                    .await?;
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
                        client.transition_issue(issue_key, transition_name).await?;
                        Ok(format!(
                            "Successfully transitioned {} to {}",
                            issue_key, transition_name
                        ))
                    }
                    None => {
                        // List available transitions
                        let transitions = client.get_transitions(issue_key).await?;
                        Ok(serde_json::to_string_pretty(&transitions)?)
                    }
                }
            }
            IssueAction::Assign(args) => {
                let issue_key = args
                    .effective_issue()
                    .ok_or_else(|| eyre::eyre!("Issue key required"))?;
                client
                    .assign_issue(issue_key, args.assignee.as_deref())
                    .await?;
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
                let versions = client.list_versions(&args.project).await?;
                Ok(serde_json::to_string_pretty(&versions)?)
            }
        },
        JiraSubcommand::Search(search_cmd) => {
            let results = client.search(&search_cmd.jql).await?;
            Ok(serde_json::to_string_pretty(&results)?)
        }
    }
}

// Implement the ServerHandler trait
#[tool_handler]
impl ServerHandler for ServiceGatorServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
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
                 - gh: GitHub API access (scope-restricted: read/draft-pr/pending-review/write permissions) \
                 - gl: GitLab API access (scope-restricted: read/draft-mr/approve/write permissions) \
                 - forgejo: Forgejo/Gitea API access (scope-restricted: read/draft-pr/pending-review/write permissions) \
                 - gh_pending_review: GitHub PR review management (requires pending-review permission) \
                 - jira: JIRA operations (scope-restricted: read/create/write permissions) \
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
        "Service-Gator Overall Status".to_string(),
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

    // Check if any repos are configured
    let has_repos = !config.gh.repos.is_empty();

    if has_token && has_repos {
        let repo_count = config.gh.repos.len();
        ServiceStatus {
            available: true,
            details: format!("Authenticated, {} repositories in scope", repo_count),
        }
    } else if has_token {
        ServiceStatus {
            available: false,
            details: "Token available but no repositories configured".to_string(),
        }
    } else if has_repos {
        ServiceStatus {
            available: false,
            details: "Repositories configured but missing GH_TOKEN".to_string(),
        }
    } else {
        ServiceStatus {
            available: false,
            details: "Missing GH_TOKEN and repository configuration".to_string(),
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
    /// Server configuration.
    pub config: Arc<ServerConfig>,
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
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    let ct = tokio_util::sync::CancellationToken::new();

    // Create token authority if secret is configured
    let token_authority = config.effective_secret().map(|secret| {
        tracing::info!(mode = ?config.server.mode, "Token authentication enabled");
        Arc::new(TokenAuthority::new(&secret))
    });

    if token_authority.is_none() && config.server.mode != AuthMode::None {
        tracing::warn!(mode = ?config.server.mode, "Auth mode set but no secret configured");
    }

    let mcp_service = StreamableHttpService::new(
        || Ok(ServiceGatorServer::new()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig {
            cancellation_token: ct.child_token(),
            ..Default::default()
        },
    );

    let app_state = AppState {
        token_authority,
        config: Arc::new(config),
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

    // Build the router with auth endpoints and MCP service
    // Note: /admin/mint-token and /token/rotate have their own auth logic
    let router = axum::Router::new()
        .route("/admin/mint-token", axum::routing::post(mint_token_handler))
        .route("/token/rotate", axum::routing::post(rotate_token_handler))
        .merge(mcp_router)
        .with_state(app_state);

    let tcp_listener = tokio::net::TcpListener::bind(bind_addr).await?;

    tracing::info!(address = %bind_addr, "MCP server listening");

    axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
            ct.cancel();
        })
        .await?;

    Ok(())
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
    let expected_admin_key = match state.config.effective_admin_key() {
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
    if !constant_time_eq(provided_key.as_bytes(), expected_admin_key.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(AuthError::new("invalid admin key")),
        )
            .into_response();
    }

    // Mint the token
    match authority.mint(&req, &state.config.server.rotation) {
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
        Err(MintError::Signing(_)) => {
            tracing::error!("Token signing failed");
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

/// Middleware that validates JWT tokens and injects resolved scopes into request extensions.
///
/// This middleware handles the three AuthMode variants:
/// - `Required`: Rejects requests without a valid Bearer token
/// - `Optional`: Validates tokens if present, uses fallback scopes for unauthenticated requests
/// - `None`: Uses fallback scopes for all requests (no auth)
///
/// On success, injects `ResolvedScopes` into the request extensions for handlers to use.
async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let mode = state.config.server.mode;
    let fallback_scopes = &state.config.scopes;

    // For AuthMode::None, use fallback scopes directly
    if mode == AuthMode::None {
        req.extensions_mut()
            .insert(ResolvedScopes(fallback_scopes.clone()));
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
            req.extensions_mut()
                .insert(ResolvedScopes(fallback_scopes.clone()));
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
            req.extensions_mut()
                .insert(ResolvedScopes(fallback_scopes.clone()));
            next.run(req).await
        }
    }
}
