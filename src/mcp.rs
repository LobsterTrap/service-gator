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

use std::process::Stdio;
use std::sync::Arc;

use eyre::Result;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Content, ServerCapabilities, ServerInfo};
use rmcp::schemars;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::RwLock;

use serde::Serialize;

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

/// The MCP server handler for service-gator.
#[derive(Clone)]
pub struct ServiceGatorServer {
    config: Arc<RwLock<ScopeConfig>>,
    tool_router: ToolRouter<Self>,
}

impl ServiceGatorServer {
    pub fn new(config: ScopeConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            tool_router: Self::tool_router(),
        }
    }

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
    /// Only `gh api` is supported for read-only access.
    #[tool(
        description = "Execute GitHub API commands (read-only). Only 'gh api <endpoint> [--jq <expr>]' is supported."
    )]
    async fn gh(
        &self,
        Parameters(input): Parameters<GhToolInput>,
    ) -> Result<CallToolResult, McpError> {
        let args = input.args;

        // Only allow `gh api` subcommand
        let first_arg = args.first().map(|s| s.as_str());
        if first_arg != Some("api") {
            return Ok(CallToolResult::error(vec![Content::text(
                "Only `gh api` is supported. Use `gh api repos/OWNER/REPO/...` to access the REST API.",
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

        let config = self.config.read().await;

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
        drop(config);

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
    /// Only `glab api` is supported for read-only access.
    #[tool(
        description = "Execute GitLab API commands (read-only). Only 'glab api <endpoint> [--jq <expr>]' is supported."
    )]
    async fn gl(
        &self,
        Parameters(input): Parameters<GlToolInput>,
    ) -> Result<CallToolResult, McpError> {
        let args = input.args;

        // Only allow `glab api` subcommand
        let first_arg = args.first().map(|s| s.as_str());
        if first_arg != Some("api") {
            return Ok(CallToolResult::error(vec![Content::text(
                "Only `glab api` is supported. Use `glab api projects/GROUP%2FPROJECT/...` to access the REST API.",
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

        let config = self.config.read().await;
        if !config.gitlab.is_read_allowed(project) {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "Read access not allowed for project: {project}"
            ))]));
        }

        // Build final args with forced GET method and optional hostname
        let final_args = gitlab::build_api_args_with_host(&api.args, config.gitlab.host.as_deref());
        drop(config);

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
    /// Only `api` is supported for read-only access.
    #[tool(
        description = "Execute Forgejo/Gitea API commands (read-only). Only 'api <endpoint>' is supported. For Codeberg, use host 'codeberg.org'."
    )]
    async fn forgejo(
        &self,
        Parameters(input): Parameters<ForgejoToolInput>,
    ) -> Result<CallToolResult, McpError> {
        let args = input.args;

        // Only allow `api` subcommand
        let first_arg = args.first().map(|s| s.as_str());
        if first_arg != Some("api") {
            return Ok(CallToolResult::error(vec![Content::text(
                "Only `api` is supported. Use `api /api/v1/repos/OWNER/REPO/...` to access the REST API.",
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
        let config = self.config.read().await;
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
        drop(config);

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
        Parameters(input): Parameters<PendingReviewInput>,
    ) -> Result<CallToolResult, McpError> {
        // Check permission
        let config = self.config.read().await;
        if !config
            .gh
            .is_allowed(&input.repo, GhOpType::ManagePendingReview, None)
        {
            return Ok(CallToolResult::error(vec![Content::text(format!(
                "pending-review permission not granted for repository: {}",
                input.repo
            ))]));
        }
        drop(config);

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
        description = "Execute JIRA commands within configured scopes. Allowed commands: issue (list/show/create/transition/assign), project list, version list, search. Only explicitly allowed options are permitted."
    )]
    async fn jira(
        &self,
        Parameters(input): Parameters<JiraToolInput>,
    ) -> Result<CallToolResult, McpError> {
        let args = input.args;

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
                     search -q JQL",
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

        // Check permission
        let config = self.config.read().await;

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
        drop(config);

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
                "service-gator: Scoped CLI access for AI agents. \
                 Tools: gh (read-only GitHub API), gl (read-only GitLab API), \
                 forgejo (read-only Forgejo/Gitea API), \
                 gh_pending_review (manage pending PR reviews), jira (JIRA CLI). \
                 All operations are checked against configured scope permissions. \
                 Pending reviews require a marker token and remain in PENDING state for human review."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
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

/// Start the MCP server on the given address.
pub async fn start_server(bind_addr: &str, config: ScopeConfig) -> Result<()> {
    use rmcp::transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    };

    let ct = tokio_util::sync::CancellationToken::new();

    let service = StreamableHttpService::new(
        move || Ok(ServiceGatorServer::new(config.clone())),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig {
            cancellation_token: ct.child_token(),
            ..Default::default()
        },
    );

    let router = axum::Router::new().nest_service("/mcp", service);
    let tcp_listener = tokio::net::TcpListener::bind(bind_addr).await?;

    eprintln!("service-gator MCP server listening on {}", bind_addr);

    axum::serve(tcp_listener, router)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
            ct.cancel();
        })
        .await?;

    Ok(())
}
