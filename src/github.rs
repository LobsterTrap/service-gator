//! GitHub CLI (`gh`) operation analysis for service-gator.
//!
//! This module provides:
//! - Extraction of target repository from `gh` command arguments
//! - Classification of operations as read vs write
//! - Handling of `gh api` with clap-based argument parsing
//! - GraphQL query parsing and classification using `graphql-parser`
//! - Command parsing utilities shared between CLI and MCP server
//! - Pending review API support with marker token validation
//!
//! ## Security Model
//!
//! We use an explicit allowlist approach for `gh api`:
//! - `--jq` / `-q`: Allowed for filtering output
//! - `-f` / `--field`: Allowed for passing parameters (including GraphQL queries)
//!
//! ### REST API
//! - All REST requests are forced to GET method (read-only)
//! - Repository is extracted from the API path for permission checking
//!
//! ### GraphQL API
//! - GraphQL queries are parsed using `graphql-parser` to determine operation type
//! - Queries and subscriptions are classified as read operations
//! - Mutations are classified as write operations
//! - If ANY operation in the document is a mutation, the entire request is Write
//! - Permission is checked via `graphql_read_allowed()` / `graphql_write_allowed()`
//! - GraphQL cannot be scoped per-repo (queries can span multiple repos)
//!
//! **Blocked dangerous options:**
//! - `--template` / `-t`: Go templates can execute code
//! - `--input`: Can read arbitrary files from filesystem
//! - `-F` / `--field @file`: File reading via `@` prefix (we only allow `-f`)
//! - `--hostname`: Could exfiltrate tokens to malicious server
//! - `--method` / `-X`: Method is controlled by us (GET for REST, POST for GraphQL)
//!
//! ## Branch Management for Sandboxed AI Agents
//!
//! When running in devaipod, AI agents are sandboxed without git credentials.
//! Two MCP tools provide safe branch management:
//!
//! - `gh_create_branch`: Creates NEW branches with enforced `agent-` prefix naming.
//!   Requires `create-draft` permission. Branches must not already exist.
//!
//! - `gh_update_pr_head`: Updates an existing PR's branch. The branch name is looked
//!   up from the PR number - agents cannot specify arbitrary branch names.
//!
//! See `src/mcp.rs` for the implementation.

use std::process::Command;

use clap::Parser;
use eyre::{bail, Result};

use graphql_parser::query::{Definition, OperationDefinition};
use itertools::Itertools;

use crate::git::PullRequestNumber;
use crate::scope::{GhOpType, OpType};

/// Parse a key=value pair for the -f/--field option.
fn parse_key_value(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("invalid field format '{}', expected key=value", s))
}

/// Parsed and validated `gh api` arguments.
///
/// We use clap to explicitly define allowed options and reject everything else.
/// This is more secure than trying to filter arbitrary arguments.
#[derive(Parser, Debug, Clone)]
#[command(name = "api", no_binary_name = true)]
#[command(disable_help_flag = true, disable_version_flag = true)]
pub struct GhApiArgs {
    /// The API endpoint path (e.g., repos/owner/repo/pulls)
    #[arg(required = true)]
    pub endpoint: String,

    /// Filter output using a jq expression
    #[arg(short = 'q', long = "jq")]
    pub jq: Option<String>,

    /// Field parameters in key=value format (used for GraphQL queries)
    #[arg(short = 'f', long = "field", value_parser = parse_key_value)]
    pub fields: Vec<(String, String)>,
}

impl GhApiArgs {
    /// Extract the GraphQL query from fields, if present.
    pub fn graphql_query(&self) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k == "query")
            .map(|(_, v)| v.as_str())
    }
}

/// Result of analyzing a `gh` command.
#[derive(Debug, Clone, PartialEq)]
pub struct GhAnalysis {
    /// The target repository (if determinable).
    pub repo: Option<String>,
    /// Whether this is a read or write operation.
    pub op_type: OpType,
    /// Human-readable description of what was detected.
    pub description: String,
}

/// Parsed and validated `gh api` command.
#[derive(Debug, Clone)]
pub struct GhApi {
    /// The parsed arguments.
    pub args: GhApiArgs,
    /// The target repository (if determinable from API path).
    /// Note: For GraphQL, this is None since queries can span multiple repos.
    pub repo: Option<String>,
    /// Whether this is a read or write operation.
    pub op_type: OpType,
    /// Whether this is a GraphQL request.
    pub is_graphql: bool,
    /// Human-readable description.
    pub description: String,
}

/// Parse and validate a `gh api` command using clap.
///
/// We use clap to explicitly define allowed options and reject everything else.
/// This is more secure than trying to filter arbitrary arguments.
///
/// For GraphQL requests, the query is parsed to determine if it's read-only
/// (queries/subscriptions) or contains mutations.
pub fn parse_api(args: &[String]) -> Result<GhApi> {
    // Find where "api" is in the args and get everything after it
    let api_args: Vec<&str> = match args.iter().position(|a| a == "api") {
        Some(pos) => args.iter().skip(pos + 1).map(|s| s.as_str()).collect(),
        None => args.iter().map(|s| s.as_str()).collect(),
    };

    // Parse using clap - this will reject any unknown options
    let parsed = match GhApiArgs::try_parse_from(api_args) {
        Ok(args) => args,
        Err(e) => {
            // Format the error nicely
            match e.kind() {
                clap::error::ErrorKind::UnknownArgument => {
                    bail!("Unknown option. Only --jq/-q and -f/--field are allowed.\n{e}");
                }
                clap::error::ErrorKind::MissingRequiredArgument => {
                    bail!("No API endpoint specified");
                }
                _ => bail!("{e}"),
            }
        }
    };

    let endpoint = &parsed.endpoint;
    let is_graphql = endpoint == "graphql" || endpoint == "/graphql";

    if is_graphql {
        // GraphQL request - extract and classify the query
        let query = parsed.graphql_query().ok_or_else(|| {
            eyre::eyre!("GraphQL requires a query field. Use: gh api graphql -f query='{{...}}'")
        })?;

        let op_type = classify_graphql_query(query);

        // Reject mutations for security reasons
        if op_type == OpType::Write {
            bail!("GraphQL mutations are not supported for security reasons. Only queries are allowed.");
        }

        Ok(GhApi {
            args: parsed,
            repo: None,            // GraphQL can span multiple repos
            op_type: OpType::Read, // Always read since we reject mutations
            is_graphql: true,
            description: "gh api graphql (query)".to_string(),
        })
    } else {
        // REST API request - always GET (read-only)
        let repo = extract_repo_from_api_path(endpoint);
        let description = format!("gh api {}", endpoint);

        Ok(GhApi {
            args: parsed,
            repo,
            op_type: OpType::Read, // REST is forced to GET
            is_graphql: false,
            description,
        })
    }
}

/// Build the final args for a validated `gh api` command.
///
/// For REST API: Forces GET method for read-only access.
/// For GraphQL: Uses POST method (required by GraphQL spec), but the query
/// has already been validated as read-only in `parse_api()`.
pub fn build_api_args(api: &GhApi) -> Vec<String> {
    let args = &api.args;

    // GraphQL uses POST, REST uses GET
    let method = if api.is_graphql { "POST" } else { "GET" };

    let mut result = vec![
        "api".to_string(),
        format!("--method={}", method),
        args.endpoint.clone(),
    ];

    // Pass through --jq if specified
    if let Some(jq) = &args.jq {
        result.push("--jq".to_string());
        result.push(jq.clone());
    }

    // Pass through fields for GraphQL
    for (key, value) in &args.fields {
        result.push("-f".to_string());
        result.push(format!("{}={}", key, value));
    }

    result
}

// ============================================================================
// Pending Review API Support
// ============================================================================

/// Marker token that must be present in review body for service-gator to manage it.
/// This prevents the agent from manipulating reviews created by humans.
pub const REVIEW_MARKER_TOKEN: &str = "<!-- service-gator-review -->";

/// Types of pending review operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingReviewOp {
    /// List reviews for a PR (GET /repos/{owner}/{repo}/pulls/{pull}/reviews)
    List,
    /// Create a new pending review (POST /repos/{owner}/{repo}/pulls/{pull}/reviews)
    Create,
    /// Get a specific review (GET /repos/{owner}/{repo}/pulls/{pull}/reviews/{id})
    Get,
    /// Update review body (PUT /repos/{owner}/{repo}/pulls/{pull}/reviews/{id})
    Update,
    /// Delete a pending review (DELETE /repos/{owner}/{repo}/pulls/{pull}/reviews/{id})
    Delete,
}

/// Parsed pending review API request.
#[derive(Debug, Clone)]
pub struct PendingReviewRequest {
    /// The target repository (owner/repo).
    pub repo: String,
    /// The pull request number.
    pub pull_number: PullRequestNumber,
    /// The review ID (if targeting a specific review).
    pub review_id: Option<u64>,
    /// The operation to perform.
    pub op: PendingReviewOp,
    /// The request body (for create/update operations).
    pub body: Option<serde_json::Value>,
}

impl PendingReviewRequest {
    /// Build the gh api arguments for this request.
    pub fn build_args(&self) -> Vec<String> {
        let endpoint = match self.review_id {
            Some(id) => format!(
                "repos/{}/pulls/{}/reviews/{}",
                self.repo, self.pull_number, id
            ),
            None => format!("repos/{}/pulls/{}/reviews", self.repo, self.pull_number),
        };

        let method = match self.op {
            PendingReviewOp::List | PendingReviewOp::Get => "GET",
            PendingReviewOp::Create => "POST",
            PendingReviewOp::Update => "PUT",
            PendingReviewOp::Delete => "DELETE",
        };

        let mut args = vec!["api".to_string(), format!("--method={}", method), endpoint];

        // Add body for create/update
        if let Some(body) = &self.body {
            args.push("--input".to_string());
            args.push("-".to_string());
            // The caller needs to pipe the body to stdin
            // We store the serialized body for reference
            let _ = body; // Body is passed via stdin
        }

        args
    }

    /// Get the JSON body to send via stdin (for create/update).
    pub fn body_json(&self) -> Option<String> {
        self.body.as_ref().map(|b| b.to_string())
    }
}

/// Parse and validate a pending review API request.
///
/// Accepts paths like:
/// - repos/{owner}/{repo}/pulls/{n}/reviews (list/create)
/// - repos/{owner}/{repo}/pulls/{n}/reviews/{id} (get/update/delete)
///
/// Rejects:
/// - repos/{owner}/{repo}/pulls/{n}/reviews/{id}/events (submit - human only)
/// - repos/{owner}/{repo}/pulls/{n}/reviews/{id}/dismissals (dismiss - human only)
pub fn parse_pending_review_request(
    endpoint: &str,
    method: &str,
    body: Option<serde_json::Value>,
) -> Result<PendingReviewRequest> {
    let path = endpoint.trim_start_matches('/');

    // Reject forbidden sub-endpoints
    if path.contains("/events") {
        bail!("Cannot submit reviews via API - human must submit in GitHub UI");
    }
    if path.contains("/dismissals") {
        bail!("Cannot dismiss reviews via API - human must dismiss in GitHub UI");
    }
    if path.contains("/comments") {
        bail!("Use the reviews endpoint to create reviews with comments atomically");
    }

    // Parse: repos/{owner}/{repo}/pulls/{n}/reviews[/{id}]
    // Use split_once() to incrementally parse the path
    let rest = path
        .strip_prefix("repos/")
        .ok_or_else(|| eyre::eyre!("Path must start with 'repos/'"))?;

    let (owner, rest) = rest
        .split_once('/')
        .ok_or_else(|| eyre::eyre!("Missing owner in path"))?;

    let (repo_name, rest) = rest
        .split_once('/')
        .ok_or_else(|| eyre::eyre!("Missing repo in path"))?;

    let rest = rest
        .strip_prefix("pulls/")
        .ok_or_else(|| eyre::eyre!("Expected 'pulls/' after repo"))?;

    let (pull_str, rest) = rest.split_once('/').unwrap_or((rest, ""));

    let pull_number: PullRequestNumber = pull_str
        .parse()
        .map_err(|_| eyre::eyre!("Invalid pull request number: {}", pull_str))?;

    let rest = rest
        .strip_prefix("reviews")
        .ok_or_else(|| eyre::eyre!("Expected 'reviews' in path"))?;

    // After "reviews", we either have nothing, "/" + review_id, or "/" + review_id + "/..."
    let review_id: Option<u64> = if rest.is_empty() {
        None
    } else {
        let rest = rest
            .strip_prefix('/')
            .ok_or_else(|| eyre::eyre!("Expected '/' after 'reviews'"))?;
        if rest.is_empty() {
            None
        } else {
            // Take just the numeric part (ignore any trailing path segments)
            let id_str = rest.split('/').next().unwrap_or(rest);
            Some(
                id_str
                    .parse()
                    .map_err(|_| eyre::eyre!("Invalid review ID: {}", id_str))?,
            )
        }
    };

    let repo = format!("{}/{}", owner, repo_name);

    // Determine operation from method and path
    let op = match (method.to_uppercase().as_str(), review_id) {
        ("GET", None) => PendingReviewOp::List,
        ("GET", Some(_)) => PendingReviewOp::Get,
        ("POST", None) => PendingReviewOp::Create,
        ("PUT", Some(_)) => PendingReviewOp::Update,
        ("DELETE", Some(_)) => PendingReviewOp::Delete,
        ("POST", Some(_)) => bail!("POST to specific review ID not allowed"),
        ("PUT", None) => bail!("PUT requires a review ID"),
        ("DELETE", None) => bail!("DELETE requires a review ID"),
        (m, _) => bail!("Unsupported method for reviews: {}", m),
    };

    // For create operations, validate and sanitize the body
    let body = if let Some(mut b) = body {
        if op == PendingReviewOp::Create {
            // Remove 'event' field to force PENDING state
            if let Some(obj) = b.as_object_mut() {
                if obj.remove("event").is_some() {
                    // Silently removed - we always create pending reviews
                }

                // Ensure marker token is in the body
                let body_text = obj.get("body").and_then(|v| v.as_str()).unwrap_or("");

                if !body_text.contains(REVIEW_MARKER_TOKEN) {
                    // Prepend marker token to body
                    let new_body = format!("{}\n\n{}", REVIEW_MARKER_TOKEN, body_text);
                    obj.insert("body".to_string(), serde_json::Value::String(new_body));
                }
            }
        }
        Some(b)
    } else {
        None
    };

    Ok(PendingReviewRequest {
        repo,
        pull_number,
        review_id,
        op,
        body,
    })
}

/// Check if a review body contains the service-gator marker token.
pub fn review_has_marker(body: &str) -> bool {
    body.contains(REVIEW_MARKER_TOKEN)
}

/// Validate that a review can be managed by checking for the marker token.
/// Returns an error if the review doesn't have the marker.
pub fn validate_review_marker(review_json: &serde_json::Value) -> Result<()> {
    let body = review_json
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !review_has_marker(body) {
        bail!(
            "Review does not contain service-gator marker token. \
             Only reviews created by service-gator can be managed. \
             Expected marker: {}",
            REVIEW_MARKER_TOKEN
        );
    }

    Ok(())
}

/// Validate that a review is in PENDING state (not yet submitted).
pub fn validate_review_pending(review_json: &serde_json::Value) -> Result<()> {
    let state = review_json
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");

    if state != "PENDING" {
        bail!(
            "Review is in {} state, not PENDING. \
             Only pending reviews can be managed.",
            state
        );
    }

    Ok(())
}

/// Extended help text for the pending review tool.
pub const REVIEW_TOOL_HELP: &str = "\
# Pending Review Tool

Manage pending (draft) PR reviews on GitHub. Reviews are created in PENDING \
state and must be submitted by a human through the GitHub UI.

## Operations

- create: Create a pending review. Errors if a pending service-gator review \
already exists on this PR; set replace=true to delete the existing one first. \
Provide 'body' (review summary) and optionally 'comments' (inline comments \
on specific lines).
- list: List all reviews on a PR.
- get: Get a specific review by review_id.
- update: Update the body text of an existing pending review (by review_id). \
Cannot modify inline comments — use create to replace the whole review instead.
- delete: Delete a pending review by review_id.
- extended-help: Show this help text.

## Dry Run

Set dry_run: true with the 'create' operation to validate inputs without \
submitting. Returns a summary of what would be created.

## Example (create)

  operation: \"create\"
  repo: \"owner/repo\"
  pull_number: 42
  body: \"Review summary text.\"
  comments:
    - path: \"src/lib.rs\", line: 42, body: \"Consider adding error handling here.\"
    - path: \"src/main.rs\", line: 15, body: \"Use eprintln! for error output.\"

## Marker Token

All reviews created by this tool include a hidden marker token in the body. \
This allows the tool to identify its own pending reviews for idempotent \
replacement. Only reviews with this marker can be updated or deleted.
";

/// Analyze a `gh` command to determine target repo and read/write classification.
/// Note: In API-only mode, prefer using `analyze_api()` directly.
pub fn analyze(args: &[String]) -> GhAnalysis {
    let parsed = ParsedArgs::from_args(args);

    // Handle `gh api` specially - need to check HTTP method
    if parsed.command.as_deref() == Some("api") {
        return analyze_api_command(args, &parsed);
    }

    // For other commands, classify based on command/subcommand
    let op_type = classify_command(parsed.command.as_deref(), parsed.subcommand.as_deref());

    // Try to get repo from args, or detect from git
    let repo = parsed.repo.or_else(|| detect_repo_from_git().ok());

    let description = match (&parsed.command, &parsed.subcommand) {
        (Some(cmd), Some(sub)) => format!("gh {} {}", cmd, sub),
        (Some(cmd), None) => format!("gh {}", cmd),
        _ => "gh".to_string(),
    };

    GhAnalysis {
        repo,
        op_type,
        description,
    }
}

/// Analyze a `gh api` command.
fn analyze_api_command(args: &[String], parsed: &ParsedArgs) -> GhAnalysis {
    let api_path = extract_api_path(args);

    // Check if this is a GraphQL request
    let is_graphql =
        api_path.as_deref() == Some("graphql") || api_path.as_deref() == Some("/graphql");

    let (op_type, description) = if is_graphql {
        analyze_graphql_api(args)
    } else {
        analyze_rest_api(args, api_path.as_deref())
    };

    // Try to extract repo from the API path (REST only)
    let repo = api_path
        .as_ref()
        .and_then(|p| extract_repo_from_api_path(p))
        .or_else(|| parsed.repo.clone())
        .or_else(|| detect_repo_from_git().ok());

    GhAnalysis {
        repo,
        op_type,
        description,
    }
}

/// Analyze a REST API call.
fn analyze_rest_api(args: &[String], path: Option<&str>) -> (OpType, String) {
    let method = extract_api_method(args);
    let op_type = match method.to_uppercase().as_str() {
        "GET" | "HEAD" => OpType::Read,
        _ => OpType::Write, // POST, PUT, PATCH, DELETE are all writes
    };

    let description = format!("gh api {} {}", method, path.unwrap_or("<path>"));
    (op_type, description)
}

/// Analyze a GraphQL API call.
/// GraphQL uses POST but can be query (read) or mutation (write).
fn analyze_graphql_api(args: &[String]) -> (OpType, String) {
    // Extract the query from -f query=... or -F query=... or --field query=...
    let query = extract_graphql_query(args);

    let op_type = match &query {
        Some(q) => classify_graphql_query(q),
        None => OpType::Write, // If we can't determine, assume write (safer)
    };

    let description = match op_type {
        OpType::Read => "gh api graphql (query)".to_string(),
        // Comment and Create are JIRA-specific; GraphQL mutations map to Write
        OpType::Write | OpType::Comment | OpType::Create => "gh api graphql (mutation)".to_string(),
    };

    (op_type, description)
}

/// Extract GraphQL query string from arguments.
fn extract_graphql_query(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        // Handle -f query='...' or -F query='...' or --field query='...'
        if arg == "-f" || arg == "-F" || arg == "--field" || arg == "--raw-field" {
            if let Some(field) = iter.next() {
                if let Some(query) = field.strip_prefix("query=") {
                    return Some(query.to_string());
                }
            }
        }
        // Handle -f=query=... format
        for prefix in ["-f", "-F", "--field=", "--raw-field="] {
            if let Some(rest) = arg.strip_prefix(prefix) {
                if let Some(query) = rest.strip_prefix("query=") {
                    return Some(query.to_string());
                }
            }
        }
    }
    None
}

/// Classify a GraphQL query as read or write using proper parsing.
///
/// - Returns `OpType::Read` if all operations are queries or subscriptions
/// - Returns `OpType::Write` if any operation is a mutation
/// - Returns `OpType::Write` on parse errors (conservative - deny on error)
/// - Returns `OpType::Write` for documents with only fragments (not executable)
fn classify_graphql_query(query: &str) -> OpType {
    let doc = match graphql_parser::query::parse_query::<&str>(query) {
        Ok(doc) => doc,
        Err(_) => return OpType::Write, // Parse error: conservative deny
    };

    // Track whether we found any executable operations
    let mut has_operation = false;

    for def in &doc.definitions {
        match def {
            Definition::Operation(op) => {
                has_operation = true;
                // Check if this operation is a mutation
                let is_mutation = match op {
                    OperationDefinition::Mutation(_) => true,
                    OperationDefinition::Query(_)
                    | OperationDefinition::Subscription(_)
                    | OperationDefinition::SelectionSet(_) => false,
                };
                if is_mutation {
                    return OpType::Write;
                }
            }
            Definition::Fragment(_) => {
                // Fragments alone are not executable; continue checking
            }
        }
    }

    // If no operations found (empty doc or only fragments), deny
    if !has_operation {
        return OpType::Write;
    }

    OpType::Read
}

/// Classify a gh command/subcommand as read or write.
fn classify_command(command: Option<&str>, subcommand: Option<&str>) -> OpType {
    match (command, subcommand) {
        // Explicitly read-only operations
        (Some("pr"), Some("list" | "view" | "status" | "diff" | "checks")) => OpType::Read,
        (Some("issue"), Some("list" | "view" | "status")) => OpType::Read,
        (Some("repo"), Some("list" | "view" | "clone")) => OpType::Read,
        (Some("release"), Some("list" | "view" | "download")) => OpType::Read,
        (Some("run"), Some("list" | "view" | "watch" | "download")) => OpType::Read,
        (Some("workflow"), Some("list" | "view")) => OpType::Read,
        (Some("cache"), Some("list")) => OpType::Read,
        (Some("search"), Some(_)) => OpType::Read, // all search is read-only
        (Some("auth"), Some("status" | "token")) => OpType::Read,
        (Some("config"), Some("get" | "list")) => OpType::Read,
        (Some("ssh-key" | "gpg-key"), Some("list")) => OpType::Read,
        (Some("secret" | "variable"), Some("list" | "get")) => OpType::Read,
        (Some("ruleset"), Some("list" | "view" | "check")) => OpType::Read,
        (Some("project"), Some("list" | "view" | "field-list" | "item-list")) => OpType::Read,
        (Some("codespace"), Some("list" | "view" | "logs")) => OpType::Read,
        (Some("extension"), Some("list" | "search")) => OpType::Read,
        (Some("label"), Some("list")) => OpType::Read,
        (Some("alias"), Some("list")) => OpType::Read,
        (Some("org"), Some("list")) => OpType::Read,
        (Some("gist"), Some("list" | "view")) => OpType::Read,
        (Some("attestation"), Some("verify")) => OpType::Read,

        // Top-level read-only commands
        (Some("status" | "browse" | "completion"), _) => OpType::Read,

        // Everything else is a write
        _ => OpType::Write,
    }
}

/// Extract the HTTP method from `gh api` arguments.
fn extract_api_method(args: &[String]) -> String {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        if arg == "-X" || arg == "--method" {
            if let Some(method) = iter.next() {
                return method.clone();
            }
        }
        if let Some(method) = arg.strip_prefix("--method=") {
            return method.to_string();
        }
        if let Some(method) = arg.strip_prefix("-X") {
            if !method.is_empty() {
                return method.to_string();
            }
        }
    }
    // Default is GET
    "GET".to_string()
}

/// Extract the API path from `gh api` arguments.
fn extract_api_path(args: &[String]) -> Option<String> {
    let mut skip_next = false;
    let mut found_api = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        // Skip flags and their values
        if arg.starts_with('-') {
            // Flags that take a value
            if arg == "-X"
                || arg == "--method"
                || arg == "-H"
                || arg == "--header"
                || arg == "-f"
                || arg == "-F"
                || arg == "--field"
                || arg == "--raw-field"
                || arg == "-q"
                || arg == "--jq"
                || arg == "-t"
                || arg == "--template"
                || arg == "--input"
                || arg == "--hostname"
            {
                skip_next = true;
            }
            continue;
        }

        if arg == "api" {
            found_api = true;
            continue;
        }

        // First non-flag after "api" is the path
        if found_api {
            return Some(arg.clone());
        }
    }

    None
}

/// Validate that a path component (owner or repo name) contains only valid characters.
/// GitHub allows alphanumeric, hyphens, underscores, and dots.
fn is_valid_path_component(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Extract repository from an API path like `/repos/owner/repo/...`.
pub fn extract_repo_from_api_path(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');
    let rest = path.strip_prefix("repos/")?;
    let [owner, repo]: [&str; 2] = rest.split('/').next_array()?;

    // Validate path components to prevent injection attacks
    if !is_valid_path_component(owner) || !is_valid_path_component(repo) {
        return None;
    }

    Some(format!("{owner}/{repo}"))
}

/// Extract resource reference from an API path.
///
/// Returns references in the format `owner/repo#N` for paths that target
/// specific PRs or issues. This enables scoped write permissions.
///
/// Examples:
/// - `/repos/owner/repo/pulls/123` → Some("owner/repo#123")
/// - `/repos/owner/repo/issues/456` → Some("owner/repo#456")
/// - `/repos/owner/repo/pulls/123/comments` → Some("owner/repo#123")
/// - `/repos/owner/repo/pulls` → None (no specific resource)
pub fn extract_resource_from_api_path(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');
    let rest = path.strip_prefix("repos/")?;
    // Pattern: owner/repo/resource_type/resource_id[/...]
    let [owner, repo, resource_type, resource_id]: [&str; 4] = rest.split('/').next_array()?;

    // Only return if resource_id is a valid number and resource type is PR or issue
    resource_id.parse::<u64>().ok()?;

    match resource_type {
        "pulls" | "issues" => Some(format!("{owner}/{repo}#{resource_id}")),
        _ => None,
    }
}

/// Parsed gh command arguments.
struct ParsedArgs {
    command: Option<String>,
    subcommand: Option<String>,
    repo: Option<String>,
}

impl ParsedArgs {
    fn from_args(args: &[String]) -> Self {
        let mut command = None;
        let mut subcommand = None;
        let mut repo = None;
        let mut skip_next = false;

        for (i, arg) in args.iter().enumerate() {
            if skip_next {
                skip_next = false;
                continue;
            }

            // Handle repo flags
            if arg == "-R" || arg == "--repo" {
                if let Some(r) = args.get(i + 1) {
                    repo = Some(r.clone());
                    skip_next = true;
                }
                continue;
            }
            if let Some(r) = arg.strip_prefix("--repo=") {
                repo = Some(r.to_string());
                continue;
            }
            if let Some(r) = arg.strip_prefix("-R") {
                if !r.is_empty() {
                    repo = Some(r.to_string());
                    continue;
                }
            }

            // Skip other flags
            if arg.starts_with('-') {
                // Flags that take a value
                if arg == "-H" || arg == "--hostname" {
                    skip_next = true;
                }
                continue;
            }

            // First positional is command, second is subcommand
            if command.is_none() {
                command = Some(arg.clone());
            } else if subcommand.is_none() {
                subcommand = Some(arg.clone());
            }
        }

        Self {
            command,
            subcommand,
            repo,
        }
    }
}

/// Detect the current repo using `gh repo view`.
fn detect_repo_from_git() -> Result<String, String> {
    let output = Command::new("gh")
        .args([
            "repo",
            "view",
            "--json",
            "nameWithOwner",
            "-q",
            ".nameWithOwner",
        ])
        .output()
        .map_err(|e| format!("Failed to run gh repo view: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Failed to detect repo: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let repo = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if repo.is_empty() {
        return Err("Could not detect repository".to_string());
    }
    Ok(repo)
}

// ============================================================================
// Shared command parsing utilities
// ============================================================================

/// Classify a gh command into the fine-grained operation type.
pub fn classify_gh_op(args: &[String], analysis: &GhAnalysis) -> GhOpType {
    match analysis.op_type {
        OpType::Read => GhOpType::Read,
        // Comment and Create are JIRA-specific; treat as Write for GitHub
        OpType::Write | OpType::Comment | OpType::Create => {
            let (cmd, subcmd) = parse_gh_cmd(args);

            match (cmd.as_deref(), subcmd.as_deref()) {
                (Some("pr"), Some("create")) if has_draft_flag(args) => GhOpType::CreateDraft,
                (Some("pr"), Some("comment" | "edit"))
                | (Some("issue"), Some("comment" | "edit")) => GhOpType::WriteResource,
                _ => GhOpType::Write,
            }
        }
    }
}

/// Parse command and subcommand from gh args.
pub fn parse_gh_cmd(args: &[String]) -> (Option<String>, Option<String>) {
    let mut cmd = None;
    let mut subcmd = None;
    let mut skip = false;

    for arg in args {
        if skip {
            skip = false;
            continue;
        }
        if arg.starts_with('-') {
            if arg == "-R" || arg == "--repo" || arg == "-H" || arg == "--hostname" {
                skip = true;
            }
            continue;
        }
        if cmd.is_none() {
            cmd = Some(arg.clone());
        } else if subcmd.is_none() {
            subcmd = Some(arg.clone());
            break;
        }
    }

    (cmd, subcmd)
}

/// Check if --draft flag is present.
pub fn has_draft_flag(args: &[String]) -> bool {
    args.iter().any(|a| a == "--draft" || a == "-d")
}

/// Extract resource reference (owner/repo#number) for PR/issue operations.
pub fn extract_gh_resource_ref(args: &[String], repo: &str) -> Option<String> {
    let (cmd, subcmd) = parse_gh_cmd(args);

    match (cmd.as_deref(), subcmd.as_deref()) {
        (Some("pr"), Some("comment" | "edit" | "view" | "close" | "merge" | "ready"))
        | (Some("issue"), Some("comment" | "edit" | "view" | "close")) => {
            if let Some(num) = extract_resource_number(args) {
                return Some(format!("{}#{}", repo, num));
            }
        }
        _ => {}
    }

    None
}

/// Extract PR/issue number from args.
pub fn extract_resource_number(args: &[String]) -> Option<String> {
    let mut skip = false;
    let mut found_cmd = false;
    let mut found_subcmd = false;

    for arg in args {
        if skip {
            skip = false;
            continue;
        }
        if arg.starts_with('-') {
            if arg == "-R"
                || arg == "--repo"
                || arg == "-b"
                || arg == "--body"
                || arg == "-t"
                || arg == "--title"
                || arg == "-F"
                || arg == "--body-file"
            {
                skip = true;
            }
            continue;
        }

        if !found_cmd {
            found_cmd = true;
            continue;
        }
        if !found_subcmd {
            found_subcmd = true;
            continue;
        }

        // Handle URL format
        if arg.contains("/pull/") || arg.contains("/issues/") {
            if let Some(num) = arg.rsplit('/').next() {
                return Some(num.to_string());
            }
        }
        // Plain number
        if arg.chars().all(|c| c.is_ascii_digit()) {
            return Some(arg.clone());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::assert_equal;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn test_classify_read_commands() {
        assert_eq!(classify_command(Some("pr"), Some("list")), OpType::Read);
        assert_eq!(classify_command(Some("pr"), Some("view")), OpType::Read);
        assert_eq!(classify_command(Some("issue"), Some("list")), OpType::Read);
        assert_eq!(classify_command(Some("status"), None), OpType::Read);
        assert_eq!(
            classify_command(Some("search"), Some("issues")),
            OpType::Read
        );
    }

    #[test]
    fn test_classify_write_commands() {
        assert_eq!(classify_command(Some("pr"), Some("create")), OpType::Write);
        assert_eq!(classify_command(Some("pr"), Some("merge")), OpType::Write);
        assert_eq!(
            classify_command(Some("issue"), Some("create")),
            OpType::Write
        );
        assert_eq!(
            classify_command(Some("repo"), Some("create")),
            OpType::Write
        );
    }

    #[test]
    fn test_extract_api_method() {
        assert_eq!(extract_api_method(&args("api /repos/foo/bar")), "GET");
        assert_eq!(
            extract_api_method(&args("api -X POST /repos/foo/bar")),
            "POST"
        );
        assert_eq!(
            extract_api_method(&args("api --method PUT /repos/foo/bar")),
            "PUT"
        );
        assert_eq!(
            extract_api_method(&args("api --method=DELETE /repos/foo/bar")),
            "DELETE"
        );
    }

    #[test]
    fn test_extract_api_path() {
        assert_eq!(
            extract_api_path(&args("api /repos/foo/bar")),
            Some("/repos/foo/bar".into())
        );
        assert_eq!(
            extract_api_path(&args("api -X POST /repos/foo/bar")),
            Some("/repos/foo/bar".into())
        );
        assert_eq!(
            extract_api_path(&args("api --jq .name /repos/foo/bar")),
            Some("/repos/foo/bar".into())
        );
    }

    #[test]
    fn test_extract_repo_from_api_path() {
        assert_eq!(
            extract_repo_from_api_path("/repos/owner/repo/pulls"),
            Some("owner/repo".into())
        );
        assert_eq!(
            extract_repo_from_api_path("repos/owner/repo/issues"),
            Some("owner/repo".into())
        );
        assert_eq!(extract_repo_from_api_path("/user/repos"), None);
        assert_eq!(extract_repo_from_api_path("/orgs/foo/repos"), None);
    }

    #[test]
    fn test_extract_resource_from_api_path() {
        // PR endpoints - returns owner/repo#N format for permission matching
        assert_eq!(
            extract_resource_from_api_path("/repos/owner/repo/pulls/123"),
            Some("owner/repo#123".into())
        );
        assert_eq!(
            extract_resource_from_api_path("repos/owner/repo/pulls/456/comments"),
            Some("owner/repo#456".into())
        );
        // Issue endpoints
        assert_eq!(
            extract_resource_from_api_path("/repos/owner/repo/issues/789"),
            Some("owner/repo#789".into())
        );
        assert_eq!(
            extract_resource_from_api_path("repos/myorg/myrepo/issues/42/labels"),
            Some("myorg/myrepo#42".into())
        );
        // No specific resource
        assert_eq!(
            extract_resource_from_api_path("/repos/owner/repo/pulls"),
            None
        );
        assert_eq!(
            extract_resource_from_api_path("/repos/owner/repo/issues"),
            None
        );
        assert_eq!(extract_resource_from_api_path("/repos/owner/repo"), None);
        // Non-PR/issue resources don't have scoped permissions
        assert_eq!(
            extract_resource_from_api_path("/repos/owner/repo/branches/main"),
            None
        );
    }

    #[test]
    fn test_analyze_pr_list() {
        let result = analyze(&args("pr list -R owner/repo"));
        assert_eq!(result.op_type, OpType::Read);
        assert_eq!(result.repo, Some("owner/repo".into()));
    }

    #[test]
    fn test_analyze_pr_create() {
        let result = analyze(&args("pr create --draft -R owner/repo"));
        assert_eq!(result.op_type, OpType::Write);
        assert_eq!(result.repo, Some("owner/repo".into()));
    }

    #[test]
    fn test_analyze_api_get() {
        let result = analyze(&args("api /repos/owner/repo/pulls"));
        assert_eq!(result.op_type, OpType::Read);
        assert_eq!(result.repo, Some("owner/repo".into()));
    }

    #[test]
    fn test_analyze_api_post() {
        let result = analyze(&args("api -X POST /repos/owner/repo/pulls"));
        assert_eq!(result.op_type, OpType::Write);
        assert_eq!(result.repo, Some("owner/repo".into()));
    }

    #[test]
    fn test_classify_graphql_query() {
        // Explicit query keyword
        assert_eq!(
            classify_graphql_query("query { viewer { login } }"),
            OpType::Read
        );
        // Bare query (no keyword)
        assert_eq!(classify_graphql_query("{ viewer { login } }"), OpType::Read);
        // Query with name
        assert_eq!(
            classify_graphql_query("query GetUser { viewer { login } }"),
            OpType::Read
        );
        // Mutation
        assert_eq!(
            classify_graphql_query("mutation { createIssue(...) { id } }"),
            OpType::Write
        );
        // Mutation with name
        assert_eq!(
            classify_graphql_query("mutation CreateIssue { createIssue(...) { id } }"),
            OpType::Write
        );
        // Subscription is a read
        assert_eq!(
            classify_graphql_query("subscription { issueCreated { id } }"),
            OpType::Read
        );
        // Query with leading single-line comment (# is the only valid GraphQL comment syntax)
        assert_eq!(
            classify_graphql_query("# fetch user\nquery { viewer { login } }"),
            OpType::Read
        );
        // Mutation after comment
        assert_eq!(
            classify_graphql_query("# do something\nmutation { foo }"),
            OpType::Write
        );
        // Multiple leading comments
        assert_eq!(
            classify_graphql_query("# comment 1\n# comment 2\n{ viewer { login } }"),
            OpType::Read
        );
    }

    #[test]
    fn test_extract_graphql_query() {
        // Must construct args properly since query contains spaces
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "-f".to_string(),
            "query={ viewer { login } }".to_string(),
        ];
        assert_eq!(
            extract_graphql_query(&args),
            Some("{ viewer { login } }".into())
        );
    }

    // Additional classify_graphql_query edge case tests

    #[test]
    fn test_classify_graphql_query_whitespace_variations() {
        // Leading whitespace variations
        assert_eq!(
            classify_graphql_query("  query { viewer { login } }"),
            OpType::Read
        );
        assert_eq!(
            classify_graphql_query("\n\nquery { viewer { login } }"),
            OpType::Read
        );
        assert_eq!(
            classify_graphql_query("\t\tmutation { createIssue { id } }"),
            OpType::Write
        );
        assert_eq!(
            classify_graphql_query("   { viewer { login } }"),
            OpType::Read
        );
        // Trailing whitespace shouldn't matter
        assert_eq!(
            classify_graphql_query("query { viewer }   \n\n"),
            OpType::Read
        );
    }

    #[test]
    fn test_classify_graphql_query_named_with_variables() {
        // Named operations with variable definitions
        assert_eq!(
            classify_graphql_query("query GetPR($id: ID!) { node(id: $id) { id } }"),
            OpType::Read
        );
        assert_eq!(
            classify_graphql_query(
                "query GetUser($login: String!) { user(login: $login) { name } }"
            ),
            OpType::Read
        );
        assert_eq!(
            classify_graphql_query("mutation CreateIssue($input: CreateIssueInput!) { createIssue(input: $input) { id } }"),
            OpType::Write
        );
        // Subscription with variables
        assert_eq!(
            classify_graphql_query(
                "subscription OnIssue($repo: ID!) { issueCreated(repo: $repo) { id } }"
            ),
            OpType::Read
        );
    }

    #[test]
    fn test_classify_graphql_query_fragments() {
        // Fragment definitions alone (no query/mutation)
        // Fragments by themselves don't execute, so default to Write (safe)
        assert_eq!(
            classify_graphql_query("fragment UserFields on User { name email }"),
            OpType::Write
        );
        assert_eq!(
            classify_graphql_query("fragment IssueFields on Issue { title body }"),
            OpType::Write
        );
    }

    #[test]
    fn test_classify_graphql_query_empty_and_malformed() {
        // Empty input
        assert_eq!(classify_graphql_query(""), OpType::Write);
        // Whitespace only
        assert_eq!(classify_graphql_query("   "), OpType::Write);
        assert_eq!(classify_graphql_query("\n\t\n"), OpType::Write);
        // Malformed/garbage
        assert_eq!(classify_graphql_query("not a query"), OpType::Write);
        assert_eq!(classify_graphql_query("SELECT * FROM users"), OpType::Write);
        // Partial keywords
        assert_eq!(classify_graphql_query("quer"), OpType::Write);
        assert_eq!(classify_graphql_query("mutat"), OpType::Write);
        // Only comments, no actual operation (returns Write as safe default for unparseable input)
        assert_eq!(classify_graphql_query("# just a comment"), OpType::Write);
    }

    #[test]
    fn test_classify_graphql_query_multiple_operations() {
        // Multiple operations in one document: returns Write if ANY operation is a mutation
        // (security principle: if document contains any write operation, treat as Write)
        let multi = "query First { viewer { login } } mutation Second { createIssue { id } }";
        assert_eq!(classify_graphql_query(multi), OpType::Write);

        let multi_mutation_first =
            "mutation First { createIssue { id } } query Second { viewer { login } }";
        assert_eq!(classify_graphql_query(multi_mutation_first), OpType::Write);

        // Query with fragment definition after (no mutation, so Read)
        let query_with_fragment =
            "query GetUser { user { ...UserFields } } fragment UserFields on User { name }";
        assert_eq!(classify_graphql_query(query_with_fragment), OpType::Read);
    }

    // Additional extract_graphql_query variation tests

    #[test]
    fn test_extract_graphql_query_uppercase_f() {
        // -F (uppercase) form
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "-F".to_string(),
            "query={ viewer { login } }".to_string(),
        ];
        assert_eq!(
            extract_graphql_query(&args),
            Some("{ viewer { login } }".into())
        );
    }

    #[test]
    fn test_extract_graphql_query_field_form() {
        // --field form
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "--field".to_string(),
            "query=mutation { createIssue { id } }".to_string(),
        ];
        assert_eq!(
            extract_graphql_query(&args),
            Some("mutation { createIssue { id } }".into())
        );
    }

    #[test]
    fn test_extract_graphql_query_raw_field_form() {
        // --raw-field form
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "--raw-field".to_string(),
            "query={ viewer { login } }".to_string(),
        ];
        assert_eq!(
            extract_graphql_query(&args),
            Some("{ viewer { login } }".into())
        );
    }

    #[test]
    fn test_extract_graphql_query_combined_flag_form() {
        // Combined flag form: --field=query=...
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "--field=query={ viewer { login } }".to_string(),
        ];
        assert_eq!(
            extract_graphql_query(&args),
            Some("{ viewer { login } }".into())
        );

        // --raw-field= form
        let args2 = vec![
            "api".to_string(),
            "graphql".to_string(),
            "--raw-field=query=mutation { foo }".to_string(),
        ];
        assert_eq!(
            extract_graphql_query(&args2),
            Some("mutation { foo }".into())
        );
    }

    #[test]
    fn test_extract_graphql_query_multiple_fields() {
        // Multiple fields with query not first
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "-f".to_string(),
            "owner=cgwalters".to_string(),
            "-f".to_string(),
            "repo=service-gator".to_string(),
            "-f".to_string(),
            "query={ repository(owner: $owner, name: $repo) { id } }".to_string(),
        ];
        assert_eq!(
            extract_graphql_query(&args),
            Some("{ repository(owner: $owner, name: $repo) { id } }".into())
        );
    }

    #[test]
    fn test_extract_graphql_query_no_query_field() {
        // No query field present
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "-f".to_string(),
            "owner=cgwalters".to_string(),
            "-f".to_string(),
            "name=service-gator".to_string(),
        ];
        assert_eq!(extract_graphql_query(&args), None);

        // Empty args
        assert_eq!(extract_graphql_query(&[]), None);

        // Only has api graphql, no field flags
        let args2 = vec!["api".to_string(), "graphql".to_string()];
        assert_eq!(extract_graphql_query(&args2), None);
    }

    #[test]
    fn test_analyze_graphql_query() {
        // We need to construct args with the query properly
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "-f".to_string(),
            "query={ viewer { login } }".to_string(),
        ];
        let result = analyze(&args);
        assert_eq!(result.op_type, OpType::Read);
        assert!(result.description.contains("query"));
    }

    #[test]
    fn test_analyze_graphql_mutation() {
        // Note: analyze() still returns Write for mutations (it uses classify_graphql_query)
        // but parse_api() now rejects mutations entirely
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "-f".to_string(),
            "query=mutation { createIssue { id } }".to_string(),
        ];
        let result = analyze(&args);
        assert_eq!(result.op_type, OpType::Write);
        assert!(result.description.contains("mutation"));
    }

    // Direct unit tests for ParsedArgs::from_args()

    #[test]
    fn test_parsed_args_basic_command() {
        let parsed = ParsedArgs::from_args(&args("pr list"));
        assert_eq!(parsed.command.as_deref(), Some("pr"));
        assert_eq!(parsed.subcommand.as_deref(), Some("list"));
        assert_eq!(parsed.repo, None);
    }

    #[test]
    fn test_parsed_args_repo_short_flag() {
        let parsed = ParsedArgs::from_args(&args("-R owner/repo pr list"));
        assert_eq!(parsed.repo.as_deref(), Some("owner/repo"));
        assert_eq!(parsed.command.as_deref(), Some("pr"));
        assert_eq!(parsed.subcommand.as_deref(), Some("list"));
    }

    #[test]
    fn test_parsed_args_repo_long_flag() {
        let parsed = ParsedArgs::from_args(&args("--repo owner/repo pr list"));
        assert_eq!(parsed.repo.as_deref(), Some("owner/repo"));
        assert_eq!(parsed.command.as_deref(), Some("pr"));
        assert_eq!(parsed.subcommand.as_deref(), Some("list"));
    }

    #[test]
    fn test_parsed_args_repo_long_flag_equals() {
        let parsed = ParsedArgs::from_args(&args("--repo=owner/repo pr list"));
        assert_eq!(parsed.repo.as_deref(), Some("owner/repo"));
        assert_eq!(parsed.command.as_deref(), Some("pr"));
        assert_eq!(parsed.subcommand.as_deref(), Some("list"));
    }

    #[test]
    fn test_parsed_args_repo_short_flag_attached() {
        let parsed = ParsedArgs::from_args(&args("-Rowner/repo pr list"));
        assert_eq!(parsed.repo.as_deref(), Some("owner/repo"));
        assert_eq!(parsed.command.as_deref(), Some("pr"));
        assert_eq!(parsed.subcommand.as_deref(), Some("list"));
    }

    #[test]
    fn test_parsed_args_mixed_flags() {
        let parsed = ParsedArgs::from_args(&args("pr list -R owner/repo --state open"));
        assert_eq!(parsed.command.as_deref(), Some("pr"));
        assert_eq!(parsed.subcommand.as_deref(), Some("list"));
        assert_eq!(parsed.repo.as_deref(), Some("owner/repo"));
    }

    #[test]
    fn test_parsed_args_command_only() {
        let parsed = ParsedArgs::from_args(&args("status"));
        assert_eq!(parsed.command.as_deref(), Some("status"));
        assert_eq!(parsed.subcommand, None);
        assert_eq!(parsed.repo, None);
    }

    #[test]
    fn test_parsed_args_empty() {
        let parsed = ParsedArgs::from_args(&[]);
        assert_eq!(parsed.command, None);
        assert_eq!(parsed.subcommand, None);
        assert_eq!(parsed.repo, None);
    }

    #[test]
    fn test_parsed_args_api_command() {
        let parsed = ParsedArgs::from_args(&args("api /repos/owner/repo/pulls"));
        assert_eq!(parsed.command.as_deref(), Some("api"));
        assert_eq!(
            parsed.subcommand.as_deref(),
            Some("/repos/owner/repo/pulls")
        );
        assert_eq!(parsed.repo, None);
    }

    #[test]
    fn test_parsed_args_api_with_repo_flag() {
        let parsed = ParsedArgs::from_args(&args("api -R myowner/myrepo /repos/owner/repo/pulls"));
        assert_eq!(parsed.command.as_deref(), Some("api"));
        assert_eq!(parsed.repo.as_deref(), Some("myowner/myrepo"));
    }

    #[test]
    fn test_parsed_args_repo_after_command() {
        let parsed = ParsedArgs::from_args(&args("pr list -R owner/repo"));
        assert_eq!(parsed.command.as_deref(), Some("pr"));
        assert_eq!(parsed.subcommand.as_deref(), Some("list"));
        assert_eq!(parsed.repo.as_deref(), Some("owner/repo"));
    }

    // ========================================================================
    // Tests for classify_gh_op()
    // ========================================================================

    /// Helper to create GhAnalysis with a given op_type for testing.
    fn analysis_with_op(op_type: OpType) -> GhAnalysis {
        GhAnalysis {
            repo: Some("owner/repo".into()),
            op_type,
            description: "test".into(),
        }
    }

    #[test]
    fn test_classify_gh_op_read_commands() {
        // Read operations should return GhOpType::Read
        let read_analysis = analysis_with_op(OpType::Read);

        assert_eq!(
            classify_gh_op(&args("pr list"), &read_analysis),
            GhOpType::Read
        );
        assert_eq!(
            classify_gh_op(&args("pr view 123"), &read_analysis),
            GhOpType::Read
        );
        assert_eq!(
            classify_gh_op(&args("issue list"), &read_analysis),
            GhOpType::Read
        );
        assert_eq!(
            classify_gh_op(&args("issue view 456"), &read_analysis),
            GhOpType::Read
        );
        assert_eq!(
            classify_gh_op(&args("pr diff"), &read_analysis),
            GhOpType::Read
        );
        assert_eq!(
            classify_gh_op(&args("pr checks"), &read_analysis),
            GhOpType::Read
        );
        assert_eq!(
            classify_gh_op(&args("status"), &read_analysis),
            GhOpType::Read
        );
    }

    #[test]
    fn test_classify_gh_op_create_draft() {
        let write_analysis = analysis_with_op(OpType::Write);

        // pr create --draft should be CreateDraft
        assert_eq!(
            classify_gh_op(&args("pr create --draft"), &write_analysis),
            GhOpType::CreateDraft
        );
        // With short flag
        assert_eq!(
            classify_gh_op(&args("pr create -d"), &write_analysis),
            GhOpType::CreateDraft
        );
        // Draft flag with other options
        assert_eq!(
            classify_gh_op(
                &args("pr create --draft --title foo --body bar"),
                &write_analysis
            ),
            GhOpType::CreateDraft
        );
        // Draft flag before other args
        assert_eq!(
            classify_gh_op(&args("pr create -d -R owner/repo"), &write_analysis),
            GhOpType::CreateDraft
        );
    }

    #[test]
    fn test_classify_gh_op_write_resource() {
        let write_analysis = analysis_with_op(OpType::Write);

        // pr comment and pr edit should be WriteResource
        assert_eq!(
            classify_gh_op(&args("pr comment 123"), &write_analysis),
            GhOpType::WriteResource
        );
        assert_eq!(
            classify_gh_op(&args("pr edit 456"), &write_analysis),
            GhOpType::WriteResource
        );
        // issue comment and issue edit should be WriteResource
        assert_eq!(
            classify_gh_op(&args("issue comment 789"), &write_analysis),
            GhOpType::WriteResource
        );
        assert_eq!(
            classify_gh_op(&args("issue edit 321"), &write_analysis),
            GhOpType::WriteResource
        );
    }

    #[test]
    fn test_classify_gh_op_write() {
        let write_analysis = analysis_with_op(OpType::Write);

        // pr create without --draft is a full Write
        assert_eq!(
            classify_gh_op(&args("pr create"), &write_analysis),
            GhOpType::Write
        );
        assert_eq!(
            classify_gh_op(&args("pr create --title foo"), &write_analysis),
            GhOpType::Write
        );
        // pr merge, close, etc. are full Write
        assert_eq!(
            classify_gh_op(&args("pr merge 123"), &write_analysis),
            GhOpType::Write
        );
        assert_eq!(
            classify_gh_op(&args("pr close 456"), &write_analysis),
            GhOpType::Write
        );
        assert_eq!(
            classify_gh_op(&args("issue close 789"), &write_analysis),
            GhOpType::Write
        );
        assert_eq!(
            classify_gh_op(&args("issue create"), &write_analysis),
            GhOpType::Write
        );
        // repo create
        assert_eq!(
            classify_gh_op(&args("repo create myrepo"), &write_analysis),
            GhOpType::Write
        );
    }

    // ========================================================================
    // Tests for parse_gh_cmd()
    // ========================================================================

    #[test]
    fn test_parse_gh_cmd_basic() {
        assert_eq!(
            parse_gh_cmd(&args("pr list")),
            (Some("pr".into()), Some("list".into()))
        );
        assert_eq!(
            parse_gh_cmd(&args("issue view 123")),
            (Some("issue".into()), Some("view".into()))
        );
        assert_eq!(
            parse_gh_cmd(&args("repo create myrepo")),
            (Some("repo".into()), Some("create".into()))
        );
    }

    #[test]
    fn test_parse_gh_cmd_single_command() {
        assert_eq!(parse_gh_cmd(&args("status")), (Some("status".into()), None));
        assert_eq!(parse_gh_cmd(&args("browse")), (Some("browse".into()), None));
    }

    #[test]
    fn test_parse_gh_cmd_with_flags_interspersed() {
        // -R flag before command
        assert_eq!(
            parse_gh_cmd(&args("-R owner/repo pr list")),
            (Some("pr".into()), Some("list".into()))
        );
        // --repo flag before command
        assert_eq!(
            parse_gh_cmd(&args("--repo owner/repo issue view")),
            (Some("issue".into()), Some("view".into()))
        );
        // Flags after subcommand shouldn't affect parsing
        assert_eq!(
            parse_gh_cmd(&args("pr list --state open")),
            (Some("pr".into()), Some("list".into()))
        );
        // -H hostname flag
        assert_eq!(
            parse_gh_cmd(&args("-H github.example.com pr list")),
            (Some("pr".into()), Some("list".into()))
        );
        // Mixed flags
        assert_eq!(
            parse_gh_cmd(&args("-R owner/repo -H example.com pr view 123")),
            (Some("pr".into()), Some("view".into()))
        );
    }

    #[test]
    fn test_parse_gh_cmd_empty_args() {
        assert_eq!(parse_gh_cmd(&[]), (None, None));
    }

    #[test]
    fn test_parse_gh_cmd_only_flags() {
        // Only flags, no command
        assert_eq!(parse_gh_cmd(&args("-R owner/repo")), (None, None));
        assert_eq!(parse_gh_cmd(&args("--repo owner/repo")), (None, None));
        assert_eq!(
            parse_gh_cmd(&args("-R owner/repo --hostname example.com")),
            (None, None)
        );
    }

    // ========================================================================
    // Tests for has_draft_flag()
    // ========================================================================

    #[test]
    fn test_has_draft_flag_long_form() {
        assert!(has_draft_flag(&args("pr create --draft")));
        assert!(has_draft_flag(&args("pr create --draft --title foo")));
        assert!(has_draft_flag(&args("--draft pr create")));
    }

    #[test]
    fn test_has_draft_flag_short_form() {
        assert!(has_draft_flag(&args("pr create -d")));
        assert!(has_draft_flag(&args("-d pr create --title foo")));
    }

    #[test]
    fn test_has_draft_flag_not_present() {
        assert!(!has_draft_flag(&args("pr create")));
        assert!(!has_draft_flag(&args("pr create --title foo --body bar")));
        assert!(!has_draft_flag(&args("pr list")));
        assert!(!has_draft_flag(&[]));
    }

    #[test]
    fn test_has_draft_flag_similar_but_not_draft() {
        // Flags that contain "draft" but aren't the draft flag
        assert!(!has_draft_flag(&args("pr create --no-draft")));
        assert!(!has_draft_flag(&args("pr create --drafts")));
    }

    // ========================================================================
    // Tests for extract_gh_resource_ref()
    // ========================================================================

    #[test]
    fn test_extract_gh_resource_ref_pr_view() {
        assert_eq!(
            extract_gh_resource_ref(&args("pr view 123"), "owner/repo"),
            Some("owner/repo#123".into())
        );
    }

    #[test]
    fn test_extract_gh_resource_ref_pr_comment() {
        assert_eq!(
            extract_gh_resource_ref(&args("pr comment 456"), "owner/repo"),
            Some("owner/repo#456".into())
        );
    }

    #[test]
    fn test_extract_gh_resource_ref_pr_edit() {
        assert_eq!(
            extract_gh_resource_ref(&args("pr edit 789"), "owner/repo"),
            Some("owner/repo#789".into())
        );
    }

    #[test]
    fn test_extract_gh_resource_ref_pr_close_merge_ready() {
        assert_eq!(
            extract_gh_resource_ref(&args("pr close 100"), "owner/repo"),
            Some("owner/repo#100".into())
        );
        assert_eq!(
            extract_gh_resource_ref(&args("pr merge 101"), "owner/repo"),
            Some("owner/repo#101".into())
        );
        assert_eq!(
            extract_gh_resource_ref(&args("pr ready 102"), "owner/repo"),
            Some("owner/repo#102".into())
        );
    }

    #[test]
    fn test_extract_gh_resource_ref_issue_operations() {
        assert_eq!(
            extract_gh_resource_ref(&args("issue view 200"), "owner/repo"),
            Some("owner/repo#200".into())
        );
        assert_eq!(
            extract_gh_resource_ref(&args("issue comment 201"), "owner/repo"),
            Some("owner/repo#201".into())
        );
        assert_eq!(
            extract_gh_resource_ref(&args("issue edit 202"), "owner/repo"),
            Some("owner/repo#202".into())
        );
        assert_eq!(
            extract_gh_resource_ref(&args("issue close 203"), "owner/repo"),
            Some("owner/repo#203".into())
        );
    }

    #[test]
    fn test_extract_gh_resource_ref_no_resource() {
        // Commands that don't have resource numbers
        assert_eq!(
            extract_gh_resource_ref(&args("pr list"), "owner/repo"),
            None
        );
        assert_eq!(
            extract_gh_resource_ref(&args("pr create"), "owner/repo"),
            None
        );
        assert_eq!(
            extract_gh_resource_ref(&args("issue list"), "owner/repo"),
            None
        );
        assert_eq!(
            extract_gh_resource_ref(&args("issue create"), "owner/repo"),
            None
        );
        assert_eq!(
            extract_gh_resource_ref(&args("repo view"), "owner/repo"),
            None
        );
    }

    #[test]
    fn test_extract_gh_resource_ref_with_flags() {
        assert_eq!(
            extract_gh_resource_ref(&args("pr view -R owner/repo 123"), "owner/repo"),
            Some("owner/repo#123".into())
        );
    }

    // ========================================================================
    // Tests for extract_resource_number()
    // ========================================================================

    #[test]
    fn test_extract_resource_number_positional() {
        assert_eq!(
            extract_resource_number(&args("pr view 123")),
            Some("123".into())
        );
        assert_eq!(
            extract_resource_number(&args("issue comment 456")),
            Some("456".into())
        );
        assert_eq!(
            extract_resource_number(&args("pr merge 789")),
            Some("789".into())
        );
    }

    #[test]
    fn test_extract_resource_number_url_pull() {
        assert_eq!(
            extract_resource_number(&args("pr view https://github.com/owner/repo/pull/789")),
            Some("789".into())
        );
        assert_eq!(
            extract_resource_number(&args("pr comment https://github.com/myorg/myrepo/pull/42")),
            Some("42".into())
        );
    }

    #[test]
    fn test_extract_resource_number_url_issues() {
        assert_eq!(
            extract_resource_number(&args("issue view https://github.com/owner/repo/issues/321")),
            Some("321".into())
        );
        assert_eq!(
            extract_resource_number(&args(
                "issue comment https://github.com/org/project/issues/999"
            )),
            Some("999".into())
        );
    }

    #[test]
    fn test_extract_resource_number_no_number() {
        assert_eq!(extract_resource_number(&args("pr list")), None);
        assert_eq!(extract_resource_number(&args("pr create")), None);
        assert_eq!(extract_resource_number(&args("issue list")), None);
        assert_eq!(extract_resource_number(&args("status")), None);
        assert_eq!(extract_resource_number(&[]), None);
    }

    #[test]
    fn test_extract_resource_number_with_flags() {
        // Should skip -R and its value
        assert_eq!(
            extract_resource_number(&args("pr view -R owner/repo 123")),
            Some("123".into())
        );
        // Should skip -b/--body and its value
        assert_eq!(
            extract_resource_number(&args("pr comment 456 -b comment body")),
            Some("456".into())
        );
        // Should skip --title and its value
        assert_eq!(
            extract_resource_number(&args("issue edit 789 --title newtitle")),
            Some("789".into())
        );
        // Multiple flags
        assert_eq!(
            extract_resource_number(&args("pr comment -R owner/repo 321 --body text")),
            Some("321".into())
        );
    }

    #[test]
    fn test_extract_resource_number_skips_non_number_args() {
        // Args that aren't numbers should be skipped
        // (the function looks for numeric positional args after cmd/subcmd)
        // Note: This behavior depends on implementation - URLs and numbers are handled
        assert_eq!(extract_resource_number(&args("pr view notanumber")), None);
    }

    // ========================================================================
    // Tests for parse_api() - clap-based parsing
    // ========================================================================

    #[test]
    fn test_parse_api_rest_endpoint() {
        let result = parse_api(&args("api repos/owner/repo/pulls")).unwrap();
        assert_eq!(result.args.endpoint, "repos/owner/repo/pulls");
        assert_eq!(result.args.jq, None);
        assert_eq!(result.repo, Some("owner/repo".into()));
        assert!(result.description.contains("repos/owner/repo/pulls"));
    }

    #[test]
    fn test_parse_api_rest_with_leading_slash() {
        let result = parse_api(&args("api /repos/owner/repo/issues")).unwrap();
        assert_eq!(result.args.endpoint, "/repos/owner/repo/issues");
        assert_eq!(result.repo, Some("owner/repo".into()));
    }

    #[test]
    fn test_parse_api_with_jq() {
        let result = parse_api(&args("api repos/owner/repo/pulls --jq .[].title")).unwrap();
        assert_eq!(result.args.endpoint, "repos/owner/repo/pulls");
        assert_eq!(result.args.jq, Some(".[].title".into()));
        assert_eq!(result.repo, Some("owner/repo".into()));
    }

    #[test]
    fn test_parse_api_with_jq_short() {
        let result = parse_api(&args("api repos/owner/repo/pulls -q .name")).unwrap();
        assert_eq!(result.args.endpoint, "repos/owner/repo/pulls");
        assert_eq!(result.args.jq, Some(".name".into()));
    }

    #[test]
    fn test_parse_api_graphql_without_query_rejected() {
        // GraphQL without a query field should be rejected
        let err = parse_api(&args("api graphql")).unwrap_err();
        assert!(err.to_string().contains("query"));
    }

    #[test]
    fn test_parse_api_graphql_query() {
        // GraphQL with a read-only query should succeed
        // Note: -f value contains spaces, so construct args manually
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "-f".to_string(),
            "query={ viewer { login } }".to_string(),
        ];
        let result = parse_api(&args).unwrap();
        assert!(result.is_graphql);
        assert_eq!(result.op_type, OpType::Read);
        assert_eq!(result.repo, None); // GraphQL spans repos
        assert!(result.description.contains("query"));
    }

    #[test]
    fn test_parse_api_graphql_mutation_rejected() {
        // GraphQL mutations are rejected for security reasons
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "-f".to_string(),
            "query=mutation { createIssue(input: {}) { id } }".to_string(),
        ];
        let err = parse_api(&args).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mutations are not supported"),
            "Expected mutation rejection error, got: {}",
            msg
        );
    }

    #[test]
    fn test_parse_api_graphql_invalid_query_rejected() {
        // Invalid GraphQL is rejected (classified as mutation/write, which is rejected)
        let args = vec![
            "api".to_string(),
            "graphql".to_string(),
            "-f".to_string(),
            "query=not valid graphql".to_string(),
        ];
        let err = parse_api(&args).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mutations are not supported"),
            "Expected mutation rejection error for invalid query, got: {}",
            msg
        );
    }

    #[test]
    fn test_parse_api_unknown_option_rejected() {
        // Unknown options should be rejected by clap
        let err = parse_api(&args("api -X POST repos/owner/repo/pulls")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Unknown") || msg.contains("unexpected"));
    }

    #[test]
    fn test_parse_api_method_flag_rejected() {
        let result = parse_api(&args("api --method POST repos/owner/repo/pulls"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_api_non_repo_endpoint() {
        // Endpoints like /user or /orgs don't have a repo
        let result = parse_api(&args("api user")).unwrap();
        assert_eq!(result.repo, None);
    }

    #[test]
    fn test_parse_api_no_endpoint() {
        let err = parse_api(&args("api")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("endpoint") || msg.contains("required"));
    }

    // ========================================================================
    // Tests for build_api_args()
    // ========================================================================

    #[test]
    fn test_build_api_args_simple() {
        let api = parse_api(&args("api repos/owner/repo/pulls")).unwrap();
        assert_equal(
            build_api_args(&api),
            ["api", "--method=GET", "repos/owner/repo/pulls"],
        );
    }

    #[test]
    fn test_build_api_args_with_jq() {
        let api = parse_api(&args("api repos/owner/repo/pulls --jq .[].title")).unwrap();
        assert_equal(
            build_api_args(&api),
            [
                "api",
                "--method=GET",
                "repos/owner/repo/pulls",
                "--jq",
                ".[].title",
            ],
        );
    }

    #[test]
    fn test_build_api_args_with_fields() {
        // Note: GraphQL requires a query field, so we test with a valid graphql request
        // that has the query field. We construct the args manually since parse_api
        // validates graphql queries.
        let api = GhApi {
            args: GhApiArgs {
                endpoint: "graphql".into(),
                jq: None,
                fields: vec![
                    ("owner".into(), "cgwalters".into()),
                    ("query".into(), "{ viewer { login } }".into()),
                ],
            },
            repo: None,
            op_type: OpType::Read,
            is_graphql: true,
            description: "test".into(),
        };
        assert_equal(
            build_api_args(&api),
            [
                "api",
                "--method=POST",
                "graphql",
                "-f",
                "owner=cgwalters",
                "-f",
                "query={ viewer { login } }",
            ],
        );
    }

    #[test]
    fn test_graphql_query_helper() {
        let args = GhApiArgs {
            endpoint: "graphql".into(),
            jq: None,
            fields: vec![
                ("owner".into(), "cgwalters".into()),
                ("query".into(), "{ viewer { login } }".into()),
            ],
        };
        assert_eq!(args.graphql_query(), Some("{ viewer { login } }"));

        let args_no_query = GhApiArgs {
            endpoint: "graphql".into(),
            jq: None,
            fields: vec![("owner".into(), "cgwalters".into())],
        };
        assert_eq!(args_no_query.graphql_query(), None);
    }

    // ========================================================================
    // Tests for pending review functionality
    // ========================================================================

    #[test]
    fn test_review_marker_token() {
        assert!(review_has_marker(
            "<!-- service-gator-review -->\n\nThis is a review"
        ));
        assert!(review_has_marker(
            "Some text <!-- service-gator-review --> more text"
        ));
        assert!(!review_has_marker("This is a review without marker"));
        assert!(!review_has_marker("<!-- other-marker -->"));
    }

    #[test]
    fn test_validate_review_marker_success() {
        let review = serde_json::json!({
            "body": "<!-- service-gator-review -->\n\nReview content",
            "state": "PENDING"
        });
        assert!(validate_review_marker(&review).is_ok());
    }

    #[test]
    fn test_validate_review_marker_failure() {
        let review = serde_json::json!({
            "body": "Human review without marker",
            "state": "PENDING"
        });
        assert!(validate_review_marker(&review).is_err());
    }

    #[test]
    fn test_validate_review_pending_success() {
        let review = serde_json::json!({
            "body": "<!-- service-gator-review -->",
            "state": "PENDING"
        });
        assert!(validate_review_pending(&review).is_ok());
    }

    #[test]
    fn test_validate_review_pending_failure() {
        for state in ["APPROVED", "CHANGES_REQUESTED", "COMMENTED", "DISMISSED"] {
            let review = serde_json::json!({
                "body": "<!-- service-gator-review -->",
                "state": state
            });
            assert!(
                validate_review_pending(&review).is_err(),
                "Should reject state: {}",
                state
            );
        }
    }

    #[test]
    fn test_parse_pending_review_request_list() {
        let req =
            parse_pending_review_request("repos/owner/repo/pulls/42/reviews", "GET", None).unwrap();
        assert_eq!(req.repo, "owner/repo");
        assert_eq!(req.pull_number.get(), 42);
        assert_eq!(req.review_id, None);
        assert_eq!(req.op, PendingReviewOp::List);
    }

    #[test]
    fn test_parse_pending_review_request_get() {
        let req =
            parse_pending_review_request("repos/owner/repo/pulls/42/reviews/123", "GET", None)
                .unwrap();
        assert_eq!(req.repo, "owner/repo");
        assert_eq!(req.pull_number.get(), 42);
        assert_eq!(req.review_id, Some(123));
        assert_eq!(req.op, PendingReviewOp::Get);
    }

    #[test]
    fn test_parse_pending_review_request_create() {
        let body = serde_json::json!({
            "body": "Review body",
            "comments": []
        });
        let req =
            parse_pending_review_request("repos/owner/repo/pulls/42/reviews", "POST", Some(body))
                .unwrap();
        assert_eq!(req.op, PendingReviewOp::Create);
        // Marker should be added
        let body_json = req.body.unwrap();
        let body_str = body_json["body"].as_str().unwrap();
        assert!(body_str.contains(REVIEW_MARKER_TOKEN));
    }

    #[test]
    fn test_parse_pending_review_request_create_strips_event() {
        let body = serde_json::json!({
            "body": "Review body",
            "event": "APPROVE",
            "comments": []
        });
        let req =
            parse_pending_review_request("repos/owner/repo/pulls/42/reviews", "POST", Some(body))
                .unwrap();
        // Event should be stripped
        assert!(req.body.as_ref().unwrap().get("event").is_none());
    }

    #[test]
    fn test_parse_pending_review_request_update() {
        let body = serde_json::json!({"body": "Updated body"});
        let req = parse_pending_review_request(
            "repos/owner/repo/pulls/42/reviews/123",
            "PUT",
            Some(body),
        )
        .unwrap();
        assert_eq!(req.op, PendingReviewOp::Update);
        assert_eq!(req.review_id, Some(123));
    }

    #[test]
    fn test_parse_pending_review_request_delete() {
        let req =
            parse_pending_review_request("repos/owner/repo/pulls/42/reviews/123", "DELETE", None)
                .unwrap();
        assert_eq!(req.op, PendingReviewOp::Delete);
        assert_eq!(req.review_id, Some(123));
    }

    #[test]
    fn test_parse_pending_review_request_rejects_events() {
        let result = parse_pending_review_request(
            "repos/owner/repo/pulls/42/reviews/123/events",
            "POST",
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("submit"));
    }

    #[test]
    fn test_parse_pending_review_request_rejects_dismissals() {
        let result = parse_pending_review_request(
            "repos/owner/repo/pulls/42/reviews/123/dismissals",
            "PUT",
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("dismiss"));
    }

    #[test]
    fn test_parse_pending_review_request_rejects_comments() {
        let result = parse_pending_review_request(
            "repos/owner/repo/pulls/42/reviews/123/comments",
            "GET",
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_pending_review_request_invalid_methods() {
        // POST to specific review
        assert!(parse_pending_review_request(
            "repos/owner/repo/pulls/42/reviews/123",
            "POST",
            None
        )
        .is_err());

        // PUT without review_id
        assert!(
            parse_pending_review_request("repos/owner/repo/pulls/42/reviews", "PUT", None).is_err()
        );

        // DELETE without review_id
        assert!(
            parse_pending_review_request("repos/owner/repo/pulls/42/reviews", "DELETE", None)
                .is_err()
        );
    }

    #[test]
    fn test_pending_review_request_build_args() {
        let req = PendingReviewRequest {
            repo: "owner/repo".into(),
            pull_number: 42.try_into().unwrap(),
            review_id: None,
            op: PendingReviewOp::Create,
            body: Some(serde_json::json!({"body": "test"})),
        };
        let args = req.build_args();
        assert!(args.contains(&"--method=POST".to_string()));
        assert!(args.contains(&"repos/owner/repo/pulls/42/reviews".to_string()));
    }

    #[test]
    fn test_pending_review_request_build_args_with_id() {
        let req = PendingReviewRequest {
            repo: "owner/repo".into(),
            pull_number: 42.try_into().unwrap(),
            review_id: Some(123),
            op: PendingReviewOp::Delete,
            body: None,
        };
        let args = req.build_args();
        assert!(args.contains(&"--method=DELETE".to_string()));
        assert!(args.contains(&"repos/owner/repo/pulls/42/reviews/123".to_string()));
    }
}
