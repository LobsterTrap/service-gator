//! GitLab CLI (`glab`) operation analysis for service-gator.
//!
//! This module provides:
//! - Extraction of target project from `glab` command arguments
//! - Classification of operations as read vs write based on HTTP method
//! - Handling of `glab api` with clap-based argument parsing
//! - Command parsing utilities shared between CLI and MCP server
//!
//! ## Security Model
//!
//! We use clap to explicitly define allowed options for the `api` command:
//! - `--method` / `-X`: HTTP method (GET, POST, PUT, PATCH, DELETE)
//! - `--jq` / `-q`: Filter output using a jq expression
//!
//! Operation type (read vs write) is determined by HTTP method:
//! - GET/HEAD = read
//! - POST/PUT/PATCH/DELETE = write
//!
//! The caller must check permissions based on `GlApi::op_type` before
//! executing write operations.
//!
//! **Blocked dangerous options:**
//! - `--input`: Can read arbitrary files from filesystem
//! - `-F` / `--field @file`: Can read files via `@` prefix
//! - `--hostname`: Could exfiltrate tokens to malicious server
//! - GraphQL endpoints are rejected (mutations could be hidden)

use clap::Parser;
use eyre::{bail, Result};

use crate::scope::{GlOpType, OpType};

/// Parsed and validated `glab api` arguments.
///
/// We use clap to explicitly define allowed options and reject everything else.
/// This is more secure than trying to filter arbitrary arguments.
#[derive(Parser, Debug, Clone)]
#[command(name = "api", no_binary_name = true)]
#[command(disable_help_flag = true, disable_version_flag = true)]
pub struct GlApiArgs {
    /// The API endpoint path (e.g., projects/group%2Fproject/merge_requests)
    #[arg(required = true)]
    pub endpoint: String,

    /// HTTP method (GET, POST, PUT, PATCH, DELETE)
    #[arg(short = 'X', long = "method", default_value = "GET")]
    pub method: String,

    /// Filter output using a jq expression
    #[arg(short = 'q', long = "jq")]
    pub jq: Option<String>,
}

/// Result of analyzing a `glab` command.
#[derive(Debug, Clone, PartialEq)]
pub struct GlAnalysis {
    /// The target project (if determinable).
    pub project: Option<String>,
    /// Whether this is a read or write operation.
    pub op_type: OpType,
    /// Human-readable description of what was detected.
    pub description: String,
}

/// Parsed and validated `glab api` command.
#[derive(Debug, Clone)]
pub struct GlApi {
    /// The parsed arguments.
    pub args: GlApiArgs,
    /// The target project (if determinable from API path).
    pub project: Option<String>,
    /// Whether this is a read or write operation (based on HTTP method).
    pub op_type: OpType,
    /// Human-readable description.
    pub description: String,
}

/// Parse and validate a `glab api` command using clap.
///
/// We use clap to explicitly define allowed options and reject everything else.
/// This is more secure than trying to filter arbitrary arguments.
pub fn parse_api(args: &[String]) -> Result<GlApi> {
    // Find where "api" is in the args and get everything after it
    let api_args: Vec<&str> = match args.iter().position(|a| a == "api") {
        Some(pos) => args.iter().skip(pos + 1).map(|s| s.as_str()).collect(),
        None => args.iter().map(|s| s.as_str()).collect(),
    };

    // Parse using clap - this will reject any unknown options
    let parsed = match GlApiArgs::try_parse_from(api_args) {
        Ok(args) => args,
        Err(e) => {
            // Format the error nicely
            match e.kind() {
                clap::error::ErrorKind::UnknownArgument => {
                    bail!("Unknown option. Only --method/-X and --jq/-q are allowed.\n{e}");
                }
                clap::error::ErrorKind::MissingRequiredArgument => {
                    bail!("No API endpoint specified");
                }
                _ => bail!("{e}"),
            }
        }
    };

    // Check if this is a GraphQL request - not allowed since we can't safely
    // restrict it to read-only queries without parsing the query argument
    let endpoint = &parsed.endpoint;
    if endpoint == "graphql" || endpoint == "/graphql" {
        bail!("GraphQL is not supported (would require query arguments to do anything useful)");
    }

    // Extract project from API path
    let project = extract_project_from_api_path(endpoint);
    let op_type = classify_method(&parsed.method);
    let description = format!(
        "glab api {} {}",
        parsed.method.to_uppercase(),
        parsed.endpoint
    );

    Ok(GlApi {
        args: parsed,
        project,
        op_type,
        description,
    })
}

/// Build the final args for a validated `glab api` command.
/// Passes through the validated method and other options.
pub fn build_api_args(args: &GlApiArgs) -> Vec<String> {
    build_api_args_with_host(args, None)
}

/// Build the final args for a validated `glab api` command with optional hostname.
/// Passes through the validated method and other options.
pub fn build_api_args_with_host(args: &GlApiArgs, host: Option<&str>) -> Vec<String> {
    let mut result = vec!["api".to_string()];

    // Add hostname for self-hosted GitLab instances
    if let Some(h) = host {
        result.push(format!("--hostname={}", h));
    }

    result.push(format!("--method={}", args.method.to_uppercase()));
    result.push(args.endpoint.clone());

    // Pass through --jq if specified
    if let Some(jq) = &args.jq {
        result.push("--jq".to_string());
        result.push(jq.clone());
    }

    result
}

/// Extract project from a GitLab API path.
///
/// GitLab API paths use URL-encoded project paths like:
/// - `/projects/group%2Fproject/...`
/// - `projects/group%2Fsubgroup%2Fproject/...`
///
/// The `%2F` is the URL encoding of `/`.
pub fn extract_project_from_api_path(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');

    if let Some(rest) = path.strip_prefix("projects/") {
        // Find the next '/' which separates the encoded project path from the rest
        let project_encoded = if let Some(pos) = rest.find('/') {
            &rest[..pos]
        } else {
            rest
        };

        // URL decode the project path (%2F -> /, %2f -> /)
        let project = decode_project_path(project_encoded);
        return Some(project);
    }

    None
}

/// Simple URL decoding for GitLab project paths.
///
/// GitLab project paths typically only need `%2F` -> `/` decoding.
/// We also handle a few other common cases for robustness.
fn decode_project_path(encoded: &str) -> String {
    encoded
        .replace("%2F", "/")
        .replace("%2f", "/")
        .replace("%20", " ")
        .replace("%3A", ":")
        .replace("%3a", ":")
}

/// Classify HTTP method as read or write operation.
///
/// GET/HEAD are reads, everything else (POST, PUT, PATCH, DELETE) is a write.
fn classify_method(method: &str) -> OpType {
    match method.to_uppercase().as_str() {
        "GET" | "HEAD" => OpType::Read,
        _ => OpType::Write,
    }
}

/// Classify a glab command into the fine-grained operation type.
pub fn classify_gl_op(args: &[String], analysis: &GlAnalysis) -> GlOpType {
    match analysis.op_type {
        OpType::Read => GlOpType::Read,
        OpType::Write => {
            let (cmd, subcmd) = parse_gl_cmd(args);

            match (cmd.as_deref(), subcmd.as_deref()) {
                // Draft MR creation
                (Some("mr"), Some("create")) if has_draft_flag(args) => GlOpType::CreateDraft,
                // MR approval
                (Some("mr"), Some("approve")) => GlOpType::Approve,
                // Comments/edits on specific resources
                (Some("mr"), Some("note" | "comment" | "update"))
                | (Some("issue"), Some("note" | "comment" | "update")) => GlOpType::WriteResource,
                _ => GlOpType::Write,
            }
        }
    }
}

/// Parse command and subcommand from glab args.
pub fn parse_gl_cmd(args: &[String]) -> (Option<String>, Option<String>) {
    let mut cmd = None;
    let mut subcmd = None;
    let mut skip = false;

    for arg in args {
        if skip {
            skip = false;
            continue;
        }
        if arg.starts_with('-') {
            // Flags that take a value
            if arg == "-R" || arg == "--repo" || arg == "-g" || arg == "--group" {
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
/// Note: glab uses -d for --description, not --draft, so we only check --draft.
pub fn has_draft_flag(args: &[String]) -> bool {
    args.iter().any(|a| a == "--draft")
}

/// Classify a glab command/subcommand as read or write.
fn classify_command(command: Option<&str>, subcommand: Option<&str>) -> OpType {
    match (command, subcommand) {
        // Explicitly read-only operations
        (Some("mr"), Some("list" | "view" | "diff" | "approvers")) => OpType::Read,
        (Some("issue"), Some("list" | "view")) => OpType::Read,
        (Some("project" | "repo"), Some("list" | "view" | "clone")) => OpType::Read,
        (Some("release"), Some("list" | "view" | "download")) => OpType::Read,
        (Some("ci"), Some("list" | "view" | "status" | "trace" | "artifact")) => OpType::Read,
        (Some("pipeline"), Some("list" | "view" | "status")) => OpType::Read,
        (Some("job"), Some("list" | "view" | "trace" | "artifact")) => OpType::Read,
        (Some("variable"), Some("list" | "get")) => OpType::Read,
        (Some("label"), Some("list")) => OpType::Read,
        (Some("milestone"), Some("list" | "view")) => OpType::Read,
        (Some("snippet"), Some("list" | "view")) => OpType::Read,
        (Some("ssh-key"), Some("list")) => OpType::Read,
        (Some("auth"), Some("status")) => OpType::Read,
        (Some("config"), Some("get")) => OpType::Read,

        // Top-level read-only commands
        (Some("completion" | "help" | "version"), _) => OpType::Read,

        // Everything else is a write
        _ => OpType::Write,
    }
}

/// Analyze a `glab` command to determine target project and read/write classification.
pub fn analyze(args: &[String]) -> GlAnalysis {
    let parsed = ParsedArgs::from_args(args);

    // Handle `glab api` specially - use clap-based parsing
    if parsed.command.as_deref() == Some("api") {
        return analyze_api_command(args, parsed.repo);
    }

    // For other commands, classify based on command/subcommand
    let op_type = classify_command(parsed.command.as_deref(), parsed.subcommand.as_deref());

    let description = match (&parsed.command, &parsed.subcommand) {
        (Some(cmd), Some(sub)) => format!("glab {} {}", cmd, sub),
        (Some(cmd), None) => format!("glab {}", cmd),
        _ => "glab".to_string(),
    };

    GlAnalysis {
        project: parsed.repo,
        op_type,
        description,
    }
}

/// Analyze a `glab api` command.
///
/// Uses `parse_api` for proper clap-based parsing. If parsing fails,
/// falls back to a conservative "unknown write" classification.
fn analyze_api_command(args: &[String], fallback_project: Option<String>) -> GlAnalysis {
    match parse_api(args) {
        Ok(api) => GlAnalysis {
            project: api.project.or(fallback_project),
            op_type: api.op_type,
            description: api.description,
        },
        Err(_) => {
            // If we can't parse the api command, treat it as an unknown write
            // (conservative - requires write permission)
            GlAnalysis {
                project: fallback_project,
                op_type: OpType::Write,
                description: "glab api (unparseable)".to_string(),
            }
        }
    }
}

/// Parsed glab command arguments.
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

            // Handle repo flags (-R/--repo for glab)
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
                if arg == "-g" || arg == "--group" {
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

/// Extract MR/issue resource reference (group/project!number or group/project#number).
pub fn extract_gl_resource_ref(args: &[String], project: &str) -> Option<String> {
    let (cmd, subcmd) = parse_gl_cmd(args);

    match (cmd.as_deref(), subcmd.as_deref()) {
        (
            Some("mr"),
            Some(
                "note" | "comment" | "update" | "view" | "close" | "merge" | "reopen" | "approve"
                | "revoke",
            ),
        )
        | (Some("issue"), Some("note" | "comment" | "update" | "view" | "close" | "reopen")) => {
            if let Some(num) = extract_resource_number(args) {
                // MRs use ! separator, issues use #
                let separator = if cmd.as_deref() == Some("mr") {
                    "!"
                } else {
                    "#"
                };
                return Some(format!("{}{}{}", project, separator, num));
            }
        }
        _ => {}
    }

    None
}

/// Extract MR/issue number from args.
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
            // Flags that take a value
            if arg == "-R"
                || arg == "--repo"
                || arg == "-m"
                || arg == "--message"
                || arg == "-t"
                || arg == "--title"
                || arg == "-d"
                || arg == "--description"
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
        if arg.contains("/merge_requests/") || arg.contains("/-/issues/") {
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

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    // ========================================================================
    // Tests for extract_project_from_api_path()
    // ========================================================================

    #[test]
    fn test_extract_project_simple() {
        assert_eq!(
            extract_project_from_api_path("projects/group%2Fproject/merge_requests"),
            Some("group/project".into())
        );
    }

    #[test]
    fn test_extract_project_with_leading_slash() {
        assert_eq!(
            extract_project_from_api_path("/projects/group%2Fproject/issues"),
            Some("group/project".into())
        );
    }

    #[test]
    fn test_extract_project_subgroup() {
        assert_eq!(
            extract_project_from_api_path("projects/group%2Fsubgroup%2Fproject/merge_requests"),
            Some("group/subgroup/project".into())
        );
    }

    #[test]
    fn test_extract_project_no_rest() {
        assert_eq!(
            extract_project_from_api_path("projects/group%2Fproject"),
            Some("group/project".into())
        );
    }

    #[test]
    fn test_extract_project_non_project_endpoint() {
        assert_eq!(extract_project_from_api_path("/users"), None);
        assert_eq!(extract_project_from_api_path("/groups/mygroup"), None);
    }

    // ========================================================================
    // Tests for parse_api()
    // ========================================================================

    #[test]
    fn test_parse_api_rest_endpoint() {
        let result = parse_api(&args("api projects/group%2Fproject/merge_requests")).unwrap();
        assert_eq!(
            result.args.endpoint,
            "projects/group%2Fproject/merge_requests"
        );
        assert_eq!(result.args.jq, None);
        assert_eq!(result.project, Some("group/project".into()));
    }

    #[test]
    fn test_parse_api_with_jq() {
        let result = parse_api(&args(
            "api projects/group%2Fproject/merge_requests --jq .[].title",
        ))
        .unwrap();
        assert_eq!(result.args.jq, Some(".[].title".into()));
    }

    #[test]
    fn test_parse_api_graphql_rejected() {
        let err = parse_api(&args("api graphql")).unwrap_err();
        assert!(err.to_string().contains("GraphQL"));
    }

    #[test]
    fn test_parse_api_unknown_option_rejected() {
        // Test with an actually unknown option like --input
        let err = parse_api(&args(
            "api --input data.json projects/group%2Fproject/merge_requests",
        ))
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Unknown") || msg.contains("unexpected"));
    }

    #[test]
    fn test_parse_api_with_method() {
        let result =
            parse_api(&args("api -X POST projects/group%2Fproject/merge_requests")).unwrap();
        assert_eq!(result.args.method, "POST");
        assert_eq!(result.op_type, OpType::Write);
        assert!(result.description.contains("POST"));

        let result = parse_api(&args(
            "api --method GET projects/group%2Fproject/merge_requests",
        ))
        .unwrap();
        assert_eq!(result.args.method, "GET");
        assert_eq!(result.op_type, OpType::Read);
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
        let api_args = GlApiArgs {
            endpoint: "projects/group%2Fproject/merge_requests".into(),
            method: "GET".into(),
            jq: None,
        };
        let result = build_api_args(&api_args);
        assert_eq!(
            result,
            vec![
                "api",
                "--method=GET",
                "projects/group%2Fproject/merge_requests"
            ]
        );
    }

    #[test]
    fn test_build_api_args_post() {
        let api_args = GlApiArgs {
            endpoint: "projects/group%2Fproject/merge_requests".into(),
            method: "POST".into(),
            jq: None,
        };
        let result = build_api_args(&api_args);
        assert_eq!(
            result,
            vec![
                "api",
                "--method=POST",
                "projects/group%2Fproject/merge_requests"
            ]
        );
    }

    #[test]
    fn test_build_api_args_with_jq() {
        let api_args = GlApiArgs {
            endpoint: "projects/group%2Fproject/merge_requests".into(),
            method: "GET".into(),
            jq: Some(".[].title".into()),
        };
        let result = build_api_args(&api_args);
        assert_eq!(
            result,
            vec![
                "api",
                "--method=GET",
                "projects/group%2Fproject/merge_requests",
                "--jq",
                ".[].title"
            ]
        );
    }

    #[test]
    fn test_build_api_args_with_host() {
        let api_args = GlApiArgs {
            endpoint: "projects/group%2Fproject/merge_requests".into(),
            method: "GET".into(),
            jq: None,
        };
        let result = build_api_args_with_host(&api_args, Some("gitlab.example.com"));
        assert_eq!(
            result,
            vec![
                "api",
                "--hostname=gitlab.example.com",
                "--method=GET",
                "projects/group%2Fproject/merge_requests"
            ]
        );
    }

    #[test]
    fn test_build_api_args_with_host_none() {
        let api_args = GlApiArgs {
            endpoint: "projects/group%2Fproject/merge_requests".into(),
            method: "GET".into(),
            jq: Some(".[].iid".into()),
        };
        // None host should behave like build_api_args
        let result = build_api_args_with_host(&api_args, None);
        assert_eq!(
            result,
            vec![
                "api",
                "--method=GET",
                "projects/group%2Fproject/merge_requests",
                "--jq",
                ".[].iid"
            ]
        );
    }

    // ========================================================================
    // Tests for classify_command()
    // ========================================================================

    #[test]
    fn test_classify_read_commands() {
        assert_eq!(classify_command(Some("mr"), Some("list")), OpType::Read);
        assert_eq!(classify_command(Some("mr"), Some("view")), OpType::Read);
        assert_eq!(classify_command(Some("issue"), Some("list")), OpType::Read);
        assert_eq!(classify_command(Some("ci"), Some("status")), OpType::Read);
        assert_eq!(
            classify_command(Some("pipeline"), Some("list")),
            OpType::Read
        );
    }

    #[test]
    fn test_classify_write_commands() {
        assert_eq!(classify_command(Some("mr"), Some("create")), OpType::Write);
        assert_eq!(classify_command(Some("mr"), Some("merge")), OpType::Write);
        assert_eq!(classify_command(Some("mr"), Some("approve")), OpType::Write);
        assert_eq!(
            classify_command(Some("issue"), Some("create")),
            OpType::Write
        );
    }

    // ========================================================================
    // Tests for analyze()
    // ========================================================================

    #[test]
    fn test_analyze_mr_list() {
        let result = analyze(&args("mr list -R group/project"));
        assert_eq!(result.op_type, OpType::Read);
        assert_eq!(result.project, Some("group/project".into()));
    }

    #[test]
    fn test_analyze_mr_create() {
        let result = analyze(&args("mr create --draft -R group/project"));
        assert_eq!(result.op_type, OpType::Write);
        assert_eq!(result.project, Some("group/project".into()));
    }

    #[test]
    fn test_analyze_api_get() {
        let result = analyze(&args("api projects/group%2Fproject/merge_requests"));
        assert_eq!(result.op_type, OpType::Read);
        assert_eq!(result.project, Some("group/project".into()));
    }

    #[test]
    fn test_analyze_api_post() {
        let result = analyze(&args("api -X POST projects/group%2Fproject/merge_requests"));
        assert_eq!(result.op_type, OpType::Write);
        assert_eq!(result.project, Some("group/project".into()));
    }

    // ========================================================================
    // Tests for classify_gl_op()
    // ========================================================================

    fn analysis_with_op(op_type: OpType) -> GlAnalysis {
        GlAnalysis {
            project: Some("group/project".into()),
            op_type,
            description: "test".into(),
        }
    }

    #[test]
    fn test_classify_gl_op_read() {
        let read_analysis = analysis_with_op(OpType::Read);
        assert_eq!(
            classify_gl_op(&args("mr list"), &read_analysis),
            GlOpType::Read
        );
    }

    #[test]
    fn test_classify_gl_op_create_draft() {
        let write_analysis = analysis_with_op(OpType::Write);
        assert_eq!(
            classify_gl_op(&args("mr create --draft"), &write_analysis),
            GlOpType::CreateDraft
        );
        // Note: -d is --description in glab, not --draft, so this is a regular write
        assert_eq!(
            classify_gl_op(&args("mr create -d"), &write_analysis),
            GlOpType::Write
        );
    }

    #[test]
    fn test_classify_gl_op_approve() {
        let write_analysis = analysis_with_op(OpType::Write);
        assert_eq!(
            classify_gl_op(&args("mr approve 123"), &write_analysis),
            GlOpType::Approve
        );
    }

    #[test]
    fn test_classify_gl_op_write_resource() {
        let write_analysis = analysis_with_op(OpType::Write);
        assert_eq!(
            classify_gl_op(&args("mr note 123"), &write_analysis),
            GlOpType::WriteResource
        );
        assert_eq!(
            classify_gl_op(&args("mr comment 123"), &write_analysis),
            GlOpType::WriteResource
        );
        assert_eq!(
            classify_gl_op(&args("issue note 456"), &write_analysis),
            GlOpType::WriteResource
        );
    }

    #[test]
    fn test_classify_gl_op_write() {
        let write_analysis = analysis_with_op(OpType::Write);
        assert_eq!(
            classify_gl_op(&args("mr create"), &write_analysis),
            GlOpType::Write
        );
        assert_eq!(
            classify_gl_op(&args("mr merge 123"), &write_analysis),
            GlOpType::Write
        );
    }

    // ========================================================================
    // Tests for parse_gl_cmd()
    // ========================================================================

    #[test]
    fn test_parse_gl_cmd_basic() {
        assert_eq!(
            parse_gl_cmd(&args("mr list")),
            (Some("mr".into()), Some("list".into()))
        );
        assert_eq!(
            parse_gl_cmd(&args("issue view 123")),
            (Some("issue".into()), Some("view".into()))
        );
    }

    #[test]
    fn test_parse_gl_cmd_with_flags() {
        assert_eq!(
            parse_gl_cmd(&args("-R group/project mr list")),
            (Some("mr".into()), Some("list".into()))
        );
    }

    // ========================================================================
    // Tests for has_draft_flag()
    // ========================================================================

    #[test]
    fn test_has_draft_flag() {
        assert!(has_draft_flag(&args("mr create --draft")));
        // Note: -d is --description in glab, not --draft
        assert!(!has_draft_flag(&args("mr create -d")));
        assert!(!has_draft_flag(&args("mr create")));
    }

    // ========================================================================
    // Tests for extract_gl_resource_ref()
    // ========================================================================

    #[test]
    fn test_extract_gl_resource_ref_mr() {
        assert_eq!(
            extract_gl_resource_ref(&args("mr view 123"), "group/project"),
            Some("group/project!123".into())
        );
        assert_eq!(
            extract_gl_resource_ref(&args("mr note 456"), "group/project"),
            Some("group/project!456".into())
        );
    }

    #[test]
    fn test_extract_gl_resource_ref_issue() {
        assert_eq!(
            extract_gl_resource_ref(&args("issue view 789"), "group/project"),
            Some("group/project#789".into())
        );
        assert_eq!(
            extract_gl_resource_ref(&args("issue note 321"), "group/project"),
            Some("group/project#321".into())
        );
    }

    #[test]
    fn test_extract_gl_resource_ref_no_number() {
        assert_eq!(
            extract_gl_resource_ref(&args("mr list"), "group/project"),
            None
        );
        assert_eq!(
            extract_gl_resource_ref(&args("mr create"), "group/project"),
            None
        );
    }

    // ========================================================================
    // Tests for extract_resource_number()
    // ========================================================================

    #[test]
    fn test_extract_resource_number_positional() {
        assert_eq!(
            extract_resource_number(&args("mr view 123")),
            Some("123".into())
        );
        assert_eq!(
            extract_resource_number(&args("issue note 456")),
            Some("456".into())
        );
    }

    #[test]
    fn test_extract_resource_number_url() {
        assert_eq!(
            extract_resource_number(&args(
                "mr view https://gitlab.com/group/project/-/merge_requests/789"
            )),
            Some("789".into())
        );
        assert_eq!(
            extract_resource_number(&args(
                "issue view https://gitlab.com/group/project/-/issues/321"
            )),
            Some("321".into())
        );
    }

    #[test]
    fn test_extract_resource_number_none() {
        assert_eq!(extract_resource_number(&args("mr list")), None);
        assert_eq!(extract_resource_number(&args("mr create")), None);
    }
}
