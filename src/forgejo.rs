//! Forgejo/Gitea REST API operation analysis for service-gator.
//!
//! This module provides:
//! - Extraction of target repository from Forgejo API paths
//! - Classification of operations as read vs write based on HTTP method
//! - Handling of `/api/v1/...` endpoints with clap-based argument parsing
//! - Command parsing utilities
//!
//! Forgejo is a fork of Gitea, and both have identical REST APIs.
//! Key differences from GitHub:
//! - API base path: /api/v1/
//! - Uses /repos/{owner}/{repo}/pulls (similar to GitHub, but under /api/v1/)
//! - No GraphQL support
//! - Always self-hosted (host is REQUIRED)
//! - PR/issue resource separator is # (like GitHub issues)
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
//! The caller must check permissions based on `ForgejoApi::op_type` before
//! executing write operations.
//!
//! ## Note on `tea` CLI
//!
//! This module is designed to work with the `tea` CLI from Gitea/Forgejo.
//! However, as of 2026, `tea` does not have a raw `api` subcommand like
//! `gh api` or `glab api`. The implementation assumes such functionality
//! exists or will be added. If using a version of `tea` without `api`,
//! this tool will not work for Forgejo.

use clap::Parser;
use eyre::{bail, Result};

use crate::scope::{ForgejoOpType, OpType};

/// Parsed and validated Forgejo API arguments.
///
/// We use clap to explicitly define allowed options and reject everything else.
/// This is more secure than trying to filter arbitrary arguments.
#[derive(Parser, Debug, Clone)]
#[command(name = "api", no_binary_name = true)]
#[command(disable_help_flag = true, disable_version_flag = true)]
pub struct ForgejoApiArgs {
    /// The API endpoint path (e.g., /api/v1/repos/owner/repo/pulls)
    #[arg(required = true)]
    pub endpoint: String,

    /// HTTP method (GET, POST, PUT, PATCH, DELETE)
    #[arg(short = 'X', long = "method", default_value = "GET")]
    pub method: String,

    /// Filter output using a jq expression
    #[arg(short = 'q', long = "jq")]
    pub jq: Option<String>,
}

/// Result of analyzing a Forgejo command.
#[derive(Debug, Clone, PartialEq)]
pub struct ForgejoAnalysis {
    /// The target repository (if determinable).
    pub repo: Option<String>,
    /// Whether this is a read or write operation.
    pub op_type: OpType,
    /// Human-readable description of what was detected.
    pub description: String,
}

/// Parsed and validated Forgejo API command.
#[derive(Debug, Clone)]
pub struct ForgejoApi {
    /// The parsed arguments.
    pub args: ForgejoApiArgs,
    /// The target repository (if determinable from API path).
    pub repo: Option<String>,
    /// Whether this is a read or write operation (based on HTTP method).
    pub op_type: OpType,
    /// Human-readable description.
    pub description: String,
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

/// Parse and validate a Forgejo API command using clap.
///
/// We use clap to explicitly define allowed options and reject everything else.
/// This is more secure than trying to filter arbitrary arguments.
pub fn parse_api(args: &[String]) -> Result<ForgejoApi> {
    // Find where "api" is in the args and get everything after it
    let api_args: Vec<&str> = match args.iter().position(|a| a == "api") {
        Some(pos) => args.iter().skip(pos + 1).map(|s| s.as_str()).collect(),
        None => args.iter().map(|s| s.as_str()).collect(),
    };

    // Parse using clap - this will reject any unknown options
    let parsed = match ForgejoApiArgs::try_parse_from(api_args) {
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

    // Forgejo/Gitea doesn't have GraphQL, so no need to check for it

    // Extract repo from API path
    let repo = extract_repo_from_api_path(&parsed.endpoint);
    let op_type = classify_method(&parsed.method);
    let description = format!(
        "forgejo api {} {}",
        parsed.method.to_uppercase(),
        parsed.endpoint
    );

    Ok(ForgejoApi {
        args: parsed,
        repo,
        op_type,
        description,
    })
}

/// Build the final args for a validated Forgejo API command.
/// Passes through the validated method and other options.
pub fn build_api_args(args: &ForgejoApiArgs) -> Vec<String> {
    let mut result = vec![
        "api".to_string(),
        format!("--method={}", args.method.to_uppercase()),
        args.endpoint.clone(),
    ];

    // Pass through --jq if specified
    if let Some(jq) = &args.jq {
        result.push("--jq".to_string());
        result.push(jq.clone());
    }

    result
}

/// Extract repository from a Forgejo API path like `/api/v1/repos/owner/repo/...`.
///
/// Forgejo API paths follow the pattern:
/// - `/api/v1/repos/{owner}/{repo}/...`
/// - `api/v1/repos/{owner}/{repo}/...`
///
/// Also handles GitHub-compatible paths (without /api/v1 prefix) for flexibility:
/// - `/repos/{owner}/{repo}/...`
/// - `repos/{owner}/{repo}/...`
pub fn extract_repo_from_api_path(path: &str) -> Option<String> {
    let path = path.trim_start_matches('/');

    // Try Forgejo/Gitea style: api/v1/repos/...
    let repos_path = if let Some(rest) = path.strip_prefix("api/v1/repos/") {
        rest
    } else if let Some(rest) = path.strip_prefix("repos/") {
        // Also handle direct repos/ path for compatibility
        rest
    } else {
        return None;
    };

    // Extract owner/repo from the remaining path
    let parts: Vec<&str> = repos_path.splitn(3, '/').collect();
    if parts.len() >= 2 {
        return Some(format!("{}/{}", parts[0], parts[1]));
    }

    None
}

/// Classify a Forgejo command into the fine-grained operation type.
pub fn classify_forgejo_op(args: &[String], analysis: &ForgejoAnalysis) -> ForgejoOpType {
    match analysis.op_type {
        OpType::Read => ForgejoOpType::Read,
        // Comment and Create are JIRA-specific; treat as Write for Forgejo
        OpType::Write | OpType::Comment | OpType::Create => {
            let (cmd, subcmd) = parse_forgejo_cmd(args);

            match (cmd.as_deref(), subcmd.as_deref()) {
                // Draft PR creation (Forgejo uses "pulls" or "pr")
                (Some("pr" | "pulls"), Some("create")) if has_draft_flag(args) => {
                    ForgejoOpType::CreateDraft
                }
                // Comments/edits on specific resources
                (Some("pr" | "pulls"), Some("comment" | "update"))
                | (Some("issue" | "issues"), Some("comment" | "update")) => {
                    ForgejoOpType::WriteResource
                }
                _ => ForgejoOpType::Write,
            }
        }
    }
}

/// Parse command and subcommand from args.
pub fn parse_forgejo_cmd(args: &[String]) -> (Option<String>, Option<String>) {
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
            if arg == "-R" || arg == "--repo" || arg == "-o" || arg == "--output" {
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
/// Note: Like glab, tea may use -d for other options, so we only check --draft.
pub fn has_draft_flag(args: &[String]) -> bool {
    args.iter().any(|a| a == "--draft")
}

/// Classify a command/subcommand as read or write.
fn classify_command(command: Option<&str>, subcommand: Option<&str>) -> OpType {
    match (command, subcommand) {
        // Explicitly read-only operations
        (Some("pr" | "pulls"), Some("list" | "view" | "diff" | "files" | "commits")) => {
            OpType::Read
        }
        (Some("issue" | "issues"), Some("list" | "view" | "comments")) => OpType::Read,
        (Some("repo" | "repos"), Some("list" | "view" | "clone" | "search")) => OpType::Read,
        (Some("release" | "releases"), Some("list" | "view" | "download")) => OpType::Read,
        (Some("org" | "orgs"), Some("list" | "view")) => OpType::Read,
        (Some("user" | "users"), Some("list" | "view" | "search")) => OpType::Read,
        (Some("label" | "labels"), Some("list")) => OpType::Read,
        (Some("milestone" | "milestones"), Some("list" | "view")) => OpType::Read,
        (Some("branch" | "branches"), Some("list")) => OpType::Read,
        (Some("tag" | "tags"), Some("list")) => OpType::Read,
        (Some("comment" | "comments"), Some("list")) => OpType::Read,
        (Some("notification" | "notifications"), Some("list" | "view")) => OpType::Read,

        // Top-level read-only commands
        (Some("version" | "help" | "completion"), _) => OpType::Read,

        // Everything else is a write
        _ => OpType::Write,
    }
}

/// Analyze a Forgejo API command to determine target repo and read/write classification.
pub fn analyze(args: &[String]) -> ForgejoAnalysis {
    let parsed = ParsedArgs::from_args(args);

    // Handle `api` command specially - use clap-based parsing
    if parsed.command.as_deref() == Some("api") {
        return analyze_api_command(args, parsed.repo);
    }

    // For other commands, classify based on command/subcommand
    let op_type = classify_command(parsed.command.as_deref(), parsed.subcommand.as_deref());

    let description = match (&parsed.command, &parsed.subcommand) {
        (Some(cmd), Some(sub)) => format!("forgejo {} {}", cmd, sub),
        (Some(cmd), None) => format!("forgejo {}", cmd),
        _ => "forgejo".to_string(),
    };

    ForgejoAnalysis {
        repo: parsed.repo,
        op_type,
        description,
    }
}

/// Analyze a Forgejo API command.
///
/// Uses `parse_api` for proper clap-based parsing. If parsing fails,
/// falls back to a conservative "unknown write" classification.
fn analyze_api_command(args: &[String], fallback_repo: Option<String>) -> ForgejoAnalysis {
    match parse_api(args) {
        Ok(api) => ForgejoAnalysis {
            repo: api.repo.or(fallback_repo),
            op_type: api.op_type,
            description: api.description,
        },
        Err(_) => {
            // If we can't parse the api command, treat it as an unknown write
            // (conservative - requires write permission)
            ForgejoAnalysis {
                repo: fallback_repo,
                op_type: OpType::Write,
                description: "forgejo api (unparseable)".to_string(),
            }
        }
    }
}

/// Parsed Forgejo command arguments.
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

            // Handle repo flags (-R/--repo)
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
                if arg == "-o" || arg == "--output" || arg == "-H" || arg == "--host" {
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

/// Extract PR/issue resource reference (owner/repo#number).
pub fn extract_forgejo_resource_ref(args: &[String], repo: &str) -> Option<String> {
    let (cmd, subcmd) = parse_forgejo_cmd(args);

    match (cmd.as_deref(), subcmd.as_deref()) {
        (Some("pr" | "pulls"), Some("view" | "comment" | "update" | "close" | "merge"))
        | (Some("issue" | "issues"), Some("view" | "comment" | "update" | "close")) => {
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
                || arg == "-m"
                || arg == "--message"
                || arg == "-t"
                || arg == "--title"
                || arg == "-b"
                || arg == "--body"
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
        if arg.contains("/pulls/") || arg.contains("/issues/") {
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
    // Tests for extract_repo_from_api_path()
    // ========================================================================

    #[test]
    fn test_extract_repo_forgejo_style() {
        assert_eq!(
            extract_repo_from_api_path("/api/v1/repos/owner/repo/pulls"),
            Some("owner/repo".into())
        );
        assert_eq!(
            extract_repo_from_api_path("api/v1/repos/owner/repo/issues"),
            Some("owner/repo".into())
        );
    }

    #[test]
    fn test_extract_repo_github_style() {
        // Also supports GitHub-compatible paths
        assert_eq!(
            extract_repo_from_api_path("/repos/owner/repo/pulls"),
            Some("owner/repo".into())
        );
        assert_eq!(
            extract_repo_from_api_path("repos/owner/repo/issues"),
            Some("owner/repo".into())
        );
    }

    #[test]
    fn test_extract_repo_no_match() {
        assert_eq!(extract_repo_from_api_path("/api/v1/user"), None);
        assert_eq!(extract_repo_from_api_path("/api/v1/orgs/myorg"), None);
        assert_eq!(extract_repo_from_api_path("/user/repos"), None);
    }

    #[test]
    fn test_extract_repo_short_path() {
        assert_eq!(
            extract_repo_from_api_path("/api/v1/repos/owner/repo"),
            Some("owner/repo".into())
        );
    }

    // ========================================================================
    // Tests for parse_api()
    // ========================================================================

    #[test]
    fn test_parse_api_rest_endpoint() {
        let result = parse_api(&args("api /api/v1/repos/owner/repo/pulls")).unwrap();
        assert_eq!(result.args.endpoint, "/api/v1/repos/owner/repo/pulls");
        assert_eq!(result.args.jq, None);
        assert_eq!(result.repo, Some("owner/repo".into()));
    }

    #[test]
    fn test_parse_api_with_jq() {
        let result = parse_api(&args("api /api/v1/repos/owner/repo/pulls --jq .[].title")).unwrap();
        assert_eq!(result.args.jq, Some(".[].title".into()));
    }

    #[test]
    fn test_parse_api_with_method() {
        let result = parse_api(&args("api -X POST /api/v1/repos/owner/repo/pulls")).unwrap();
        assert_eq!(result.args.endpoint, "/api/v1/repos/owner/repo/pulls");
        assert_eq!(result.args.method, "POST");
        assert_eq!(result.op_type, OpType::Write);
    }

    #[test]
    fn test_parse_api_unknown_option_rejected() {
        let err =
            parse_api(&args("api --unknown-flag /api/v1/repos/owner/repo/pulls")).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unknown") || msg.contains("unexpected"),
            "Expected unknown/unexpected error, got: {msg}"
        );
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
    fn test_build_api_args_get() {
        let api_args = ForgejoApiArgs {
            endpoint: "/api/v1/repos/owner/repo/pulls".into(),
            method: "GET".into(),
            jq: None,
        };
        let result = build_api_args(&api_args);
        assert_eq!(
            result,
            vec!["api", "--method=GET", "/api/v1/repos/owner/repo/pulls"]
        );
    }

    #[test]
    fn test_build_api_args_post() {
        let api_args = ForgejoApiArgs {
            endpoint: "/api/v1/repos/owner/repo/pulls".into(),
            method: "POST".into(),
            jq: None,
        };
        let result = build_api_args(&api_args);
        assert_eq!(
            result,
            vec!["api", "--method=POST", "/api/v1/repos/owner/repo/pulls"]
        );
    }

    #[test]
    fn test_build_api_args_with_jq() {
        let api_args = ForgejoApiArgs {
            endpoint: "/api/v1/repos/owner/repo/pulls".into(),
            method: "GET".into(),
            jq: Some(".[].title".into()),
        };
        let result = build_api_args(&api_args);
        assert_eq!(
            result,
            vec![
                "api",
                "--method=GET",
                "/api/v1/repos/owner/repo/pulls",
                "--jq",
                ".[].title"
            ]
        );
    }

    // ========================================================================
    // Tests for classify_command()
    // ========================================================================

    #[test]
    fn test_classify_read_commands() {
        assert_eq!(classify_command(Some("pr"), Some("list")), OpType::Read);
        assert_eq!(classify_command(Some("pulls"), Some("view")), OpType::Read);
        assert_eq!(classify_command(Some("issue"), Some("list")), OpType::Read);
        assert_eq!(classify_command(Some("issues"), Some("view")), OpType::Read);
        assert_eq!(classify_command(Some("repo"), Some("list")), OpType::Read);
    }

    #[test]
    fn test_classify_write_commands() {
        assert_eq!(classify_command(Some("pr"), Some("create")), OpType::Write);
        assert_eq!(classify_command(Some("pr"), Some("merge")), OpType::Write);
        assert_eq!(
            classify_command(Some("issue"), Some("create")),
            OpType::Write
        );
    }

    // ========================================================================
    // Tests for analyze()
    // ========================================================================

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
        let result = analyze(&args("api /api/v1/repos/owner/repo/pulls"));
        assert_eq!(result.op_type, OpType::Read);
        assert_eq!(result.repo, Some("owner/repo".into()));
    }

    #[test]
    fn test_analyze_api_post() {
        let result = analyze(&args("api -X POST /api/v1/repos/owner/repo/pulls"));
        assert_eq!(result.op_type, OpType::Write);
        assert_eq!(result.repo, Some("owner/repo".into()));
    }

    // ========================================================================
    // Tests for classify_forgejo_op()
    // ========================================================================

    fn analysis_with_op(op_type: OpType) -> ForgejoAnalysis {
        ForgejoAnalysis {
            repo: Some("owner/repo".into()),
            op_type,
            description: "test".into(),
        }
    }

    #[test]
    fn test_classify_forgejo_op_read() {
        let read_analysis = analysis_with_op(OpType::Read);
        assert_eq!(
            classify_forgejo_op(&args("pr list"), &read_analysis),
            ForgejoOpType::Read
        );
    }

    #[test]
    fn test_classify_forgejo_op_create_draft() {
        let write_analysis = analysis_with_op(OpType::Write);
        assert_eq!(
            classify_forgejo_op(&args("pr create --draft"), &write_analysis),
            ForgejoOpType::CreateDraft
        );
        // Note: -d may be used for other options, so this is a regular write without --draft
        assert_eq!(
            classify_forgejo_op(&args("pulls create -d"), &write_analysis),
            ForgejoOpType::Write
        );
    }

    #[test]
    fn test_classify_forgejo_op_write_resource() {
        let write_analysis = analysis_with_op(OpType::Write);
        assert_eq!(
            classify_forgejo_op(&args("pr comment 123"), &write_analysis),
            ForgejoOpType::WriteResource
        );
        assert_eq!(
            classify_forgejo_op(&args("issue comment 456"), &write_analysis),
            ForgejoOpType::WriteResource
        );
    }

    #[test]
    fn test_classify_forgejo_op_write() {
        let write_analysis = analysis_with_op(OpType::Write);
        assert_eq!(
            classify_forgejo_op(&args("pr create"), &write_analysis),
            ForgejoOpType::Write
        );
        assert_eq!(
            classify_forgejo_op(&args("pr merge 123"), &write_analysis),
            ForgejoOpType::Write
        );
    }

    // ========================================================================
    // Tests for parse_forgejo_cmd()
    // ========================================================================

    #[test]
    fn test_parse_forgejo_cmd_basic() {
        assert_eq!(
            parse_forgejo_cmd(&args("pr list")),
            (Some("pr".into()), Some("list".into()))
        );
        assert_eq!(
            parse_forgejo_cmd(&args("issue view 123")),
            (Some("issue".into()), Some("view".into()))
        );
    }

    #[test]
    fn test_parse_forgejo_cmd_with_flags() {
        assert_eq!(
            parse_forgejo_cmd(&args("-R owner/repo pr list")),
            (Some("pr".into()), Some("list".into()))
        );
    }

    // ========================================================================
    // Tests for has_draft_flag()
    // ========================================================================

    #[test]
    fn test_has_draft_flag() {
        assert!(has_draft_flag(&args("pr create --draft")));
        // Note: -d may be used for other options (like --description), so we only check --draft
        assert!(!has_draft_flag(&args("pr create -d")));
        assert!(!has_draft_flag(&args("pr create")));
    }

    // ========================================================================
    // Tests for extract_forgejo_resource_ref()
    // ========================================================================

    #[test]
    fn test_extract_forgejo_resource_ref_pr() {
        assert_eq!(
            extract_forgejo_resource_ref(&args("pr view 123"), "owner/repo"),
            Some("owner/repo#123".into())
        );
        assert_eq!(
            extract_forgejo_resource_ref(&args("pulls comment 456"), "owner/repo"),
            Some("owner/repo#456".into())
        );
    }

    #[test]
    fn test_extract_forgejo_resource_ref_issue() {
        assert_eq!(
            extract_forgejo_resource_ref(&args("issue view 789"), "owner/repo"),
            Some("owner/repo#789".into())
        );
        assert_eq!(
            extract_forgejo_resource_ref(&args("issues comment 321"), "owner/repo"),
            Some("owner/repo#321".into())
        );
    }

    #[test]
    fn test_extract_forgejo_resource_ref_no_number() {
        assert_eq!(
            extract_forgejo_resource_ref(&args("pr list"), "owner/repo"),
            None
        );
        assert_eq!(
            extract_forgejo_resource_ref(&args("pr create"), "owner/repo"),
            None
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
    }

    #[test]
    fn test_extract_resource_number_url() {
        assert_eq!(
            extract_resource_number(&args("pr view https://codeberg.org/owner/repo/pulls/789")),
            Some("789".into())
        );
        assert_eq!(
            extract_resource_number(&args(
                "issue view https://codeberg.org/owner/repo/issues/321"
            )),
            Some("321".into())
        );
    }

    #[test]
    fn test_extract_resource_number_none() {
        assert_eq!(extract_resource_number(&args("pr list")), None);
        assert_eq!(extract_resource_number(&args("pr create")), None);
    }
}
