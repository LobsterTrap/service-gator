//! JIRA CLI operation analysis for service-gator.
//!
//! This module provides:
//! - Explicit allowlist of jirust-cli commands and options
//! - Clap-based argument parsing to reject unknown options
//! - Extraction of target project/issue from JIRA CLI arguments
//! - Classification of operations as read vs write
//!
//! ## Security Model
//!
//! We use an explicit allowlist approach:
//! - Only specific commands/subcommands are allowed
//! - Only specific options for each command are allowed
//! - Unknown commands, subcommands, or options are rejected
//!
//! This prevents the AI agent from using undocumented or dangerous options.
//!
//! Targets `jirust-cli` as the CLI tool.

use clap::{Parser, Subcommand};
use eyre::{bail, Result};

use crate::jira_types::{JiraIssueKey, JiraProjectKey};
use crate::scope::OpType;

// ============================================================================
// Top-level CLI structure
// ============================================================================

/// Validated jirust-cli command.
///
/// We use clap to explicitly define allowed commands and options.
/// This is more secure than trying to filter arbitrary arguments.
#[derive(Parser, Debug, Clone)]
#[command(name = "jirust-cli", no_binary_name = true)]
#[command(disable_help_flag = true, disable_version_flag = true)]
pub struct JiraCommand {
    #[command(subcommand)]
    pub command: JiraSubcommand,
}

/// Allowed jirust-cli subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum JiraSubcommand {
    /// Issue operations
    Issue(IssueCommand),
    /// Project operations
    Project(ProjectCommand),
    /// Version operations
    Version(VersionCommand),
    /// Search with JQL
    Search(SearchCommand),
}

// ============================================================================
// Issue commands
// ============================================================================

#[derive(Parser, Debug, Clone)]
pub struct IssueCommand {
    #[command(subcommand)]
    pub action: IssueAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IssueAction {
    /// List issues in a project
    List(IssueListArgs),
    /// View/show issue details
    #[command(alias = "view")]
    Show(IssueShowArgs),
    /// Create a new issue
    Create(IssueCreateArgs),
    /// Transition an issue
    Transition(IssueTransitionArgs),
    /// Assign an issue
    Assign(IssueAssignArgs),
    /// Add a comment to an issue
    #[command(name = "comment")]
    Comment(IssueCommentArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct IssueListArgs {
    /// Project key
    #[arg(short = 'p', long = "project")]
    pub project: JiraProjectKey,

    /// Output format (json, table)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct IssueShowArgs {
    /// Issue key (e.g., PROJ-123)
    #[arg(short = 'i', long = "issue")]
    pub issue: Option<JiraIssueKey>,

    /// Issue key as positional argument
    #[arg()]
    pub issue_key: Option<JiraIssueKey>,

    /// Output format (json, table)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

impl IssueShowArgs {
    /// Get the effective issue key from either flag or positional
    pub fn effective_issue(&self) -> Option<&JiraIssueKey> {
        self.issue.as_ref().or(self.issue_key.as_ref())
    }
}

#[derive(Parser, Debug, Clone)]
pub struct IssueCreateArgs {
    /// Project key
    #[arg(short = 'p', long = "project")]
    pub project: JiraProjectKey,

    /// Issue summary/title
    #[arg(short = 's', long = "summary")]
    pub summary: String,

    /// Issue description
    #[arg(short = 'd', long = "description")]
    pub description: Option<String>,

    /// Issue type
    #[arg(short = 't', long = "type")]
    pub issue_type: Option<String>,

    /// Output format (json, table)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct IssueTransitionArgs {
    /// Issue key (e.g., PROJ-123)
    #[arg(short = 'i', long = "issue")]
    pub issue: Option<JiraIssueKey>,

    /// Issue key as positional argument
    #[arg()]
    pub issue_key: Option<JiraIssueKey>,

    /// Transition name or ID
    #[arg(short = 't', long = "transition")]
    pub transition: Option<String>,

    /// Output format (json, table)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

impl IssueTransitionArgs {
    pub fn effective_issue(&self) -> Option<&JiraIssueKey> {
        self.issue.as_ref().or(self.issue_key.as_ref())
    }
}

#[derive(Parser, Debug, Clone)]
pub struct IssueAssignArgs {
    /// Issue key (e.g., PROJ-123)
    #[arg(short = 'i', long = "issue")]
    pub issue: Option<JiraIssueKey>,

    /// Issue key as positional argument
    #[arg()]
    pub issue_key: Option<JiraIssueKey>,

    /// Assignee username or account ID
    #[arg(short = 'a', long = "assignee")]
    pub assignee: Option<String>,

    /// Output format (json, table)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

impl IssueAssignArgs {
    pub fn effective_issue(&self) -> Option<&JiraIssueKey> {
        self.issue.as_ref().or(self.issue_key.as_ref())
    }
}

/// Arguments for `issue comment`.
#[derive(Debug, Clone, Parser)]
pub struct IssueCommentArgs {
    /// Issue key (e.g. PROJ-123)
    #[arg(short = 'i', long = "issue")]
    pub issue: String,

    /// Comment body text
    #[arg(short = 'b', long = "body")]
    pub body: String,
}

// ============================================================================
// Project commands
// ============================================================================

#[derive(Parser, Debug, Clone)]
pub struct ProjectCommand {
    #[command(subcommand)]
    pub action: ProjectAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ProjectAction {
    /// List all accessible projects
    List(ProjectListArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct ProjectListArgs {
    /// Output format (json, table)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

// ============================================================================
// Version commands
// ============================================================================

#[derive(Parser, Debug, Clone)]
pub struct VersionCommand {
    #[command(subcommand)]
    pub action: VersionAction,
}

#[derive(Subcommand, Debug, Clone)]
pub enum VersionAction {
    /// List versions in a project
    List(VersionListArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct VersionListArgs {
    /// Project key
    #[arg(short = 'p', long = "project")]
    pub project: JiraProjectKey,

    /// Output format (json, table)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

// ============================================================================
// Search command
// ============================================================================

#[derive(Parser, Debug, Clone)]
pub struct SearchCommand {
    /// Project key(s) to search within (required for authorization).
    /// The search will be scoped to these projects.
    /// Can be specified multiple times: -p PROJ1 -p PROJ2
    #[arg(short = 'p', long = "project", required = true)]
    pub projects: Vec<JiraProjectKey>,

    /// JQL query string (applied within the specified projects)
    #[arg(short = 'q', long = "jql")]
    pub jql: String,

    /// Output format (json, table)
    #[arg(short = 'o', long = "output")]
    pub output: Option<String>,
}

impl SearchCommand {
    /// Build the effective JQL by prepending a project filter.
    ///
    /// This ensures the search is scoped to the explicitly authorized projects,
    /// regardless of what the user-provided JQL contains.
    pub fn effective_jql(&self) -> String {
        crate::services::jira::build_scoped_jql(&self.projects, &self.jql)
    }
}

// ============================================================================
// Parsing and validation
// ============================================================================

/// Result of analyzing a JIRA CLI command.
#[derive(Debug, Clone, PartialEq)]
pub struct JiraAnalysis {
    /// The target project key (if determinable).
    pub project: Option<String>,
    /// The target issue key (if determinable), e.g., "PROJ-123".
    pub issue: Option<String>,
    /// Whether this is a read or write operation.
    pub op_type: OpType,
    /// Human-readable description of what was detected.
    pub description: String,
}

impl JiraAnalysis {
    /// Get the project from either explicit project or extracted from issue key.
    pub fn effective_project(&self) -> Option<&str> {
        self.project
            .as_deref()
            .or_else(|| self.issue.as_ref().and_then(|i| i.split('-').next()))
    }
}

/// Parsed and validated JIRA command.
#[derive(Debug, Clone)]
pub struct ValidatedJiraCommand {
    /// The parsed command.
    pub command: JiraCommand,
    /// The target project (if determinable).
    pub project: Option<String>,
    /// The target issue (if determinable).
    pub issue: Option<String>,
    /// Human-readable description.
    pub description: String,
}

/// Parse and validate a jirust-cli command using clap.
///
/// We use clap to explicitly define allowed commands and options.
/// Unknown commands or options are rejected.
pub fn parse_command(args: &[String]) -> Result<ValidatedJiraCommand> {
    // Parse using clap - this will reject any unknown options or commands
    let parsed = match JiraCommand::try_parse_from(args) {
        Ok(cmd) => cmd,
        Err(e) => match e.kind() {
            clap::error::ErrorKind::UnknownArgument => {
                bail!(
                    "Unknown option. Only explicitly allowed options are permitted.\n{}",
                    e
                );
            }
            clap::error::ErrorKind::InvalidSubcommand => {
                bail!(
                    "Unknown command. Allowed: issue, project, version, search.\n{}",
                    e
                );
            }
            clap::error::ErrorKind::MissingRequiredArgument => {
                bail!("Missing required argument.\n{}", e);
            }
            _ => bail!("{}", e),
        },
    };

    // Extract project and issue from the parsed command
    let (project, issue, description) = extract_metadata(&parsed);

    Ok(ValidatedJiraCommand {
        command: parsed,
        project,
        issue,
        description,
    })
}

/// Extract project, issue, and description from parsed command.
fn extract_metadata(cmd: &JiraCommand) -> (Option<String>, Option<String>, String) {
    match &cmd.command {
        JiraSubcommand::Issue(issue_cmd) => match &issue_cmd.action {
            IssueAction::List(args) => (
                Some(args.project.as_str().to_string()),
                None,
                format!("jira issue list -p {}", args.project),
            ),
            IssueAction::Show(args) => {
                let issue = args.effective_issue();
                let project = issue.map(|i| i.project().to_string());
                let issue_str = issue.map(|i| i.to_string());
                let desc = match issue {
                    Some(i) => format!("jira issue show {}", i),
                    None => "jira issue show".to_string(),
                };
                (project, issue_str, desc)
            }
            IssueAction::Create(args) => (
                Some(args.project.as_str().to_string()),
                None,
                format!("jira issue create -p {}", args.project),
            ),
            IssueAction::Transition(args) => {
                let issue = args.effective_issue();
                let project = issue.map(|i| i.project().to_string());
                let issue_str = issue.map(|i| i.to_string());
                let desc = match issue {
                    Some(i) => format!("jira issue transition {}", i),
                    None => "jira issue transition".to_string(),
                };
                (project, issue_str, desc)
            }
            IssueAction::Assign(args) => {
                let issue = args.effective_issue();
                let project = issue.map(|i| i.project().to_string());
                let issue_str = issue.map(|i| i.to_string());
                let desc = match issue {
                    Some(i) => format!("jira issue assign {}", i),
                    None => "jira issue assign".to_string(),
                };
                (project, issue_str, desc)
            }
            IssueAction::Comment(args) => {
                let project = project_from_issue(&args.issue);
                (
                    project,
                    Some(args.issue.clone()),
                    "jira issue comment".to_string(),
                )
            }
        },
        JiraSubcommand::Project(project_cmd) => match &project_cmd.action {
            ProjectAction::List(_) => (None, None, "jira project list".to_string()),
        },
        JiraSubcommand::Version(version_cmd) => match &version_cmd.action {
            VersionAction::List(args) => (
                Some(args.project.as_str().to_string()),
                None,
                format!("jira version list -p {}", args.project),
            ),
        },
        JiraSubcommand::Search(search_cmd) => {
            // Use the first project as the primary project for permission checking.
            // All projects are validated separately by the caller.
            let primary_project = search_cmd.projects.first().map(|p| p.as_str().to_string());
            let projects_str = search_cmd
                .projects
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            (
                primary_project,
                None,
                format!("jira search -p {} --jql '{}'", projects_str, search_cmd.jql),
            )
        }
    }
}

/// Build the final args for a validated JIRA command.
/// This reconstructs the command line for jirust-cli.
pub fn build_command_args(cmd: &ValidatedJiraCommand) -> Vec<String> {
    match &cmd.command.command {
        JiraSubcommand::Issue(issue_cmd) => match &issue_cmd.action {
            IssueAction::List(args) => {
                let mut result = vec![
                    "issue".to_string(),
                    "list".to_string(),
                    "-p".to_string(),
                    args.project.to_string(),
                ];
                if let Some(ref output) = args.output {
                    result.push("-o".to_string());
                    result.push(output.clone());
                }
                result
            }
            IssueAction::Show(args) => {
                let mut result = vec!["issue".to_string(), "show".to_string()];
                if let Some(issue) = args.effective_issue() {
                    result.push("-i".to_string());
                    result.push(issue.to_string());
                }
                if let Some(ref output) = args.output {
                    result.push("-o".to_string());
                    result.push(output.clone());
                }
                result
            }
            IssueAction::Create(args) => {
                let mut result = vec![
                    "issue".to_string(),
                    "create".to_string(),
                    "-p".to_string(),
                    args.project.to_string(),
                    "-s".to_string(),
                    args.summary.clone(),
                ];
                if let Some(ref desc) = args.description {
                    result.push("-d".to_string());
                    result.push(desc.clone());
                }
                if let Some(ref issue_type) = args.issue_type {
                    result.push("-t".to_string());
                    result.push(issue_type.clone());
                }
                if let Some(ref output) = args.output {
                    result.push("-o".to_string());
                    result.push(output.clone());
                }
                result
            }
            IssueAction::Transition(args) => {
                let mut result = vec!["issue".to_string(), "transition".to_string()];
                if let Some(issue) = args.effective_issue() {
                    result.push("-i".to_string());
                    result.push(issue.to_string());
                }
                if let Some(ref transition) = args.transition {
                    result.push("-t".to_string());
                    result.push(transition.clone());
                }
                if let Some(ref output) = args.output {
                    result.push("-o".to_string());
                    result.push(output.clone());
                }
                result
            }
            IssueAction::Assign(args) => {
                let mut result = vec!["issue".to_string(), "assign".to_string()];
                if let Some(issue) = args.effective_issue() {
                    result.push("-i".to_string());
                    result.push(issue.to_string());
                }
                if let Some(ref assignee) = args.assignee {
                    result.push("-a".to_string());
                    result.push(assignee.clone());
                }
                if let Some(ref output) = args.output {
                    result.push("-o".to_string());
                    result.push(output.clone());
                }
                result
            }
            IssueAction::Comment(args) => {
                vec![
                    "issue".to_string(),
                    "comment".to_string(),
                    "-i".to_string(),
                    args.issue.clone(),
                    "-b".to_string(),
                    args.body.clone(),
                ]
            }
        },
        JiraSubcommand::Project(project_cmd) => match &project_cmd.action {
            ProjectAction::List(args) => {
                let mut result = vec!["project".to_string(), "list".to_string()];
                if let Some(ref output) = args.output {
                    result.push("-o".to_string());
                    result.push(output.clone());
                }
                result
            }
        },
        JiraSubcommand::Version(version_cmd) => match &version_cmd.action {
            VersionAction::List(args) => {
                let mut result = vec![
                    "version".to_string(),
                    "list".to_string(),
                    "-p".to_string(),
                    args.project.to_string(),
                ];
                if let Some(ref output) = args.output {
                    result.push("-o".to_string());
                    result.push(output.clone());
                }
                result
            }
        },
        JiraSubcommand::Search(search_cmd) => {
            let mut result = vec!["search".to_string()];
            for project in &search_cmd.projects {
                result.push("-p".to_string());
                result.push(project.to_string());
            }
            result.push("-q".to_string());
            result.push(search_cmd.jql.clone());
            if let Some(ref output) = search_cmd.output {
                result.push("-o".to_string());
                result.push(output.clone());
            }
            result
        }
    }
}

/// Classify a validated command as read or write.
pub fn classify_command(cmd: &ValidatedJiraCommand) -> OpType {
    match &cmd.command.command {
        JiraSubcommand::Issue(issue_cmd) => match &issue_cmd.action {
            IssueAction::List(_) | IssueAction::Show(_) => OpType::Read,
            IssueAction::Comment(_) => OpType::Comment,
            IssueAction::Create(_) => OpType::Create,
            IssueAction::Transition(_) | IssueAction::Assign(_) => OpType::Write,
        },
        JiraSubcommand::Project(project_cmd) => match &project_cmd.action {
            ProjectAction::List(_) => OpType::Read,
        },
        JiraSubcommand::Version(version_cmd) => match &version_cmd.action {
            VersionAction::List(_) => OpType::Read,
        },
        JiraSubcommand::Search(_) => OpType::Read,
    }
}

/// Extract project key from an issue key like "PROJ-123".
/// Uses JiraIssueKey for validation when possible, falls back to simple parsing.
fn project_from_issue(issue: &str) -> Option<String> {
    // Try using the proper type first
    if let Ok(key) = issue.parse::<JiraIssueKey>() {
        return Some(key.project().to_string());
    }
    // Fallback for legacy compatibility with looser validation
    let parts: Vec<&str> = issue.splitn(2, '-').collect();
    if parts.len() == 2 && !parts[0].is_empty() && parts[1].chars().all(|c| c.is_ascii_digit()) {
        Some(parts[0].to_uppercase())
    } else {
        None
    }
}

// ============================================================================
// Legacy analyze function for backward compatibility
// ============================================================================

/// Analyze a `jirust-cli` command to determine target and read/write classification.
///
/// This function provides backward compatibility with the old API.
/// For new code, prefer using `parse_command()` which validates the command.
pub fn analyze(args: &[String]) -> JiraAnalysis {
    match parse_command(args) {
        Ok(ref validated) => {
            let op_type = classify_command(validated);
            JiraAnalysis {
                project: validated.project.clone(),
                issue: validated.issue.clone(),
                op_type,
                description: validated.description.clone(),
            }
        }
        Err(_) => {
            // For backward compatibility, try manual parsing for analysis
            // but mark as Write (safer default for unknown commands)
            let parsed = LegacyParsedArgs::from_args(args);
            let description = match (&parsed.command, &parsed.subcommand) {
                (Some(cmd), Some(sub)) => format!("jira {} {} (unvalidated)", cmd, sub),
                (Some(cmd), None) => format!("jira {} (unvalidated)", cmd),
                _ => "jira (unvalidated)".to_string(),
            };
            JiraAnalysis {
                project: parsed.project,
                issue: parsed.issue,
                op_type: OpType::Write, // Default to write for safety
                description,
            }
        }
    }
}

/// Legacy parsed arguments for backward compatibility.
struct LegacyParsedArgs {
    command: Option<String>,
    subcommand: Option<String>,
    project: Option<String>,
    issue: Option<String>,
}

impl LegacyParsedArgs {
    fn from_args(args: &[String]) -> Self {
        let mut command = None;
        let mut subcommand = None;
        let mut project = None;
        let mut issue = None;
        let mut skip_next = false;

        for (i, arg) in args.iter().enumerate() {
            if skip_next {
                skip_next = false;
                continue;
            }

            // Handle project flag
            if arg == "-p" || arg == "--project" {
                if let Some(p) = args.get(i + 1) {
                    project = Some(p.clone());
                    skip_next = true;
                }
                continue;
            }
            if let Some(p) = arg.strip_prefix("--project=") {
                project = Some(p.to_string());
                continue;
            }

            // Handle issue flag
            if arg == "-i" || arg == "--issue" {
                if let Some(iss) = args.get(i + 1) {
                    issue = Some(iss.clone());
                    skip_next = true;
                }
                continue;
            }
            if let Some(iss) = arg.strip_prefix("--issue=") {
                issue = Some(iss.to_string());
                continue;
            }

            // Skip other flags
            if arg.starts_with('-') {
                // Known flags that take values
                if matches!(
                    arg.as_str(),
                    "-o" | "--output"
                        | "-q"
                        | "--jql"
                        | "-s"
                        | "--summary"
                        | "-d"
                        | "--description"
                        | "-t"
                        | "--type"
                        | "--transition"
                        | "-a"
                        | "--assignee"
                        | "-b"
                        | "--body"
                ) {
                    skip_next = true;
                }
                continue;
            }

            // First positional is command, second is subcommand
            if command.is_none() {
                command = Some(arg.clone());
            } else if subcommand.is_none() {
                // Could be subcommand or issue key
                if project_from_issue(arg).is_some() && issue.is_none() {
                    issue = Some(arg.clone());
                } else {
                    subcommand = Some(arg.clone());
                }
            } else if issue.is_none() && project_from_issue(arg).is_some() {
                issue = Some(arg.clone());
            }
        }

        // If we have an issue but no project, extract project from issue
        if project.is_none() {
            if let Some(ref iss) = issue {
                project = project_from_issue(iss);
            }
        }

        Self {
            command,
            subcommand,
            project,
            issue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    // ========================================================================
    // Tests for parse_command() - the new clap-based parser
    // ========================================================================

    #[test]
    fn test_parse_issue_list() {
        let result = parse_command(&args("issue list -p MYPROJ")).unwrap();
        assert_eq!(result.project.as_deref(), Some("MYPROJ"));
        assert!(result.description.contains("issue list"));

        let built = build_command_args(&result);
        assert_eq!(built, vec!["issue", "list", "-p", "MYPROJ"]);
    }

    #[test]
    fn test_parse_issue_show() {
        let result = parse_command(&args("issue show -i PROJ-123")).unwrap();
        assert_eq!(result.issue.as_deref(), Some("PROJ-123"));
        assert_eq!(result.project.as_deref(), Some("PROJ"));

        let built = build_command_args(&result);
        assert_eq!(built, vec!["issue", "show", "-i", "PROJ-123"]);
    }

    #[test]
    fn test_parse_issue_show_positional() {
        let result = parse_command(&args("issue show PROJ-456")).unwrap();
        assert_eq!(result.issue.as_deref(), Some("PROJ-456"));
        assert_eq!(result.project.as_deref(), Some("PROJ"));
    }

    #[test]
    fn test_parse_issue_create() {
        let args = vec![
            "issue".to_string(),
            "create".to_string(),
            "-p".to_string(),
            "MYPROJ".to_string(),
            "-s".to_string(),
            "Bug title".to_string(),
            "-t".to_string(),
            "Bug".to_string(),
        ];
        let result = parse_command(&args).unwrap();
        assert_eq!(result.project.as_deref(), Some("MYPROJ"));

        let op_type = classify_command(&result);
        assert_eq!(op_type, OpType::Create);
    }

    #[test]
    fn test_parse_project_list() {
        let result = parse_command(&args("project list")).unwrap();
        assert_eq!(result.project, None);
        assert!(result.description.contains("project list"));

        let op_type = classify_command(&result);
        assert_eq!(op_type, OpType::Read);
    }

    #[test]
    fn test_parse_search() {
        let result = parse_command(&args("search -p MYPROJ -q status=Open")).unwrap();
        assert!(result.description.contains("search"));
        assert_eq!(result.project.as_deref(), Some("MYPROJ"));

        let op_type = classify_command(&result);
        assert_eq!(op_type, OpType::Read);
    }

    #[test]
    fn test_parse_search_multiple_projects() {
        let result = parse_command(&args("search -p PROJ1 -p PROJ2 -q status=Open")).unwrap();
        assert!(result.description.contains("PROJ1"));
        assert!(result.description.contains("PROJ2"));
        assert_eq!(result.project.as_deref(), Some("PROJ1"));
    }

    #[test]
    fn test_parse_search_requires_project() {
        // Search without -p should fail
        let err = parse_command(&args("search -q status=Open"));
        assert!(err.is_err(), "Search without project should fail");
    }

    #[test]
    fn test_parse_version_list() {
        let result = parse_command(&args("version list -p PROJ")).unwrap();
        assert_eq!(result.project.as_deref(), Some("PROJ"));

        let op_type = classify_command(&result);
        assert_eq!(op_type, OpType::Read);
    }

    #[test]
    fn test_parse_unknown_command_rejected() {
        let err = parse_command(&args("unknown subcommand")).unwrap_err();
        assert!(err.to_string().contains("Unknown") || err.to_string().contains("invalid"));
    }

    #[test]
    fn test_parse_unknown_option_rejected() {
        // The --dangerous-option should be rejected
        let err = parse_command(&args("issue list -p PROJ --dangerous-option")).unwrap_err();
        assert!(err.to_string().contains("Unknown") || err.to_string().contains("unexpected"));
    }

    #[test]
    fn test_parse_config_command_rejected() {
        // config command is intentionally not in the allowlist
        let err = parse_command(&args("config setup")).unwrap_err();
        assert!(err.to_string().contains("Unknown") || err.to_string().contains("invalid"));
    }

    // ========================================================================
    // Tests for classify_command()
    // ========================================================================

    #[test]
    fn test_classify_read_commands() {
        let cmd = parse_command(&args("issue list -p PROJ")).unwrap();
        assert_eq!(classify_command(&cmd), OpType::Read);

        let cmd = parse_command(&args("issue show -i PROJ-1")).unwrap();
        assert_eq!(classify_command(&cmd), OpType::Read);

        let cmd = parse_command(&args("project list")).unwrap();
        assert_eq!(classify_command(&cmd), OpType::Read);

        let cmd = parse_command(&args("search -p PROJ -q status=Open")).unwrap();
        assert_eq!(classify_command(&cmd), OpType::Read);
    }

    #[test]
    fn test_classify_write_commands() {
        let cmd = parse_command(&args("issue create -p PROJ -s Title")).unwrap();
        assert_eq!(classify_command(&cmd), OpType::Create);

        let cmd = parse_command(&args("issue transition -i PROJ-1 -t Done")).unwrap();
        assert_eq!(classify_command(&cmd), OpType::Write);

        let cmd = parse_command(&args("issue assign -i PROJ-1 -a user")).unwrap();
        assert_eq!(classify_command(&cmd), OpType::Write);
    }

    #[test]
    fn test_classify_comment_command() {
        let cmd = parse_command(&args("issue comment -i PROJ-1 -b hello")).unwrap();
        assert_eq!(classify_command(&cmd), OpType::Comment);
        assert_eq!(cmd.issue.as_deref(), Some("PROJ-1"));
        assert_eq!(cmd.project.as_deref(), Some("PROJ"));
    }

    #[test]
    fn test_parse_issue_comment() {
        let a = vec![
            "issue".to_string(),
            "comment".to_string(),
            "-i".to_string(),
            "PROJ-42".to_string(),
            "-b".to_string(),
            "This is my comment".to_string(),
        ];
        let result = parse_command(&a).unwrap();
        assert_eq!(result.issue.as_deref(), Some("PROJ-42"));
        assert_eq!(result.project.as_deref(), Some("PROJ"));
        assert!(result.description.contains("comment"));

        let op_type = classify_command(&result);
        assert_eq!(op_type, OpType::Comment);
    }

    // ========================================================================
    // Tests for project_from_issue()
    // ========================================================================

    #[test]
    fn test_project_from_issue() {
        assert_eq!(project_from_issue("PROJ-123"), Some("PROJ".into()));
        assert_eq!(project_from_issue("ABC-1"), Some("ABC".into()));
        assert_eq!(project_from_issue("proj-456"), Some("PROJ".into()));
        assert_eq!(project_from_issue("invalid"), None);
        assert_eq!(project_from_issue("PROJ-abc"), None);
        assert_eq!(project_from_issue("-123"), None);
    }

    // ========================================================================
    // Tests for backward compatibility analyze()
    // ========================================================================

    #[test]
    fn test_analyze_valid_command() {
        let result = analyze(&args("issue list -p MYPROJ"));
        assert_eq!(result.op_type, OpType::Read);
        assert_eq!(result.project.as_deref(), Some("MYPROJ"));
    }

    #[test]
    fn test_analyze_invalid_command_defaults_to_write() {
        // Unknown command should default to Write for safety
        let result = analyze(&args("dangerous command"));
        assert_eq!(result.op_type, OpType::Write);
        assert!(result.description.contains("unvalidated"));
    }

    // ========================================================================
    // Tests for build_command_args()
    // ========================================================================

    #[test]
    fn test_build_args_with_output() {
        let cmd = parse_command(&args("issue list -p PROJ -o json")).unwrap();
        let built = build_command_args(&cmd);
        assert!(built.contains(&"-o".to_string()));
        assert!(built.contains(&"json".to_string()));
    }

    #[test]
    fn test_build_search_args() {
        let cmd = parse_command(&args("search -p PROJ -q status=Open -o table")).unwrap();
        let built = build_command_args(&cmd);
        assert_eq!(built[0], "search");
        assert_eq!(built[1], "-p");
        assert_eq!(built[2], "PROJ");
        assert_eq!(built[3], "-q");
        assert_eq!(built[4], "status=Open");
        assert_eq!(built[5], "-o");
        assert_eq!(built[6], "table");
    }

    // ========================================================================
    // Tests for SearchCommand::effective_jql()
    // ========================================================================

    #[test]
    fn test_effective_jql_single_project() {
        let cmd = parse_command(&args("search -p PROJ -q status=Open")).unwrap();
        if let JiraSubcommand::Search(ref search) = cmd.command.command {
            assert_eq!(search.effective_jql(), "(project = PROJ) AND (status=Open)");
        } else {
            panic!("Expected Search command");
        }
    }

    #[test]
    fn test_effective_jql_multiple_projects() {
        let cmd = parse_command(&args("search -p PROJ1 -p PROJ2 -q status=Open")).unwrap();
        if let JiraSubcommand::Search(ref search) = cmd.command.command {
            assert_eq!(
                search.effective_jql(),
                "(project in (PROJ1, PROJ2)) AND (status=Open)"
            );
        } else {
            panic!("Expected Search command");
        }
    }

    #[test]
    fn test_effective_jql_empty_jql() {
        // Construct args directly since split_whitespace can't produce an empty string
        let cmd_args = vec![
            "search".to_string(),
            "-p".to_string(),
            "PROJ".to_string(),
            "-q".to_string(),
            "".to_string(),
        ];
        let cmd = parse_command(&cmd_args).unwrap();
        if let JiraSubcommand::Search(ref search) = cmd.command.command {
            // Empty JQL string means just the project filter
            assert_eq!(search.effective_jql(), "project = PROJ");
        } else {
            panic!("Expected Search command");
        }
    }
}
