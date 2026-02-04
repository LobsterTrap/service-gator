//! service-gator: Scope-restricted CLI wrapper for sandboxed AI agents.
//!
//! Usage:
//!   service-gator gh api repos/owner/repo/pulls
//!   service-gator jira issue view PROJ-123
//!
//! MCP server mode:
//!   service-gator --mcp-server 127.0.0.1:8080

use std::path::Path;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use eyre::{bail, Context, Result};
use tracing_subscriber::prelude::*;

use service_gator::auth::ServerConfig;
use service_gator::core::run_command;
use service_gator::forgejo;
use service_gator::github;
use service_gator::gitlab;
use service_gator::jira::{self, IssueAction, JiraSubcommand, ProjectAction, VersionAction};
use service_gator::jira_client::JiraClient;
use service_gator::jira_types::JiraProjectKey;
use service_gator::scope::{
    ForgejoRepoPermission, ForgejoScope, GhRepoPermission, GlProjectPermission,
    JiraProjectPermission, ScopeConfig,
};
use service_gator::servers::{run_servers, ServerMode};

/// Initialize tracing with env-filter support (RUST_LOG).
fn init_tracing() {
    let format = tracing_subscriber::fmt::format()
        .without_time()
        .with_target(false)
        .compact();

    let fmt_layer = tracing_subscriber::fmt::layer()
        .event_format(format)
        .with_writer(std::io::stderr)
        .with_filter(tracing_subscriber::EnvFilter::from_default_env());

    tracing_subscriber::registry().with(fmt_layer).init();
}

/// Scope-restricted CLI wrapper for sandboxed AI agents
#[derive(Parser)]
#[command(name = "service-gator", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Start MCP server on the given address (e.g., 127.0.0.1:8080)
    #[arg(long = "mcp-server", value_name = "ADDR")]
    mcp_server: Option<String>,

    /// Start REST API server on the given address (e.g., 127.0.0.1:8081)
    #[arg(long = "rest-server", value_name = "ADDR")]
    rest_server: Option<String>,

    /// Start both MCP and REST servers (dual mode)
    /// MCP server runs on --mcp-server address (default: 127.0.0.1:8080)
    /// REST server runs on --rest-server address (default: 127.0.0.1:8081)
    #[arg(long = "dual-mode")]
    dual_mode: bool,

    /// Start HTTP proxy server on the given address (e.g., 127.0.0.1:8082)
    /// Transparent proxy for CLI tools like gh, glab, etc.
    #[arg(long = "http-proxy", value_name = "ADDR")]
    http_proxy: Option<String>,

    /// Path to a TOML configuration file
    #[arg(long = "config", value_name = "PATH")]
    config_file: Option<std::path::PathBuf>,

    /// Inline scope configuration as JSON (merged with --config file if provided).
    /// Example: --scope '{"gh":{"repos":{"owner/repo":{"read":true}}}}'
    #[arg(long = "scope", value_name = "JSON")]
    scope_json: Option<String>,

    /// Path to a JSON file containing scopes that will be watched for live reload.
    /// When this file changes, scopes are automatically reloaded without restart.
    /// This enables dynamic permission updates (e.g., via `devaipod gator add`).
    /// Format: {"scopes": {"gh": {"repos": {"owner/repo": {"read": true}}}}}
    #[arg(long = "scope-file", value_name = "PATH")]
    scope_file: Option<std::path::PathBuf>,

    /// Grant GitHub repo access. Format: OWNER/REPO:PERMS where PERMS is comma-separated
    /// list of: read, create-draft, pending-review, write.
    /// Example: --gh-repo myorg/myrepo:read,create-draft
    /// Can be specified multiple times.
    #[arg(long = "gh-repo", value_name = "REPO:PERMS")]
    gh_repos: Vec<String>,

    /// Grant JIRA project access. Format: PROJECT:PERMS where PERMS is comma-separated
    /// list of: read, create, write.
    /// Example: --jira-project MYPROJ:read,create
    /// Can be specified multiple times.
    #[arg(long = "jira-project", value_name = "PROJECT:PERMS")]
    jira_projects: Vec<String>,

    /// Grant GitLab project access. Format: GROUP/PROJECT:PERMS where PERMS is comma-separated
    /// list of: read, create-draft, approve, write.
    /// Example: --gitlab-project mygroup/myproject:read,create-draft
    /// Can be specified multiple times.
    #[arg(long = "gitlab-project", value_name = "PROJECT:PERMS")]
    gitlab_projects: Vec<String>,

    /// GitLab host for self-hosted instances (default: gitlab.com)
    #[arg(long = "gitlab-host", value_name = "HOST")]
    gitlab_host: Option<String>,

    /// Forgejo/Gitea host (REQUIRED for Forgejo - always self-hosted).
    /// Can be specified multiple times for different hosts.
    /// Example: --forgejo-host codeberg.org
    #[arg(long = "forgejo-host", value_name = "HOST")]
    forgejo_hosts: Vec<String>,

    /// Grant Forgejo repository access. Format: REPO:PERMS where PERMS is comma-separated
    /// list of: read, create-draft, pending-review, write.
    /// Use with --forgejo-host to specify which host.
    /// Example: --forgejo-host codeberg.org --forgejo-repo owner/repo:read
    /// Can be specified multiple times.
    #[arg(long = "forgejo-repo", value_name = "REPO:PERMS")]
    forgejo_repos: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// GitHub CLI wrapper (use `service-gator gh` for scope info)
    #[command(disable_help_flag = true)]
    Gh {
        /// Arguments passed to gh
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// GitLab CLI wrapper (use `service-gator gl` for scope info)
    #[command(disable_help_flag = true)]
    Gl {
        /// Arguments passed to glab
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// JIRA CLI wrapper (use `service-gator jira` for scope info)
    #[command(disable_help_flag = true)]
    Jira {
        /// Arguments passed to jirust-cli
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Forgejo/Gitea CLI wrapper (use `service-gator forgejo` for scope info)
    #[command(disable_help_flag = true)]
    Forgejo {
        /// Arguments passed to tea
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() -> ExitCode {
    // Process *_FILE environment variables before anything else.
    // This allows secrets to be mounted as files (podman --secret, k8s secrets)
    // and exported to the environment for child processes (gh, glab, tea, etc.).
    init_secrets_from_files();

    // Configure git to trust all directories. This is necessary when accessing
    // workspace repositories that are mounted from a volume owned by a different uid
    // (e.g., agent workspace running as uid 1000, service-gator running as root).
    // The "-c safe.directory=*" flag doesn't work because safe.directory is checked
    // before command-line config is processed.
    configure_git_safe_directory();

    init_tracing();

    match try_main() {
        Ok(code) => code,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::from(1)
        }
    }
}

/// Read secrets from files specified by *_FILE environment variables.
///
/// For each VAR_FILE env var, reads the file and sets VAR to its contents.
/// This supports container secret patterns like `podman run --secret`.
fn init_secrets_from_files() {
    const SECRET_VARS: &[&str] = &[
        "GH_TOKEN",
        "GITLAB_TOKEN",
        "FORGEJO_TOKEN",
        "GITEA_TOKEN",
        "JIRA_API_TOKEN",
        "SERVICE_GATOR_SECRET",
        "SERVICE_GATOR_ADMIN_KEY",
    ];

    for var in SECRET_VARS {
        let file_var = format!("{}_FILE", var);
        if let Ok(path) = std::env::var(&file_var) {
            if let Some(value) = read_secret_file(Path::new(&path)) {
                std::env::set_var(var, value);
            }
        }
    }
}

/// Read a secret from a file, trimming whitespace.
fn read_secret_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Configure git to trust all directories via global config.
///
/// This is necessary for git_push_local to fetch commits from workspace
/// repositories that may be owned by a different uid. Git's "dubious ownership"
/// check rejects repositories not owned by the current user, but we need to
/// read from agent workspaces mounted as volumes.
fn configure_git_safe_directory() {
    // Best effort - if git isn't available or config fails, we'll get a clearer
    // error later when the actual git operation fails
    let _ = std::process::Command::new("git")
        .args(["config", "--global", "--add", "safe.directory", "*"])
        .status();
}

fn try_main() -> Result<ExitCode> {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Build config from file + CLI args
    let server_config = build_config(&cli)?;

    // Server mode - determine which server(s) to start
    let server_mode = determine_server_mode(&cli)?;
    if let Some((mode, mcp_addr, rest_addr)) = server_mode {
        return run_servers_mode(
            mode,
            mcp_addr.as_deref(),
            rest_addr.as_deref(),
            server_config,
            cli.scope_file,
        );
    }

    // HTTP proxy mode (separate from MCP/REST servers)
    if let Some(addr) = cli.http_proxy {
        return run_proxy_server(&addr, server_config);
    }

    // For CLI commands, we only need the scope config
    let config = &server_config.scopes;

    match cli.command {
        Some(Command::Gh { args }) => run_gh(config, args),
        Some(Command::Gl { args }) => run_gl(config, args),
        Some(Command::Jira { args }) => run_jira(config, args),
        Some(Command::Forgejo { args }) => run_forgejo(config, args),
        None => bail!("no command provided; run 'service-gator --help' for usage"),
    }
}

/// Run the HTTP proxy server.
fn run_proxy_server(addr: &str, config: ServerConfig) -> Result<ExitCode> {
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    rt.block_on(service_gator::proxy::start_proxy_server(addr, config))
        .context("HTTP proxy server failed")?;

    Ok(ExitCode::SUCCESS)
}

/// Determine which server mode to use based on CLI flags.
#[allow(clippy::type_complexity)]
fn determine_server_mode(
    cli: &Cli,
) -> Result<Option<(ServerMode, Option<String>, Option<String>)>> {
    let has_mcp = cli.mcp_server.is_some();
    let has_rest = cli.rest_server.is_some();
    let dual_mode = cli.dual_mode;

    match (has_mcp, has_rest, dual_mode) {
        // No server flags
        (false, false, false) => Ok(None),

        // Single server modes
        (true, false, false) => Ok(Some((ServerMode::Mcp, cli.mcp_server.clone(), None))),
        (false, true, false) => Ok(Some((ServerMode::Rest, None, cli.rest_server.clone()))),

        // Dual mode variants
        (false, false, true) => {
            // Use defaults for both
            Ok(Some((
                ServerMode::Dual,
                Some("127.0.0.1:8080".to_string()),
                Some("127.0.0.1:8081".to_string()),
            )))
        }
        (true, false, true) => {
            // MCP specified, use default for REST
            Ok(Some((
                ServerMode::Dual,
                cli.mcp_server.clone(),
                Some("127.0.0.1:8081".to_string()),
            )))
        }
        (false, true, true) => {
            // REST specified, use default for MCP
            Ok(Some((
                ServerMode::Dual,
                Some("127.0.0.1:8080".to_string()),
                cli.rest_server.clone(),
            )))
        }
        (true, true, false) => {
            // Both servers specified without --dual-mode, treat as dual mode
            Ok(Some((
                ServerMode::Dual,
                cli.mcp_server.clone(),
                cli.rest_server.clone(),
            )))
        }
        (true, true, true) => {
            // Both servers specified with --dual-mode
            Ok(Some((
                ServerMode::Dual,
                cli.mcp_server.clone(),
                cli.rest_server.clone(),
            )))
        }
    }
}

/// Run server(s) based on the determined mode with optional scope file watching.
fn run_servers_mode(
    mode: ServerMode,
    mcp_addr: Option<&str>,
    rest_addr: Option<&str>,
    config: ServerConfig,
    scope_file: Option<std::path::PathBuf>,
) -> Result<ExitCode> {
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;

    rt.block_on(async {
        // Set up scopes: file-watched if --scope-file provided, static otherwise
        let scopes = match scope_file {
            Some(path) => service_gator::config_watcher::watch_scopes(&path)
                .await
                .with_context(|| format!("loading scope file {}", path.display()))?,
            None => service_gator::config_watcher::static_scopes(config.scopes.clone()),
        };

        run_servers(mode, mcp_addr, rest_addr, config, scopes).await
    })
    .context("server(s) failed")?;

    Ok(ExitCode::SUCCESS)
}

/// Build configuration from file + CLI arguments.
fn build_config(cli: &Cli) -> Result<ServerConfig> {
    // Start with file config if provided, otherwise empty
    let mut config = if let Some(path) = &cli.config_file {
        load_config_file(path)?
    } else {
        ServerConfig::default()
    };

    // Merge JSON scope if provided
    if let Some(json) = &cli.scope_json {
        let json_config: ScopeConfig =
            serde_json::from_str(json).context("parsing --scope JSON")?;
        merge_config(&mut config.scopes, json_config);
    }

    // Parse and merge --gh-repo flags
    for spec in &cli.gh_repos {
        let (repo, perm) =
            parse_gh_repo_spec(spec).with_context(|| format!("parsing --gh-repo '{spec}'"))?;
        config.scopes.gh.repos.insert(repo, perm);
    }

    // Parse and merge --jira-project flags
    for spec in &cli.jira_projects {
        let (project, perm) = parse_jira_project_spec(spec)
            .with_context(|| format!("parsing --jira-project '{spec}'"))?;
        config.scopes.jira.projects.insert(project, perm);
    }

    // Parse and merge --gitlab-project flags
    for spec in &cli.gitlab_projects {
        let (project, perm) = parse_gitlab_project_spec(spec)
            .with_context(|| format!("parsing --gitlab-project '{spec}'"))?;
        config.scopes.gitlab.projects.insert(project, perm);
    }

    // Set GitLab host if provided
    if let Some(host) = &cli.gitlab_host {
        config.scopes.gitlab.host = Some(host.clone());
    }

    // Parse and merge --forgejo-host and --forgejo-repo flags
    // The pattern is: --forgejo-host HOST --forgejo-repo REPO:PERMS
    // All repos specified before the next --forgejo-host go to that host
    if !cli.forgejo_hosts.is_empty() || !cli.forgejo_repos.is_empty() {
        // If repos are specified without hosts, error
        if cli.forgejo_hosts.is_empty() && !cli.forgejo_repos.is_empty() {
            bail!("--forgejo-repo requires --forgejo-host to be specified");
        }

        // For simplicity, if there's exactly one host, all repos go to it
        // If there are multiple hosts, we need a more sophisticated approach
        // For now, we support the single-host case or require the user to use config file
        if cli.forgejo_hosts.len() == 1 {
            let host = cli.forgejo_hosts[0].clone();

            // Find or create the scope for this host
            let scope = config
                .scopes
                .forgejo
                .iter_mut()
                .find(|s| s.host == host)
                .map(|s| s as &mut ForgejoScope);

            let scope = if let Some(s) = scope {
                s
            } else {
                config.scopes.forgejo.push(ForgejoScope {
                    host: host.clone(),
                    ..Default::default()
                });
                config.scopes.forgejo.last_mut().unwrap()
            };

            for spec in &cli.forgejo_repos {
                let (repo, perm) = parse_forgejo_repo_spec(spec)
                    .with_context(|| format!("parsing --forgejo-repo '{spec}'"))?;
                scope.repos.insert(repo, perm);
            }
        } else {
            // Multiple hosts: just create empty scopes, user should use config file for repos
            for host in &cli.forgejo_hosts {
                if !config.scopes.forgejo.iter().any(|s| &s.host == host) {
                    config.scopes.forgejo.push(ForgejoScope {
                        host: host.clone(),
                        ..Default::default()
                    });
                }
            }
            if !cli.forgejo_repos.is_empty() {
                bail!(
                    "When multiple --forgejo-host flags are specified, use config file for repo permissions"
                );
            }
        }
    }

    Ok(config)
}

/// Load configuration from an explicit path.
fn load_config_file(path: &std::path::Path) -> Result<ServerConfig> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let config = toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    Ok(config)
}

/// Merge source config into target (source values override target).
fn merge_config(target: &mut ScopeConfig, source: ScopeConfig) {
    // Merge GitHub global read flag
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
    if source.gh.graphql != service_gator::scope::GraphQlPermission::None {
        target.gh.graphql = source.gh.graphql;
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
    if source.gitlab.graphql != service_gator::scope::GraphQlPermission::None {
        target.gitlab.graphql = source.gitlab.graphql;
    }
}

/// Parse a --gh-repo spec like "owner/repo:read,create-draft"
fn parse_gh_repo_spec(spec: &str) -> Result<(String, GhRepoPermission)> {
    let (repo, perms_str) = spec
        .split_once(':')
        .ok_or_else(|| eyre::eyre!("expected format OWNER/REPO:PERMS (e.g., myorg/repo:read)"))?;

    if !repo.contains('/') {
        bail!("repository must be in OWNER/REPO format, got '{repo}'");
    }

    let mut perm = GhRepoPermission::default();
    for p in perms_str.split(',') {
        match p.trim() {
            "read" => perm.read = true,
            "create-draft" => perm.create_draft = true,
            "pending-review" => perm.pending_review = true,
            "push-new-branch" => perm.push_new_branch = true,
            "push" => perm.push_new_branch = true, // alias for convenience
            "write" => perm.write = true,
            "" => {}
            other => bail!(
                "unknown permission '{other}'; valid: read, create-draft, pending-review, push-new-branch, write"
            ),
        }
    }

    Ok((repo.to_string(), perm))
}

/// Parse a --jira-project spec like "PROJ:read,create"
fn parse_jira_project_spec(spec: &str) -> Result<(JiraProjectKey, JiraProjectPermission)> {
    let (project, perms_str) = spec
        .split_once(':')
        .ok_or_else(|| eyre::eyre!("expected format PROJECT:PERMS (e.g., MYPROJ:read)"))?;

    // Validate project key
    let project_key: JiraProjectKey = project
        .parse()
        .map_err(|e| eyre::eyre!("invalid project key '{}': {}", project, e))?;

    let mut perm = JiraProjectPermission::default();
    for p in perms_str.split(',') {
        match p.trim() {
            "read" => perm.read = true,
            "create" => perm.create = true,
            "write" => perm.write = true,
            "" => {}
            other => bail!("unknown permission '{other}'; valid: read, create, write"),
        }
    }

    Ok((project_key, perm))
}

/// Parse a --gitlab-project spec like "group/project:read,create-draft"
fn parse_gitlab_project_spec(spec: &str) -> Result<(String, GlProjectPermission)> {
    let (project, perms_str) = spec.split_once(':').ok_or_else(|| {
        eyre::eyre!("expected format GROUP/PROJECT:PERMS (e.g., mygroup/project:read)")
    })?;

    if !project.contains('/') {
        bail!("project must be in GROUP/PROJECT format, got '{project}'");
    }

    let mut perm = GlProjectPermission::default();
    for p in perms_str.split(',') {
        match p.trim() {
            "read" => perm.read = true,
            "create-draft" => perm.create_draft = true,
            "approve" => perm.approve = true,
            "push-new-branch" => perm.push_new_branch = true,
            "push" => perm.push_new_branch = true, // alias for convenience
            "write" => perm.write = true,
            "" => {}
            other => {
                bail!("unknown permission '{other}'; valid: read, create-draft, approve, push-new-branch, write")
            }
        }
    }

    Ok((project.to_string(), perm))
}

/// Parse a --forgejo-repo spec like "owner/repo:read,create-draft"
fn parse_forgejo_repo_spec(spec: &str) -> Result<(String, ForgejoRepoPermission)> {
    let (repo, perms_str) = spec
        .split_once(':')
        .ok_or_else(|| eyre::eyre!("expected format OWNER/REPO:PERMS (e.g., owner/repo:read)"))?;

    if !repo.contains('/') {
        bail!("repository must be in OWNER/REPO format, got '{repo}'");
    }

    let mut perm = ForgejoRepoPermission::default();
    for p in perms_str.split(',') {
        match p.trim() {
            "read" => perm.read = true,
            "create-draft" => perm.create_draft = true,
            "pending-review" => perm.pending_review = true,
            "push-new-branch" => perm.push_new_branch = true,
            "push" => perm.push_new_branch = true, // alias for convenience
            "write" => perm.write = true,
            "" => {}
            other => bail!(
                "unknown permission '{other}'; valid: read, create-draft, pending-review, push-new-branch, write"
            ),
        }
    }

    Ok((repo.to_string(), perm))
}

/// Run a GitHub CLI command with scope checking.
/// Only `gh api` is supported with a restricted set of options.
/// All requests are forced to GET method for read-only access.
fn run_gh(config: &ScopeConfig, args: Vec<String>) -> Result<ExitCode> {
    // Handle help
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_gh_help(config);
        return Ok(ExitCode::SUCCESS);
    }

    // Only allow `gh api` subcommand
    let first_arg = args.first().map(|s| s.as_str());
    if first_arg != Some("api") {
        bail!("{}", gh_api_only_error(&args));
    }

    // Parse and validate the API command using clap
    let api = github::parse_api(&args).context("Usage: gh api <endpoint> [--jq <expression>]")?;

    // Permission check: GraphQL vs REST
    if api.is_graphql {
        // GraphQL permission check (global, not per-repo)
        // Note: Mutations are already rejected in parse_api()
        if !config.gh.graphql_read_allowed() {
            bail!("GraphQL read access not allowed; set `read = true` or `graphql = \"read\"` in [gh] section of config");
        }
    } else {
        // REST API - check permission
        match &api.repo {
            Some(repo) => {
                // Have a repo - check per-repo or global permission
                if !config.gh.is_read_allowed(repo) {
                    bail!(
                        "read access not allowed for '{repo}'; check ~/.config/service-gator.toml"
                    );
                }
            }
            None => {
                // No repo in path (e.g., /search, /gists, /user) - require global read
                if !config.gh.global_read_allowed() {
                    bail!(
                        "could not determine repository from path; \
                         use /repos/owner/repo/... or set `read = true` in [gh] section for global access"
                    );
                }
            }
        }
    }

    // Build final args with forced GET method
    run_command("gh", &github::build_api_args(&api))
}

/// Format error message when a non-api gh command is used.
fn gh_api_only_error(args: &[String]) -> String {
    let mut msg = format!(
        "only `gh api` is supported (read-only)\n\
         \n  Got: gh {}\n",
        args.join(" ")
    );

    if let Some(suggestion) = suggest_api_alternative(args) {
        msg.push_str(&format!("\nSuggested alternative:\n  {suggestion}\n"));
    }

    msg.push_str(
        "\nCommon read-only API endpoints:\n  \
         gh api repos/OWNER/REPO/pulls         # List PRs\n  \
         gh api repos/OWNER/REPO/issues/NUMBER # View issue\n\
         \nUse --jq to filter output: gh api .../pulls --jq '.[].title'",
    );

    msg
}

/// Suggest an API alternative for common gh commands.
fn suggest_api_alternative(args: &[String]) -> Option<String> {
    let cmd = args.first()?.as_str();
    let subcmd = args.get(1).map(|s| s.as_str());

    // Extract -R repo flag if present
    let repo = extract_repo_flag(args).unwrap_or("OWNER/REPO".to_string());

    // Extract PR/issue number if present (third positional arg typically)
    let number = args
        .iter()
        .skip(2)
        .find(|a| !a.starts_with('-') && a.chars().all(|c| c.is_ascii_digit()));

    match (cmd, subcmd) {
        ("pr", Some("list")) => Some(format!("gh api repos/{}/pulls", repo)),
        ("pr", Some("view")) => {
            if let Some(n) = number {
                Some(format!("gh api repos/{}/pulls/{}", repo, n))
            } else {
                Some(format!("gh api repos/{}/pulls/NUMBER", repo))
            }
        }
        ("pr", Some("diff")) => {
            number.map(|n| format!("gh api repos/{repo}/pulls/{n} --jq '.diff_url'"))
        }
        ("pr", Some("checks")) => number.map(|n| format!("gh api repos/{repo}/pulls/{n}/commits")),
        ("issue", Some("list")) => Some(format!("gh api repos/{}/issues", repo)),
        ("issue", Some("view")) => {
            if let Some(n) = number {
                Some(format!("gh api repos/{}/issues/{}", repo, n))
            } else {
                Some(format!("gh api repos/{}/issues/NUMBER", repo))
            }
        }
        ("repo", Some("view")) => Some(format!("gh api repos/{}", repo)),
        ("run", Some("list")) => Some(format!("gh api repos/{}/actions/runs", repo)),
        ("run", Some("view")) => {
            if let Some(n) = number {
                Some(format!("gh api repos/{}/actions/runs/{}", repo, n))
            } else {
                Some(format!("gh api repos/{}/actions/runs/RUN_ID", repo))
            }
        }
        ("release", Some("list")) => Some(format!("gh api repos/{}/releases", repo)),
        ("release", Some("view")) => Some(format!("gh api repos/{}/releases/latest", repo)),
        // search requires -f for query params which we don't support
        _ => None,
    }
}

/// Extract the -R/--repo flag value from args.
fn extract_repo_flag(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-R" || arg == "--repo" {
            return iter.next().cloned();
        }
        if let Some(repo) = arg.strip_prefix("--repo=") {
            return Some(repo.to_string());
        }
        if let Some(repo) = arg.strip_prefix("-R") {
            if !repo.is_empty() {
                return Some(repo.to_string());
            }
        }
    }
    None
}

/// Run a GitLab CLI command with scope checking.
/// Only `glab api` is supported with a restricted set of options.
/// All requests are forced to GET method for read-only access.
fn run_gl(config: &ScopeConfig, args: Vec<String>) -> Result<ExitCode> {
    // Handle help
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_gl_help(config);
        return Ok(ExitCode::SUCCESS);
    }

    // Only allow `glab api` subcommand
    let first_arg = args.first().map(|s| s.as_str());
    if first_arg != Some("api") {
        bail!("{}", gl_api_only_error(&args));
    }

    // Parse and validate the API command using clap
    let api = gitlab::parse_api(&args).context("Usage: glab api <endpoint> [--jq <expression>]")?;

    // Check per-project permission
    let project = api.project.as_ref().ok_or_else(|| {
        eyre::eyre!("could not determine project; use /projects/group%2Fproject/...")
    })?;

    if !config.gitlab.is_read_allowed(project) {
        bail!("read access not allowed for '{project}'; check ~/.config/service-gator.toml");
    }

    // Build final args with forced GET method and optional hostname
    let final_args = gitlab::build_api_args_with_host(&api.args, config.gitlab.host.as_deref());
    run_command("glab", &final_args)
}

/// Run a Forgejo CLI command with scope checking.
/// Only `tea api` is supported with a restricted set of options.
/// All requests are forced to GET method for read-only access.
fn run_forgejo(config: &ScopeConfig, args: Vec<String>) -> Result<ExitCode> {
    // Handle help
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_forgejo_help(config);
        return Ok(ExitCode::SUCCESS);
    }

    // Only allow `api` subcommand
    let first_arg = args.first().map(|s| s.as_str());
    if first_arg != Some("api") {
        bail!("{}", forgejo_api_only_error(&args));
    }

    // Parse and validate the API command using clap
    let api = forgejo::parse_api(&args).context("Usage: tea api <endpoint> [--jq <expression>]")?;

    // Check per-repo permission
    let repo = api.repo.as_ref().ok_or_else(|| {
        eyre::eyre!("could not determine repository; use /api/v1/repos/owner/repo/...")
    })?;

    // Find the appropriate Forgejo scope
    // For CLI, we need to extract host from args or require single host
    let host = extract_forgejo_host_flag(&args);
    let forgejo_scope = find_forgejo_scope(&config.forgejo, host.as_deref())?;

    if !forgejo_scope.is_read_allowed(repo) {
        bail!(
            "read access not allowed for '{repo}' on host '{}'; check ~/.config/service-gator.toml",
            forgejo_scope.host
        );
    }

    // Build final args with forced GET method and explicit host
    let mut tea_args = vec!["--host".to_string(), forgejo_scope.host.clone()];
    tea_args.extend(forgejo::build_api_args(&api.args));

    run_command("tea", &tea_args)
}

/// Find the appropriate ForgejoScope based on the provided host.
fn find_forgejo_scope<'a>(
    scopes: &'a [ForgejoScope],
    host: Option<&str>,
) -> Result<&'a ForgejoScope> {
    if scopes.is_empty() {
        bail!("No Forgejo hosts configured; use --forgejo-host or config file");
    }

    match host {
        Some(h) => scopes
            .iter()
            .find(|s| s.host == h)
            .ok_or_else(|| eyre::eyre!("Forgejo host '{}' not configured", h)),
        None => {
            if scopes.len() == 1 {
                Ok(&scopes[0])
            } else {
                let hosts: Vec<_> = scopes.iter().map(|s| s.host.as_str()).collect();
                bail!(
                    "Multiple Forgejo hosts configured, please specify one with --host: {}",
                    hosts.join(", ")
                )
            }
        }
    }
}

/// Extract the --host/-H flag value from args.
fn extract_forgejo_host_flag(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-H" || arg == "--host" {
            return iter.next().cloned();
        }
        if let Some(host) = arg.strip_prefix("--host=") {
            return Some(host.to_string());
        }
        if let Some(host) = arg.strip_prefix("-H") {
            if !host.is_empty() {
                return Some(host.to_string());
            }
        }
    }
    None
}

/// Format error message when a non-api forgejo command is used.
fn forgejo_api_only_error(args: &[String]) -> String {
    let mut msg = format!(
        "only `tea api` is supported (read-only)\n\
         \n  Got: tea {}\n",
        args.join(" ")
    );

    if let Some(suggestion) = suggest_forgejo_api_alternative(args) {
        msg.push_str(&format!("\nSuggested alternative:\n  {suggestion}\n"));
    }

    msg.push_str(
        "\nCommon read-only API endpoints:\n  \
         tea api /api/v1/repos/OWNER/REPO/pulls              # List PRs\n  \
         tea api /api/v1/repos/OWNER/REPO/issues/NUMBER      # View issue\n\
         \nUse --jq to filter output: tea api .../pulls --jq '.[].title'",
    );

    msg
}

/// Suggest an API alternative for common tea commands.
fn suggest_forgejo_api_alternative(args: &[String]) -> Option<String> {
    let cmd = args.first()?.as_str();
    let subcmd = args.get(1).map(|s| s.as_str());

    // Extract -R repo flag if present
    let repo = extract_forgejo_repo_flag(args).unwrap_or("OWNER/REPO".to_string());

    // Extract PR/issue number if present
    let number = args
        .iter()
        .skip(2)
        .find(|a| !a.starts_with('-') && a.chars().all(|c| c.is_ascii_digit()));

    match (cmd, subcmd) {
        ("pr" | "pulls", Some("list")) => Some(format!("tea api /api/v1/repos/{}/pulls", repo)),
        ("pr" | "pulls", Some("view")) => {
            if let Some(n) = number {
                Some(format!("tea api /api/v1/repos/{}/pulls/{}", repo, n))
            } else {
                Some(format!("tea api /api/v1/repos/{}/pulls/NUMBER", repo))
            }
        }
        ("issue" | "issues", Some("list")) => {
            Some(format!("tea api /api/v1/repos/{}/issues", repo))
        }
        ("issue" | "issues", Some("view")) => {
            if let Some(n) = number {
                Some(format!("tea api /api/v1/repos/{}/issues/{}", repo, n))
            } else {
                Some(format!("tea api /api/v1/repos/{}/issues/NUMBER", repo))
            }
        }
        ("repo" | "repos", Some("view")) => Some(format!("tea api /api/v1/repos/{}", repo)),
        ("release" | "releases", Some("list")) => {
            Some(format!("tea api /api/v1/repos/{}/releases", repo))
        }
        _ => None,
    }
}

/// Extract the -R/--repo flag value from forgejo args.
fn extract_forgejo_repo_flag(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-R" || arg == "--repo" {
            return iter.next().cloned();
        }
        if let Some(repo) = arg.strip_prefix("--repo=") {
            return Some(repo.to_string());
        }
        if let Some(repo) = arg.strip_prefix("-R") {
            if !repo.is_empty() {
                return Some(repo.to_string());
            }
        }
    }
    None
}

fn print_forgejo_help(config: &ScopeConfig) {
    println!("forgejo-gator - Forgejo/Gitea API wrapper for sandboxed AI agents (read-only)");
    println!();
    println!("Usage: service-gator forgejo api <endpoint> [--jq <expression>]");
    println!("       forgejo-gator api <endpoint> [--jq <expression>]");
    println!();
    println!("Only `tea api` with REST endpoints is supported.");
    println!("All requests are forced to GET method (read-only).");
    println!();
    println!("Options:");
    println!("  --jq, -q <expression>  Filter output using a jq expression");
    println!("  --host, -H <host>      Forgejo instance host (required if multiple configured)");
    println!();
    println!("Note: Forgejo API paths start with /api/v1/");
    println!();
    println!("Examples:");
    println!("  forgejo-gator api /api/v1/repos/owner/repo/pulls           # List PRs");
    println!("  forgejo-gator api /api/v1/repos/owner/repo/issues/123      # View issue");
    println!("  forgejo-gator api /api/v1/repos/owner/repo/pulls --jq '.[].title'");
    println!();
    println!("Configured scopes:");
    println!();
    if config.forgejo.is_empty() {
        println!("  (no Forgejo hosts configured)");
    } else {
        for scope in &config.forgejo {
            println!("  Host: {}", scope.host);
            println!("  Repositories:");
            if scope.repos.is_empty() {
                println!("    (no repositories configured)");
            } else {
                for (pattern, perm) in &scope.repos {
                    if perm.can_read() {
                        println!("    {} = read", pattern);
                    }
                }
            }
            println!();
        }
    }
}

/// Format error message when a non-api glab command is used.
fn gl_api_only_error(args: &[String]) -> String {
    let mut msg = format!(
        "only `glab api` is supported (read-only)\n\
         \n  Got: glab {}\n",
        args.join(" ")
    );

    if let Some(suggestion) = suggest_gl_api_alternative(args) {
        msg.push_str(&format!("\nSuggested alternative:\n  {suggestion}\n"));
    }

    msg.push_str(
        "\nCommon read-only API endpoints:\n  \
         glab api projects/GROUP%2FPROJECT/merge_requests        # List MRs\n  \
         glab api projects/GROUP%2FPROJECT/issues/NUMBER         # View issue\n\
         \nUse --jq to filter output: glab api .../merge_requests --jq '.[].title'",
    );

    msg
}

/// Suggest an API alternative for common glab commands.
fn suggest_gl_api_alternative(args: &[String]) -> Option<String> {
    let cmd = args.first()?.as_str();
    let subcmd = args.get(1).map(|s| s.as_str());

    // Extract -R repo flag if present
    let project = extract_gl_repo_flag(args).unwrap_or("GROUP%2FPROJECT".to_string());

    // Extract MR/issue number if present (third positional arg typically)
    let number = args
        .iter()
        .skip(2)
        .find(|a| !a.starts_with('-') && a.chars().all(|c| c.is_ascii_digit()));

    match (cmd, subcmd) {
        ("mr", Some("list")) => Some(format!("glab api projects/{}/merge_requests", project)),
        ("mr", Some("view")) => {
            if let Some(n) = number {
                Some(format!(
                    "glab api projects/{}/merge_requests/{}",
                    project, n
                ))
            } else {
                Some(format!(
                    "glab api projects/{}/merge_requests/NUMBER",
                    project
                ))
            }
        }
        ("issue", Some("list")) => Some(format!("glab api projects/{}/issues", project)),
        ("issue", Some("view")) => {
            if let Some(n) = number {
                Some(format!("glab api projects/{}/issues/{}", project, n))
            } else {
                Some(format!("glab api projects/{}/issues/NUMBER", project))
            }
        }
        ("project" | "repo", Some("view")) => Some(format!("glab api projects/{}", project)),
        ("pipeline", Some("list")) => Some(format!("glab api projects/{}/pipelines", project)),
        ("pipeline", Some("view")) => {
            if let Some(n) = number {
                Some(format!("glab api projects/{}/pipelines/{}", project, n))
            } else {
                Some(format!(
                    "glab api projects/{}/pipelines/PIPELINE_ID",
                    project
                ))
            }
        }
        ("release", Some("list")) => Some(format!("glab api projects/{}/releases", project)),
        _ => None,
    }
}

/// Extract the -R/--repo flag value from glab args.
fn extract_gl_repo_flag(args: &[String]) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "-R" || arg == "--repo" {
            return iter.next().cloned();
        }
        if let Some(repo) = arg.strip_prefix("--repo=") {
            return Some(repo.to_string());
        }
        if let Some(repo) = arg.strip_prefix("-R") {
            if !repo.is_empty() {
                return Some(repo.to_string());
            }
        }
    }
    None
}

fn print_gl_help(config: &ScopeConfig) {
    println!("gl-gator - GitLab API wrapper for sandboxed AI agents (read-only)");
    println!();
    println!("Usage: service-gator gl api <endpoint> [--jq <expression>]");
    println!("       gl-gator api <endpoint> [--jq <expression>]");
    println!();
    println!("Only `glab api` with REST endpoints is supported.");
    println!("All requests are forced to GET method (read-only).");
    println!();
    println!("Options:");
    println!("  --jq, -q <expression>  Filter output using a jq expression");
    println!();
    println!("Note: Project paths must be URL-encoded (use %2F for /).");
    println!();
    println!("Examples:");
    println!("  gl-gator api projects/group%2Fproject/merge_requests      # List MRs");
    println!("  gl-gator api projects/group%2Fproject/issues/123          # View issue");
    println!("  gl-gator api projects/group%2Fproject/merge_requests --jq '.[].title'");
    println!();
    println!("Configured scopes:");
    println!();
    println!("  Projects:");
    if config.gitlab.projects.is_empty() {
        println!("    (no projects configured)");
    } else {
        for (pattern, perm) in &config.gitlab.projects {
            if perm.can_read() {
                println!("    {} = read", pattern);
            }
        }
    }
    if let Some(host) = &config.gitlab.host {
        println!();
        println!("  Host: {}", host);
    }
}

fn print_gh_help(config: &ScopeConfig) {
    println!("gh-gator - GitHub API wrapper for sandboxed AI agents (read-only)");
    println!();
    println!("Usage: service-gator gh api <endpoint> [--jq <expression>]");
    println!("       gh-gator api <endpoint> [--jq <expression>]");
    println!();
    println!("Only `gh api` with REST endpoints is supported.");
    println!("All requests are forced to GET method (read-only).");
    println!();
    println!("Options:");
    println!("  --jq, -q <expression>  Filter output using a jq expression");
    println!();
    println!("Examples:");
    println!("  gh-gator api repos/owner/repo/pulls              # List PRs");
    println!("  gh-gator api repos/owner/repo/issues/123         # View issue");
    println!("  gh-gator api repos/owner/repo/pulls --jq '.[].title'  # Filter output");
    println!();
    println!("Configured scopes:");
    println!();
    println!("  Repositories:");
    if config.gh.repos.is_empty() {
        println!("    (no repositories configured)");
    } else {
        for (pattern, perm) in &config.gh.repos {
            if perm.can_read() {
                println!("    {} = read", pattern);
            }
        }
    }
}

/// Run a JIRA command with scope checking.
///
/// Only explicitly allowed commands and options are permitted.
/// Unknown commands or options are rejected for security.
fn run_jira(config: &ScopeConfig, args: Vec<String>) -> Result<ExitCode> {
    // Handle help
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_jira_help(config);
        return Ok(ExitCode::SUCCESS);
    }

    // Parse and validate the command using clap - rejects unknown commands/options
    let validated = jira::parse_command(&args).context(
        "Invalid command. Allowed: issue (list/show/create/transition/assign), project list, version list, search",
    )?;

    // Get the operation type
    let op_type = jira::classify_command(&validated);

    // For project list and search, we don't need a specific project
    let is_project_list = matches!(validated.command.command, JiraSubcommand::Project(_));
    let is_search = matches!(validated.command.command, JiraSubcommand::Search(_));

    // Get target project
    let project = validated
        .project
        .as_deref()
        .or_else(|| validated.issue.as_ref().and_then(|i| i.split('-').next()))
        .map(|s| s.to_string());

    // Check if JIRA credentials are configured
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
            bail!("JIRA not configured. Set host and token (and optionally username) in the config file.");
        }
    };

    // For project list and search, just check that at least one project is configured
    if is_project_list || is_search {
        if config.jira.projects.is_empty() {
            bail!("No JIRA projects configured");
        }
    } else {
        // For other commands, check specific project permission
        let project_key = match &project {
            Some(p) => p,
            None => {
                bail!("could not determine target project; use -p PROJECT or -i ISSUE-KEY");
            }
        };

        // Parse the project key string into a typed key for lookup
        let project_key_typed = project_key.parse::<JiraProjectKey>().ok();
        let project_perms = project_key_typed
            .as_ref()
            .and_then(|k| config.jira.projects.get(k));
        let allowed = match op_type {
            service_gator::scope::OpType::Read => {
                project_perms.map(|p| p.can_read()).unwrap_or(false)
            }
            service_gator::scope::OpType::Write => {
                // Check for issue-specific permissions first
                if let Some(issue) = &validated.issue {
                    // Parse issue key for typed lookup
                    let issue_key_typed = issue
                        .parse::<service_gator::jira_types::JiraIssueKey>()
                        .ok();
                    let issue_perm = issue_key_typed
                        .as_ref()
                        .and_then(|k| config.jira.issues.get(k));
                    if let Some(perm) = issue_perm {
                        if perm.write {
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
            let issue_info = validated
                .issue
                .as_ref()
                .map(|i| format!(" (issue {i})"))
                .unwrap_or_default();
            bail!(
                "operation '{}' not allowed for project '{project_key}'{issue_info}; check ~/.config/service-gator.toml",
                validated.description
            );
        }
    }

    // Create the JIRA client and execute
    // Use bearer auth if no username, otherwise basic auth
    let client = match &username {
        Some(user) => JiraClient::new(&host, user, token.expose_secret()),
        None => JiraClient::with_bearer_token(&host, token.expose_secret()),
    }
    .context("Failed to create JIRA client")?;

    // Run the async command in a blocking context
    let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
    let result = rt.block_on(execute_jira_command(&client, &validated));

    match result {
        Ok(output) => {
            if !output.is_empty() {
                println!("{}", output);
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            Ok(ExitCode::from(1))
        }
    }
}

/// Execute a validated JIRA command using the native client.
async fn execute_jira_command(
    client: &JiraClient,
    validated: &jira::ValidatedJiraCommand,
) -> eyre::Result<String> {
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
                let issue_key_str = issue_key.to_string();
                let issue = client.get_issue(&issue_key_str).await?;
                Ok(serde_json::to_string_pretty(&issue)?)
            }
            IssueAction::Create(args) => {
                let created = client
                    .create_issue(
                        args.project.as_str(),
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
                let issue_key_str = issue_key.to_string();

                match &args.transition {
                    Some(transition_name) => {
                        client
                            .transition_issue(&issue_key_str, transition_name)
                            .await?;
                        Ok(format!(
                            "Successfully transitioned {} to {}",
                            issue_key, transition_name
                        ))
                    }
                    None => {
                        // List available transitions
                        let transitions = client.get_transitions(&issue_key_str).await?;
                        Ok(serde_json::to_string_pretty(&transitions)?)
                    }
                }
            }
            IssueAction::Assign(args) => {
                let issue_key = args
                    .effective_issue()
                    .ok_or_else(|| eyre::eyre!("Issue key required"))?;
                let issue_key_str = issue_key.to_string();
                client
                    .assign_issue(&issue_key_str, args.assignee.as_deref())
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
                let versions = client.list_versions(args.project.as_str()).await?;
                Ok(serde_json::to_string_pretty(&versions)?)
            }
        },
        JiraSubcommand::Search(search_cmd) => {
            let results = client.search(&search_cmd.jql).await?;
            Ok(serde_json::to_string_pretty(&results)?)
        }
    }
}

fn print_jira_help(config: &ScopeConfig) {
    println!("jira-gator - JIRA CLI wrapper for sandboxed AI agents");
    println!();
    println!("Usage: service-gator jira <command> [args...]");
    println!("       jira-gator <command> [args...]");
    println!();
    println!("Only explicitly allowed commands and options are permitted.");
    println!();
    println!("Allowed commands:");
    println!("  issue list -p PROJECT [-o FORMAT]");
    println!("  issue show -i ISSUE-KEY [-o FORMAT]");
    println!("  issue create -p PROJECT -s SUMMARY [-d DESC] [-t TYPE] [-o FORMAT]");
    println!("  issue transition -i ISSUE-KEY [-t TRANSITION] [-o FORMAT]");
    println!("  issue assign -i ISSUE-KEY [-a ASSIGNEE] [-o FORMAT]");
    println!("  project list [-o FORMAT]");
    println!("  version list -p PROJECT [-o FORMAT]");
    println!("  search -q JQL [-o FORMAT]");
    println!();
    println!("Configured scopes:");
    if config.jira.projects.is_empty() {
        println!("  (no projects configured)");
    } else {
        for (project, perm) in &config.jira.projects {
            let mut caps = Vec::new();
            if perm.read {
                caps.push("read");
            }
            if perm.create {
                caps.push("create");
            }
            if perm.write {
                caps.push("write");
            }
            println!("  {} = {}", project, caps.join(", "));
        }
    }
}
