//! Unified service layer for service-gator.
//!
//! This module provides a simplified service architecture that eliminates code
//! duplication by using generic CLI services and a centralized service registry.

pub mod cli;
pub mod jira;

use eyre::Result;
use serde_json::Value;
use tracing::info;

use self::cli::{services, CliService};
use self::jira::JiraHttpService;
use crate::scope::{ForgejoScope, ScopeConfig};

/// Typed errors for service-layer operations.
///
/// These replace `bail!()` string errors so callers can match on variants
/// instead of inspecting error message text.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    // -- Permission errors (HTTP 403) --
    #[error("Read access not allowed for {resource_kind}: {name}")]
    ReadDenied {
        resource_kind: &'static str,
        name: String,
    },

    #[error("Write access not allowed for {resource_kind}: {name}{}", scope_msg.as_deref().unwrap_or(""))]
    WriteDenied {
        resource_kind: &'static str,
        name: String,
        scope_msg: Option<String>,
    },

    #[error("GraphQL mutations are not supported via api operation. Use dedicated tools.")]
    GraphQlMutationDenied,

    #[error("GraphQL read access not allowed for {forge}. {hint}")]
    GraphQlReadDenied {
        forge: &'static str,
        hint: &'static str,
    },

    // -- Configuration / input errors (HTTP 400) --
    #[error("{resource_kind} requires a {path_hint}")]
    MissingResourcePath {
        resource_kind: &'static str,
        path_hint: &'static str,
    },

    #[error("This endpoint requires {requirement}")]
    InsufficientScope { requirement: String },

    #[error("No {forge} hosts configured")]
    NoHostsConfigured { forge: &'static str },

    #[error("Host '{host}' not found in {forge} configuration")]
    HostNotFound { forge: &'static str, host: String },

    #[error("No configured {forge} host has access to {resource_kind}: {name}")]
    NoHostAccess {
        forge: &'static str,
        resource_kind: &'static str,
        name: String,
    },

    #[error("{0}")]
    InvalidInput(String),
}

impl ServiceError {
    /// Whether this error represents a permission denial (HTTP 403).
    pub fn is_permission_denied(&self) -> bool {
        matches!(
            self,
            ServiceError::ReadDenied { .. }
                | ServiceError::WriteDenied { .. }
                | ServiceError::GraphQlMutationDenied
                | ServiceError::GraphQlReadDenied { .. }
        )
    }
}

/// Enum representing different API services.
#[derive(Clone, Debug)]
pub enum ApiService {
    GitHub(CliServiceAdapter),
    GitLab(CliServiceAdapter),
    Forgejo(CliServiceAdapter),
    Jira(JiraServiceAdapter),
}

impl ApiService {
    /// Execute an API request.
    pub async fn execute_api(
        &self,
        config: &ScopeConfig,
        endpoint: &str,
        method: &str,
        body: Option<Value>,
        jq: Option<&str>,
        context: Option<&ServiceContext>,
    ) -> Result<String> {
        match self {
            ApiService::GitHub(service) => {
                service
                    .execute_api(config, endpoint, method, body, jq, context)
                    .await
            }
            ApiService::GitLab(service) => {
                service
                    .execute_api(config, endpoint, method, body, jq, context)
                    .await
            }
            ApiService::Forgejo(service) => {
                service
                    .execute_api(config, endpoint, method, body, jq, context)
                    .await
            }
            ApiService::Jira(service) => {
                service
                    .execute_api(config, endpoint, method, body, jq, context)
                    .await
            }
        }
    }
}

/// Additional context for service execution.
#[derive(Debug, Clone)]
pub struct ServiceContext {
    /// Host hint for multi-host services like Forgejo.
    pub host: Option<String>,
    /// Any additional parameters.
    pub params: std::collections::HashMap<String, String>,
}

/// CLI-based service adapter.
#[derive(Clone, Debug)]
pub struct CliServiceAdapter {
    cli: CliService,
    permission_checker: PermissionChecker,
}

/// JIRA HTTP service adapter.
#[derive(Clone, Debug)]
pub struct JiraServiceAdapter {
    jira: JiraHttpService,
}

/// Permission checker for different service types.
#[derive(Clone, Debug)]
pub enum PermissionChecker {
    GitHub,
    GitLab,
    Forgejo,
}

impl PermissionChecker {
    /// Check if operation is allowed.
    pub fn check_permission(
        &self,
        config: &ScopeConfig,
        endpoint: &str,
        method: &str,
        context: Option<&ServiceContext>,
    ) -> Result<()> {
        let is_write = method != "GET" && method != "HEAD";

        match self {
            PermissionChecker::GitHub => {
                self.check_github_permission(config, endpoint, method, is_write)
            }
            PermissionChecker::GitLab => {
                self.check_gitlab_permission(config, endpoint, method, is_write)
            }
            PermissionChecker::Forgejo => {
                self.check_forgejo_permission(config, endpoint, method, is_write, context)
            }
        }
    }

    fn check_github_permission(
        &self,
        config: &ScopeConfig,
        endpoint: &str,
        method: &str,
        is_write: bool,
    ) -> Result<()> {
        use crate::github::{extract_repo_from_api_path, extract_resource_from_api_path};
        use crate::scope::GhOpType;

        // GraphQL special handling
        if endpoint == "graphql" {
            if is_write {
                return Err(ServiceError::GraphQlMutationDenied.into());
            }
            if !config.gh.graphql_read_allowed() {
                return Err(ServiceError::GraphQlReadDenied {
                    forge: "GitHub",
                    hint: "Set `read = true` or `graphql = \"read\"` in [gh] config.",
                }
                .into());
            }
            return Ok(());
        }

        let repo = extract_repo_from_api_path(endpoint);
        let resource_ref = extract_resource_from_api_path(endpoint);

        if is_write {
            let repo = repo.ok_or(ServiceError::MissingResourcePath {
                resource_kind: "Write operations",
                path_hint: "repository path (repos/owner/repo/...)",
            })?;

            if !config
                .gh
                .is_allowed(&repo, GhOpType::WriteResource, resource_ref.as_deref())
            {
                return Err(ServiceError::WriteDenied {
                    resource_kind: "repository",
                    name: repo,
                    scope_msg: resource_ref.map(|res| format!(" (resource: {})", res)),
                }
                .into());
            }

            info!(
                operation = "github_api",
                method = %method,
                repo = %repo,
                endpoint = %endpoint,
                resource = resource_ref.as_deref().unwrap_or("-"),
                "GitHub API write operation"
            );
        } else {
            match repo {
                Some(ref repo) => {
                    if !config.gh.is_read_allowed(repo) {
                        return Err(ServiceError::ReadDenied {
                            resource_kind: "repository",
                            name: repo.clone(),
                        }
                        .into());
                    }
                }
                None => {
                    if !config.gh.global_read_allowed() {
                        return Err(ServiceError::InsufficientScope {
                            requirement: "global read access. Set `read = true` in [gh] config, or use /repos/owner/repo/... paths".to_string(),
                        }
                        .into());
                    }
                }
            }
        }

        Ok(())
    }

    fn check_gitlab_permission(
        &self,
        config: &ScopeConfig,
        endpoint: &str,
        method: &str,
        is_write: bool,
    ) -> Result<()> {
        use crate::gitlab::extract_project_from_api_path;
        use crate::scope::GlOpType;

        if endpoint == "graphql" {
            if is_write {
                return Err(ServiceError::GraphQlMutationDenied.into());
            }
            if !config.gitlab.graphql_read_allowed() {
                return Err(ServiceError::GraphQlReadDenied {
                    forge: "GitLab",
                    hint: "Set `graphql = \"read\"` in [gitlab] config.",
                }
                .into());
            }
            return Ok(());
        }

        let project = extract_project_from_api_path(endpoint);

        if is_write {
            let project = project.ok_or(ServiceError::MissingResourcePath {
                resource_kind: "Write operations",
                path_hint: "project path (/api/v4/projects/group%2Fproject/...)",
            })?;

            if !config
                .gitlab
                .is_allowed(&project, GlOpType::WriteResource, None)
            {
                return Err(ServiceError::WriteDenied {
                    resource_kind: "project",
                    name: project,
                    scope_msg: None,
                }
                .into());
            }

            info!(
                operation = "gitlab_api",
                method = %method,
                project = %project,
                endpoint = %endpoint,
                "GitLab API write operation"
            );
        } else {
            match project {
                Some(ref project) => {
                    if !config.gitlab.is_read_allowed(project) {
                        return Err(ServiceError::ReadDenied {
                            resource_kind: "project",
                            name: project.clone(),
                        }
                        .into());
                    }
                }
                None => {
                    if config.gitlab.projects.is_empty() {
                        return Err(ServiceError::InsufficientScope {
                            requirement: "project access. Configure at least one project in [gitlab.projects] config".to_string(),
                        }
                        .into());
                    }
                }
            }
        }

        Ok(())
    }

    fn check_forgejo_permission(
        &self,
        config: &ScopeConfig,
        endpoint: &str,
        method: &str,
        is_write: bool,
        context: Option<&ServiceContext>,
    ) -> Result<()> {
        use crate::forgejo::extract_repo_from_api_path;
        use crate::scope::ForgejoOpType;

        let repo = extract_repo_from_api_path(endpoint);
        let host_hint = context.and_then(|c| c.host.as_deref());

        // Resolve which Forgejo host to use
        let forgejo_scope = self.resolve_forgejo_host(config, repo.as_deref(), host_hint)?;

        if is_write {
            let repo = repo.ok_or(ServiceError::MissingResourcePath {
                resource_kind: "Write operations",
                path_hint: "repository path (/api/v1/repos/owner/repo/...)",
            })?;

            if !forgejo_scope.is_allowed(&repo, ForgejoOpType::WriteResource, None) {
                return Err(ServiceError::WriteDenied {
                    resource_kind: "repository",
                    name: format!("{} on host: {}", repo, forgejo_scope.host),
                    scope_msg: None,
                }
                .into());
            }

            info!(
                operation = "forgejo_api",
                method = %method,
                repo = %repo,
                host = %forgejo_scope.host,
                endpoint = %endpoint,
                "Forgejo API write operation"
            );
        } else {
            match repo {
                Some(ref repo) => {
                    if !forgejo_scope.is_read_allowed(repo) {
                        return Err(ServiceError::ReadDenied {
                            resource_kind: "repository",
                            name: format!("{} on host: {}", repo, forgejo_scope.host),
                        }
                        .into());
                    }
                }
                None => {
                    if forgejo_scope.repos.is_empty() {
                        return Err(ServiceError::InsufficientScope {
                            requirement: format!(
                                "repository access. Configure at least one repository for host: {}",
                                forgejo_scope.host
                            ),
                        }
                        .into());
                    }
                }
            }
        }

        Ok(())
    }

    fn resolve_forgejo_host<'a>(
        &self,
        config: &'a ScopeConfig,
        repo: Option<&str>,
        host_hint: Option<&str>,
    ) -> Result<&'a ForgejoScope> {
        if config.forgejo.is_empty() {
            return Err(ServiceError::NoHostsConfigured { forge: "Forgejo" }.into());
        }

        // Priority 1: Use host hint if provided
        if let Some(hint) = host_hint {
            if let Some(scope) = config.forgejo.iter().find(|s| s.host == hint) {
                return Ok(scope);
            } else {
                return Err(ServiceError::HostNotFound {
                    forge: "Forgejo",
                    host: hint.to_string(),
                }
                .into());
            }
        }

        // Priority 2: Find scope with repo permissions
        if let Some(repo_path) = repo {
            for scope in &config.forgejo {
                if scope.is_read_allowed(repo_path) {
                    return Ok(scope);
                }
            }
            return Err(ServiceError::NoHostAccess {
                forge: "Forgejo",
                resource_kind: "repository",
                name: repo_path.to_string(),
            }
            .into());
        }

        // Priority 3: Use first configured scope
        Ok(&config.forgejo[0])
    }
}

impl CliServiceAdapter {
    pub async fn execute_api(
        &self,
        config: &ScopeConfig,
        endpoint: &str,
        method: &str,
        body: Option<Value>,
        jq: Option<&str>,
        context: Option<&ServiceContext>,
    ) -> Result<String> {
        // Check permissions first
        self.permission_checker
            .check_permission(config, endpoint, method, context)?;

        // Extract host for multi-host services
        let host = context.and_then(|c| c.host.as_deref());

        // Execute the CLI command
        self.cli.execute_api(endpoint, method, body, jq, host).await
    }
}

impl JiraServiceAdapter {
    pub async fn execute_api(
        &self,
        config: &ScopeConfig,
        endpoint: &str,
        method: &str,
        body: Option<Value>,
        jq: Option<&str>,
        _context: Option<&ServiceContext>,
    ) -> Result<String> {
        self.jira
            .execute_api(config, endpoint, method, body, jq)
            .await
    }
}

/// Service registry that provides unified access to all services.
#[derive(Clone)]
pub struct ServiceRegistry {
    github: ApiService,
    gitlab: ApiService,
    forgejo: ApiService,
    jira: ApiService,
}

impl ServiceRegistry {
    /// Create a new service registry.
    pub fn new() -> Self {
        Self {
            github: ApiService::GitHub(CliServiceAdapter {
                cli: services::GITHUB,
                permission_checker: PermissionChecker::GitHub,
            }),
            gitlab: ApiService::GitLab(CliServiceAdapter {
                cli: services::GITLAB,
                permission_checker: PermissionChecker::GitLab,
            }),
            forgejo: ApiService::Forgejo(CliServiceAdapter {
                cli: services::FORGEJO,
                permission_checker: PermissionChecker::Forgejo,
            }),
            jira: ApiService::Jira(JiraServiceAdapter {
                jira: JiraHttpService::new(),
            }),
        }
    }

    /// Get the GitHub API service.
    pub fn github_service(&self) -> ApiService {
        self.github.clone()
    }

    /// Get the GitLab API service.
    pub fn gitlab_service(&self) -> ApiService {
        self.gitlab.clone()
    }

    /// Get the Forgejo API service.
    pub fn forgejo_service(&self) -> ApiService {
        self.forgejo.clone()
    }

    /// Get the JIRA API service.
    pub fn jira_service(&self) -> ApiService {
        self.jira.clone()
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{GhRepoPermission, GlProjectPermission};
    use std::collections::HashMap;

    // =========================================================================
    // PermissionChecker Tests
    // =========================================================================

    /// Downcast an eyre::Error to ServiceError for typed assertions.
    fn downcast_service_error(err: eyre::Error) -> ServiceError {
        err.downcast::<ServiceError>()
            .expect("expected a ServiceError")
    }

    fn make_github_config_with_repos(repos: Vec<(&str, GhRepoPermission)>) -> ScopeConfig {
        let mut config = ScopeConfig::default();
        for (repo, perm) in repos {
            config.gh.repos.insert(repo.to_string(), perm);
        }
        config
    }

    fn make_gitlab_config_with_projects(projects: Vec<(&str, GlProjectPermission)>) -> ScopeConfig {
        let mut config = ScopeConfig::default();
        for (project, perm) in projects {
            config.gitlab.projects.insert(project.to_string(), perm);
        }
        config
    }

    #[test]
    fn test_permission_checker_github_read_allowed() {
        let checker = PermissionChecker::GitHub;
        let config =
            make_github_config_with_repos(vec![("owner/repo", GhRepoPermission::read_only())]);

        // Read should be allowed for configured repo
        let result = checker.check_permission(&config, "repos/owner/repo", "GET", None);
        assert!(result.is_ok(), "Expected read to be allowed");
    }

    #[test]
    fn test_permission_checker_github_read_denied() {
        let checker = PermissionChecker::GitHub;
        let config =
            make_github_config_with_repos(vec![("owner/repo", GhRepoPermission::read_only())]);

        let err = checker
            .check_permission(&config, "repos/other/repo", "GET", None)
            .unwrap_err();
        assert!(
            matches!(
                downcast_service_error(err),
                ServiceError::ReadDenied {
                    resource_kind: "repository",
                    ..
                }
            ),
            "Expected ReadDenied for repository"
        );
    }

    #[test]
    fn test_permission_checker_github_write_denied_without_permission() {
        let checker = PermissionChecker::GitHub;
        let config =
            make_github_config_with_repos(vec![("owner/repo", GhRepoPermission::read_only())]);

        let err = checker
            .check_permission(&config, "repos/owner/repo/issues", "POST", None)
            .unwrap_err();
        assert!(
            matches!(
                downcast_service_error(err),
                ServiceError::WriteDenied {
                    resource_kind: "repository",
                    ..
                }
            ),
            "Expected WriteDenied for repository"
        );
    }

    #[test]
    fn test_permission_checker_github_write_allowed_with_permission() {
        let checker = PermissionChecker::GitHub;
        let config =
            make_github_config_with_repos(vec![("owner/repo", GhRepoPermission::full_write())]);

        // Write should be allowed for repos with write permission
        let result = checker.check_permission(&config, "repos/owner/repo/issues", "POST", None);
        assert!(result.is_ok(), "Expected write to be allowed");
    }

    #[test]
    fn test_permission_checker_github_graphql_read_denied_by_default() {
        let checker = PermissionChecker::GitHub;
        let config =
            make_github_config_with_repos(vec![("owner/repo", GhRepoPermission::read_only())]);

        // GraphQL read should be denied by default
        let result = checker.check_permission(&config, "graphql", "GET", None);
        assert!(
            result.is_err(),
            "Expected GraphQL read to be denied by default"
        );
    }

    #[test]
    fn test_permission_checker_github_graphql_write_always_denied() {
        let checker = PermissionChecker::GitHub;
        let mut config = ScopeConfig::default();
        config.gh.read = true; // Enable global read

        let err = checker
            .check_permission(&config, "graphql", "POST", None)
            .unwrap_err();
        assert!(
            matches!(
                downcast_service_error(err),
                ServiceError::GraphQlMutationDenied
            ),
            "Expected GraphQlMutationDenied"
        );
    }

    #[test]
    fn test_permission_checker_github_global_read() {
        let checker = PermissionChecker::GitHub;
        let mut config = ScopeConfig::default();
        config.gh.read = true; // Enable global read

        // Any read should be allowed with global read
        let result = checker.check_permission(&config, "repos/any/repo", "GET", None);
        assert!(result.is_ok(), "Expected global read to allow any repo");

        // Non-repo endpoints should also work
        let result = checker.check_permission(&config, "user", "GET", None);
        assert!(
            result.is_ok(),
            "Expected global read to allow user endpoint"
        );
    }

    #[test]
    fn test_permission_checker_github_non_repo_endpoint_denied() {
        let checker = PermissionChecker::GitHub;
        let config =
            make_github_config_with_repos(vec![("owner/repo", GhRepoPermission::read_only())]);

        // Non-repo endpoints should be denied without global read
        let result = checker.check_permission(&config, "user", "GET", None);
        assert!(result.is_err(), "Expected non-repo endpoint to be denied");
    }

    #[test]
    fn test_permission_checker_gitlab_read_allowed() {
        let checker = PermissionChecker::GitLab;
        let config = make_gitlab_config_with_projects(vec![(
            "group/project",
            GlProjectPermission::read_only(),
        )]);

        // Read should be allowed for configured project
        let result = checker.check_permission(&config, "projects/group%2Fproject", "GET", None);
        assert!(result.is_ok(), "Expected read to be allowed");
    }

    #[test]
    fn test_permission_checker_gitlab_write_denied() {
        let checker = PermissionChecker::GitLab;
        let config = make_gitlab_config_with_projects(vec![(
            "group/project",
            GlProjectPermission::read_only(),
        )]);

        // Write should be denied for read-only projects
        let result =
            checker.check_permission(&config, "projects/group%2Fproject/issues", "POST", None);
        assert!(result.is_err(), "Expected write to be denied");
    }

    // =========================================================================
    // ServiceRegistry Tests
    // =========================================================================

    #[test]
    fn test_service_registry_individual_services() {
        let registry = ServiceRegistry::new();

        // Verify each service returns the correct variant
        assert!(
            matches!(registry.github_service(), ApiService::GitHub(_)),
            "github_service should return GitHub variant"
        );
        assert!(
            matches!(registry.gitlab_service(), ApiService::GitLab(_)),
            "gitlab_service should return GitLab variant"
        );
        assert!(
            matches!(registry.forgejo_service(), ApiService::Forgejo(_)),
            "forgejo_service should return Forgejo variant"
        );
        assert!(
            matches!(registry.jira_service(), ApiService::Jira(_)),
            "jira_service should return Jira variant"
        );
    }

    // =========================================================================
    // PermissionChecker Forgejo Tests
    // =========================================================================

    #[test]
    fn test_permission_checker_forgejo_no_hosts_configured() {
        let checker = PermissionChecker::Forgejo;
        let config = ScopeConfig::default(); // No forgejo hosts

        let err = checker
            .check_permission(&config, "repos/owner/repo", "GET", None)
            .unwrap_err();
        assert!(
            matches!(
                downcast_service_error(err),
                ServiceError::NoHostsConfigured { forge: "Forgejo" }
            ),
            "Expected NoHostsConfigured for Forgejo"
        );
    }

    #[test]
    fn test_permission_checker_forgejo_with_host() {
        let checker = PermissionChecker::Forgejo;
        let mut config = ScopeConfig::default();

        let mut repos = HashMap::new();
        repos.insert(
            "owner/repo".to_string(),
            crate::scope::ForgejoRepoPermission::read_only(),
        );

        config.forgejo.push(ForgejoScope {
            host: "codeberg.org".to_string(),
            token: None,
            repos,
            prs: HashMap::new(),
            issues: HashMap::new(),
        });

        // Should work with host hint in context
        let context = ServiceContext {
            host: Some("codeberg.org".to_string()),
            params: HashMap::new(),
        };
        let result = checker.check_permission(&config, "repos/owner/repo", "GET", Some(&context));
        assert!(result.is_ok(), "Expected read to be allowed: {:?}", result);
    }

    // =========================================================================
    // ServiceContext Tests
    // =========================================================================

    #[test]
    fn test_service_context_with_host() {
        let context = ServiceContext {
            host: Some("example.com".to_string()),
            params: HashMap::new(),
        };

        assert_eq!(context.host, Some("example.com".to_string()));
        assert!(context.params.is_empty());
    }

    #[test]
    fn test_service_context_with_params() {
        let mut params = HashMap::new();
        params.insert("key1".to_string(), "value1".to_string());
        params.insert("key2".to_string(), "value2".to_string());

        let context = ServiceContext { host: None, params };

        assert!(context.host.is_none());
        assert_eq!(context.params.get("key1"), Some(&"value1".to_string()));
        assert_eq!(context.params.get("key2"), Some(&"value2".to_string()));
    }
}
