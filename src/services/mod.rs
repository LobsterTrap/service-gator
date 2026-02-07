//! Unified service layer for service-gator.
//!
//! This module provides a simplified service architecture that eliminates code
//! duplication by using generic CLI services and a centralized service registry.

pub mod cli;
pub mod jira;

use eyre::{bail, Result};
use serde_json::Value;
use tracing::info;

use self::cli::{services, CliService};
use self::jira::JiraHttpService;
use crate::scope::{ForgejoScope, ScopeConfig};

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
                bail!(
                    "GraphQL mutations are not supported via api operation. Use dedicated tools."
                );
            }
            if !config.gh.graphql_read_allowed() {
                bail!("GraphQL read access not allowed. Set `read = true` or `graphql = \"read\"` in [gh] config.");
            }
            return Ok(());
        }

        let repo = extract_repo_from_api_path(endpoint);
        let resource_ref = extract_resource_from_api_path(endpoint);

        if is_write {
            let repo = repo.ok_or_else(|| {
                eyre::eyre!("Write operations require a repository path. Use path like repos/owner/repo/...")
            })?;

            if !config
                .gh
                .is_allowed(&repo, GhOpType::WriteResource, resource_ref.as_deref())
            {
                let scope_msg = if let Some(ref res) = resource_ref {
                    format!(" (resource: {})", res)
                } else {
                    String::new()
                };
                bail!("Write access not allowed for repository: {repo}{scope_msg}");
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
                        bail!("Read access not allowed for repository: {repo}");
                    }
                }
                None => {
                    if !config.gh.global_read_allowed() {
                        bail!("This endpoint requires global read access. Set `read = true` in [gh] config, or use /repos/owner/repo/... paths.");
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
                bail!(
                    "GraphQL mutations are not supported via api operation. Use dedicated tools."
                );
            }
            if !config.gitlab.graphql_read_allowed() {
                bail!(
                    "GraphQL read access not allowed. Set `graphql = \"read\"` in [gitlab] config."
                );
            }
            return Ok(());
        }

        let project = extract_project_from_api_path(endpoint);

        if is_write {
            let project = project.ok_or_else(|| {
                eyre::eyre!("Write operations require a project path. Use path like /api/v4/projects/group%2Fproject/...")
            })?;

            if !config
                .gitlab
                .is_allowed(&project, GlOpType::WriteResource, None)
            {
                bail!("Write access not allowed for project: {project}");
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
                        bail!("Read access not allowed for project: {project}");
                    }
                }
                None => {
                    // For GitLab, check if user has any project access
                    if config.gitlab.projects.is_empty() {
                        bail!("This endpoint requires project access. Configure at least one project in [gitlab.projects] config.");
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
            let repo = repo.ok_or_else(|| {
                eyre::eyre!("Write operations require a repository path. Use path like /api/v1/repos/owner/repo/...")
            })?;

            if !forgejo_scope.is_allowed(&repo, ForgejoOpType::WriteResource, None) {
                bail!(
                    "Write access not allowed for repository: {repo} on host: {}",
                    forgejo_scope.host
                );
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
                        bail!(
                            "Read access not allowed for repository: {repo} on host: {}",
                            forgejo_scope.host
                        );
                    }
                }
                None => {
                    if forgejo_scope.repos.is_empty() {
                        bail!("This endpoint requires repository access. Configure at least one repository for host: {}", forgejo_scope.host);
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
            bail!("No Forgejo hosts configured");
        }

        // Priority 1: Use host hint if provided
        if let Some(hint) = host_hint {
            if let Some(scope) = config.forgejo.iter().find(|s| s.host == hint) {
                return Ok(scope);
            } else {
                bail!("Host '{}' not found in Forgejo configuration", hint);
            }
        }

        // Priority 2: Find scope with repo permissions
        if let Some(repo_path) = repo {
            for scope in &config.forgejo {
                if scope.is_read_allowed(repo_path) {
                    return Ok(scope);
                }
            }
            bail!(
                "No configured Forgejo host has access to repository: {}",
                repo_path
            );
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

    /// Get the appropriate service for an API path with service-aware routing.
    pub fn get_service(&self, api_path: &str) -> Option<(&ApiService, &'static str)> {
        // GitHub uses /api/v3 prefix
        if api_path.starts_with("/api/v3") {
            Some((&self.github, "/api/v3/"))
        }
        // GitLab uses /api/v4 prefix
        else if api_path.starts_with("/api/v4") {
            Some((&self.gitlab, "/api/v4/"))
        }
        // Forgejo/Gitea uses /api/v1 prefix
        else if api_path.starts_with("/api/v1") {
            Some((&self.forgejo, "/api/v1/"))
        }
        // JIRA uses /rest/api/2/ or /rest/api/ prefix
        else if api_path.starts_with("/rest/api/2/") {
            Some((&self.jira, "/rest/api/2/"))
        }
        else if api_path.starts_with("/rest/api/") {
            Some((&self.jira, "/rest/api/"))
        }
        else {
            None
        }
    }

    /// Get the appropriate service for an API path (legacy method for compatibility).
    pub fn get_service_legacy(&self, api_path: &str) -> Option<&ApiService> {
        self.get_service(api_path).map(|(service, _)| service)
    }

    /// Get service by name.
    pub fn get_service_by_name(&self, name: &str) -> Option<&ApiService> {
        match name {
            "github" => Some(&self.github),
            "gitlab" => Some(&self.gitlab),
            "forgejo" | "gitea" => Some(&self.forgejo),
            "jira" => Some(&self.jira),
            _ => None,
        }
    }

    /// Get the GitHub service directly.
    ///
    /// Used for github.localhost compatibility where paths don't have /api/v3 prefix.
    pub fn github(&self) -> &ApiService {
        &self.github
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

        // Read should be denied for unconfigured repo
        let result = checker.check_permission(&config, "repos/other/repo", "GET", None);
        assert!(result.is_err(), "Expected read to be denied");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not allowed"),
            "Error should mention access not allowed: {}",
            err
        );
    }

    #[test]
    fn test_permission_checker_github_write_denied_without_permission() {
        let checker = PermissionChecker::GitHub;
        let config =
            make_github_config_with_repos(vec![("owner/repo", GhRepoPermission::read_only())]);

        // Write (POST) should be denied for read-only repos
        let result = checker.check_permission(&config, "repos/owner/repo/issues", "POST", None);
        assert!(result.is_err(), "Expected write to be denied");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Write access not allowed"),
            "Error should mention write not allowed: {}",
            err
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

        // GraphQL write (mutation) should always be denied
        let result = checker.check_permission(&config, "graphql", "POST", None);
        assert!(result.is_err(), "Expected GraphQL write to be denied");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("mutations"),
            "Error should mention mutations: {}",
            err
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
    fn test_service_registry_get_service_github() {
        let registry = ServiceRegistry::new();

        let result = registry.get_service("/api/v3/repos/owner/repo");
        assert!(
            result.is_some(),
            "Expected GitHub service for /api/v3 path"
        );
        let (_, prefix) = result.unwrap();
        assert_eq!(prefix, "/api/v3/", "Expected GitHub API prefix");
    }

    #[test]
    fn test_service_registry_get_service_gitlab() {
        let registry = ServiceRegistry::new();

        let result = registry.get_service("/api/v4/projects/123");
        assert!(
            result.is_some(),
            "Expected GitLab service for /api/v4 path"
        );
        let (_, prefix) = result.unwrap();
        assert_eq!(prefix, "/api/v4/", "Expected GitLab API prefix");
    }

    #[test]
    fn test_service_registry_get_service_forgejo() {
        let registry = ServiceRegistry::new();

        let result = registry.get_service("/api/v1/repos/owner/repo");
        assert!(
            result.is_some(),
            "Expected Forgejo service for /api/v1 path"
        );
        let (_, prefix) = result.unwrap();
        assert_eq!(prefix, "/api/v1/", "Expected Forgejo API prefix");
    }

    #[test]
    fn test_service_registry_get_service_jira() {
        let registry = ServiceRegistry::new();

        let result = registry.get_service("/rest/api/2/issue/PROJ-123");
        assert!(
            result.is_some(),
            "Expected JIRA service for /rest/api/2 path"
        );
        let (_, prefix) = result.unwrap();
        assert_eq!(prefix, "/rest/api/2/", "Expected JIRA API v2 prefix");
    }

    #[test]
    fn test_service_registry_get_service_jira_legacy() {
        let registry = ServiceRegistry::new();

        let result = registry.get_service("/rest/api/issue/PROJ-123");
        assert!(
            result.is_some(),
            "Expected JIRA service for /rest/api path"
        );
        let (_, prefix) = result.unwrap();
        assert_eq!(prefix, "/rest/api/", "Expected JIRA API legacy prefix");
    }

    #[test]
    fn test_service_registry_get_service_unknown() {
        let registry = ServiceRegistry::new();

        let result = registry.get_service("/unknown/path");
        assert!(result.is_none(), "Expected None for unknown path");
    }

    #[test]
    fn test_service_registry_get_service_by_name() {
        let registry = ServiceRegistry::new();

        assert!(registry.get_service_by_name("github").is_some());
        assert!(registry.get_service_by_name("gitlab").is_some());
        assert!(registry.get_service_by_name("forgejo").is_some());
        assert!(registry.get_service_by_name("gitea").is_some()); // alias for forgejo
        assert!(registry.get_service_by_name("jira").is_some());
        assert!(registry.get_service_by_name("unknown").is_none());
    }

    // =========================================================================
    // PermissionChecker Forgejo Tests
    // =========================================================================

    #[test]
    fn test_permission_checker_forgejo_no_hosts_configured() {
        let checker = PermissionChecker::Forgejo;
        let config = ScopeConfig::default(); // No forgejo hosts

        let result = checker.check_permission(&config, "repos/owner/repo", "GET", None);
        assert!(
            result.is_err(),
            "Expected error when no Forgejo hosts configured"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("No Forgejo hosts configured"),
            "Error: {}",
            err
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
