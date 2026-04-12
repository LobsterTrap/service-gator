//! JIRA HTTP service for REST API requests.
//!
//! This module provides a simplified JIRA service that wraps the existing
//! JIRA client logic from the codebase, providing HTTP-based API access.

use eyre::{bail, Context, Result};
use serde_json::Value;
use tracing::info;

use crate::jira_client::JiraClient;
use crate::jira_types::JiraProjectKey;
use crate::scope::{OpType, ScopeConfig};

/// Build JQL scoped to specific projects.
///
/// Prepends a `project = X` or `project in (X, Y)` filter to the user-provided
/// JQL, ensuring results are restricted to authorized projects regardless of
/// what the user JQL contains.
pub fn build_scoped_jql(projects: &[JiraProjectKey], user_jql: &str) -> String {
    let project_filter = if projects.len() == 1 {
        format!("project = {}", projects[0])
    } else {
        let keys: Vec<&str> = projects.iter().map(|p| p.as_str()).collect();
        format!("project in ({})", keys.join(", "))
    };

    if user_jql.is_empty() {
        project_filter
    } else {
        format!("({}) AND ({})", project_filter, user_jql)
    }
}

/// HTTP-based JIRA API service.
#[derive(Clone, Debug, Default)]
pub struct JiraHttpService;

impl JiraHttpService {
    /// Create a new JIRA HTTP service.
    pub fn new() -> Self {
        Self
    }

    /// Execute a JIRA API request using HTTP.
    pub async fn execute_api(
        &self,
        config: &ScopeConfig,
        endpoint: &str,
        method: &str,
        body: Option<Value>,
        _jq: Option<&str>, // JIRA doesn't support jq filtering like CLI tools
    ) -> Result<String> {
        // Determine operation type based on method
        let _is_write = method != "GET" && method != "HEAD";

        // For now, route to specific methods based on endpoint patterns
        // This maintains compatibility with existing JIRA service functionality
        match (method, endpoint) {
            ("GET", "/rest/api/2/myself") => self.get_myself(config).await,
            ("GET", path) if path.starts_with("/rest/api/2/project/") => {
                let project_key = path.trim_start_matches("/rest/api/2/project/");
                self.get_project(config, project_key).await
            }
            ("GET", "/rest/api/2/project") => self.list_projects(config).await,
            ("POST", "/rest/api/2/search") => {
                let jql = body
                    .as_ref()
                    .and_then(|b| b.get("jql"))
                    .and_then(|j| j.as_str())
                    .unwrap_or("");
                let projects: Vec<String> = body
                    .as_ref()
                    .and_then(|b| b.get("projects"))
                    .and_then(|p| p.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                self.search_issues(config, jql, &projects).await
            }
            _ => {
                // Generic HTTP request for other endpoints
                let response = self
                    .make_http_request(config, method, endpoint, body)
                    .await?;
                Ok(serde_json::to_string_pretty(&response)?)
            }
        }
    }

    /// Get current user information.
    async fn get_myself(&self, config: &ScopeConfig) -> Result<String> {
        // Check basic read permission
        if !config.jira.has_any_read_access() {
            return Err(super::ServiceError::InsufficientScope {
                requirement: "JIRA read access".to_string(),
            }
            .into());
        }

        info!(operation = "jira_myself", "getting current user");

        let user_response = self
            .make_http_request(config, "GET", "/rest/api/2/myself", None)
            .await?;

        Ok(serde_json::to_string_pretty(&user_response)?)
    }

    /// List accessible projects.
    async fn list_projects(&self, config: &ScopeConfig) -> Result<String> {
        let client = self.create_client(config).await?;

        if !config.jira.has_any_read_access() {
            return Err(super::ServiceError::InsufficientScope {
                requirement: "JIRA read access".to_string(),
            }
            .into());
        }

        info!(operation = "jira_list_projects", "listing projects");

        let _projects = client.list_projects().await?;
        // Return placeholder for now
        let result = serde_json::json!({
            "projects": [],
            "message": "Projects endpoint placeholder"
        });

        Ok(serde_json::to_string_pretty(&result)?)
    }

    /// Get project information.
    async fn get_project(&self, config: &ScopeConfig, project_key: &str) -> Result<String> {
        if !config.jira.is_allowed(project_key, OpType::Read, None) {
            return Err(super::ServiceError::ReadDenied {
                resource_kind: "project",
                name: project_key.to_string(),
            }
            .into());
        }

        info!(
            operation = "jira_get_project",
            project = project_key,
            "getting project info"
        );

        let endpoint = format!("/rest/api/2/project/{}", project_key);
        let project_response = self
            .make_http_request(config, "GET", &endpoint, None)
            .await?;

        Ok(serde_json::to_string_pretty(&project_response)?)
    }

    /// Search issues using JQL.
    ///
    /// Requires explicit project keys in the request body for authorization.
    /// The JQL sent to JIRA is prepended with a `project in (...)` filter
    /// scoped to the authorized projects.
    async fn search_issues(
        &self,
        config: &ScopeConfig,
        jql: &str,
        projects: &[String],
    ) -> Result<String> {
        if projects.is_empty() {
            return Err(super::ServiceError::InvalidInput(
                "Search requires explicit project(s) in the request body. \
                 Use {\"projects\": [\"PROJ\"], \"jql\": \"...\"}"
                    .to_string(),
            )
            .into());
        }

        // Validate each project as a proper JiraProjectKey before building JQL.
        // This is defense-in-depth: is_allowed() also validates internally, but
        // we must not interpolate unvalidated strings into JQL.
        let validated_keys: Vec<JiraProjectKey> = projects
            .iter()
            .map(|p| {
                p.parse::<JiraProjectKey>()
                    .map_err(|e| eyre::eyre!("Invalid project key '{}': {}", p, e))
            })
            .collect::<Result<Vec<_>>>()?;

        for key in &validated_keys {
            if !config.jira.is_allowed(key.as_str(), OpType::Read, None) {
                return Err(super::ServiceError::ReadDenied {
                    resource_kind: "project",
                    name: key.to_string(),
                }
                .into());
            }
        }

        let effective_jql = build_scoped_jql(&validated_keys, jql);

        info!(
            operation = "jira_search",
            jql = %effective_jql,
            projects = ?projects,
            "searching issues"
        );

        let _client = self.create_client(config).await?;
        let result = serde_json::json!({
            "jql": effective_jql,
            "issues": [],
            "total": 0,
            "projects": projects
        });

        Ok(serde_json::to_string_pretty(&result)?)
    }

    /// Create a JIRA client instance.
    async fn create_client(&self, config: &ScopeConfig) -> Result<JiraClient> {
        // For now, create a basic client - we'll need to implement from_config or use existing methods
        if let Some(host) = &config.jira.host {
            if let Some(username) = &config.jira.username {
                if let Some(token) = &config.jira.token {
                    return JiraClient::new(host, username, token.expose_secret())
                        .context("Failed to create JIRA client");
                }
            }
            // Try bearer token
            if let Some(token) = &config.jira.token {
                return JiraClient::with_bearer_token(host, token.expose_secret())
                    .context("Failed to create JIRA client");
            }
        }
        bail!("JIRA configuration missing required fields: host and token")
    }

    /// Make a generic HTTP request to JIRA API.
    async fn make_http_request(
        &self,
        config: &ScopeConfig,
        method: &str,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        // Create client and use its HTTP capabilities
        let _client = self.create_client(config).await?;

        // For now, we'll use the client's built-in methods where possible
        // This is a simplified implementation - a full HTTP client could be added here
        match (method, endpoint) {
            ("GET", "/rest/api/2/myself") => {
                // Use the existing client method if available
                Ok(serde_json::json!({
                    "message": "JIRA HTTP endpoint not fully implemented yet",
                    "method": method,
                    "endpoint": endpoint
                }))
            }
            _ => Ok(serde_json::json!({
                "message": "Generic JIRA HTTP endpoint",
                "method": method,
                "endpoint": endpoint,
                "body": body
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::JiraProjectPermission;
    use crate::services::ServiceError;

    fn make_jira_config_with_projects(projects: Vec<(&str, JiraProjectPermission)>) -> ScopeConfig {
        let mut config = ScopeConfig::default();
        for (project, perm) in projects {
            config.jira.projects.insert(project.parse().unwrap(), perm);
        }
        config
    }

    // =========================================================================
    // JiraHttpService Tests
    // =========================================================================

    #[test]
    fn test_jira_http_service_new() {
        let service = JiraHttpService::new();
        // Just verify it can be created (it's a unit struct)
        let _ = service;
    }

    // =========================================================================
    // Search Authorization Tests
    // =========================================================================

    #[tokio::test]
    async fn test_search_requires_explicit_projects() {
        let service = JiraHttpService::new();
        let config =
            make_jira_config_with_projects(vec![("PROJ", JiraProjectPermission::read_only())]);

        let err = service
            .search_issues(&config, "status = Open", &[])
            .await
            .unwrap_err();
        assert!(
            err.downcast_ref::<ServiceError>()
                .is_some_and(|e| matches!(e, ServiceError::InvalidInput(_))),
            "Expected InvalidInput, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_search_denied_for_unauthorized_project() {
        let service = JiraHttpService::new();
        let config =
            make_jira_config_with_projects(vec![("PROJ", JiraProjectPermission::read_only())]);

        let err = service
            .search_issues(&config, "status = Open", &["OTHER".to_string()])
            .await
            .unwrap_err();
        assert!(
            err.downcast_ref::<ServiceError>()
                .is_some_and(|e| matches!(e, ServiceError::ReadDenied { .. })),
            "Expected ReadDenied, got: {}",
            err
        );
    }

    // =========================================================================
    // Permission Check Tests
    // =========================================================================

    #[test]
    fn test_jira_config_has_any_read_access() {
        let config =
            make_jira_config_with_projects(vec![("PROJ", JiraProjectPermission::read_only())]);

        assert!(config.jira.has_any_read_access(), "Should have read access");
    }

    #[test]
    fn test_jira_config_no_read_access() {
        let config = ScopeConfig::default();

        assert!(
            !config.jira.has_any_read_access(),
            "Should not have read access"
        );
    }

    #[test]
    fn test_jira_is_allowed_read() {
        let config =
            make_jira_config_with_projects(vec![("PROJ", JiraProjectPermission::read_only())]);

        assert!(config.jira.is_allowed("PROJ", OpType::Read, None));
        assert!(!config.jira.is_allowed("OTHER", OpType::Read, None));
    }

    #[test]
    fn test_jira_is_allowed_write() {
        let mut perm = JiraProjectPermission::read_only();
        perm.write = true;

        let config = make_jira_config_with_projects(vec![("PROJ", perm)]);

        assert!(config.jira.is_allowed("PROJ", OpType::Write, None));
    }

    #[test]
    fn test_jira_is_allowed_comment() {
        let perm = JiraProjectPermission {
            comment: true,
            ..Default::default()
        };
        let config = make_jira_config_with_projects(vec![("PROJ", perm)]);

        // comment implies read
        assert!(config.jira.is_allowed("PROJ", OpType::Read, None));
        assert!(config.jira.is_allowed("PROJ", OpType::Comment, None));
        // comment does not imply create or write
        assert!(!config.jira.is_allowed("PROJ", OpType::Create, None));
        assert!(!config.jira.is_allowed("PROJ", OpType::Write, None));
    }

    #[test]
    fn test_jira_is_allowed_create() {
        let perm = JiraProjectPermission {
            create: true,
            ..Default::default()
        };
        let config = make_jira_config_with_projects(vec![("PROJ", perm)]);

        // create implies read
        assert!(config.jira.is_allowed("PROJ", OpType::Read, None));
        assert!(config.jira.is_allowed("PROJ", OpType::Create, None));
        // create does not imply comment or write
        assert!(!config.jira.is_allowed("PROJ", OpType::Comment, None));
        assert!(!config.jira.is_allowed("PROJ", OpType::Write, None));
    }

    #[test]
    fn test_jira_write_implies_all() {
        let perm = JiraProjectPermission {
            write: true,
            ..Default::default()
        };
        let config = make_jira_config_with_projects(vec![("PROJ", perm)]);

        assert!(config.jira.is_allowed("PROJ", OpType::Read, None));
        assert!(config.jira.is_allowed("PROJ", OpType::Comment, None));
        assert!(config.jira.is_allowed("PROJ", OpType::Create, None));
        assert!(config.jira.is_allowed("PROJ", OpType::Write, None));
    }

    #[test]
    fn test_jira_global_read() {
        let mut config = ScopeConfig::default();
        config.jira.global_read = true;

        // global_read allows reading any project
        assert!(config.jira.is_allowed("ANYPROJ", OpType::Read, None));
        assert!(config.jira.has_any_read_access());
        // but not comment/create/write
        assert!(!config.jira.is_allowed("ANYPROJ", OpType::Comment, None));
        assert!(!config.jira.is_allowed("ANYPROJ", OpType::Create, None));
        assert!(!config.jira.is_allowed("ANYPROJ", OpType::Write, None));
    }

    #[test]
    fn test_jira_global_read_with_project_override() {
        let mut config = ScopeConfig::default();
        config.jira.global_read = true;
        config.jira.projects.insert(
            "PROJ".parse().unwrap(),
            JiraProjectPermission {
                comment: true,
                ..Default::default()
            },
        );

        // PROJ gets comment from explicit config
        assert!(config.jira.is_allowed("PROJ", OpType::Comment, None));
        // OTHER gets read from global_read but not comment
        assert!(config.jira.is_allowed("OTHER", OpType::Read, None));
        assert!(!config.jira.is_allowed("OTHER", OpType::Comment, None));
    }
}
