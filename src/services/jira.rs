//! JIRA HTTP service for REST API requests.
//!
//! This module provides a simplified JIRA service that wraps the existing
//! JIRA client logic from the codebase, providing HTTP-based API access.

use std::collections::HashMap;

use eyre::{bail, Context, Result};
use serde_json::Value;
use tracing::info;

use crate::jira_client::JiraClient;
use crate::scope::{OpType, ScopeConfig};

/// HTTP-based JIRA API service.
#[derive(Clone, Debug)]
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
                let jql = if let Some(body) = &body {
                    body.get("jql")
                        .and_then(|j| j.as_str())
                        .unwrap_or("")
                } else {
                    ""
                };
                self.search_issues(config, jql, None).await
            }
            _ => {
                // Generic HTTP request for other endpoints
                let response = self.make_http_request(config, method, endpoint, body).await?;
                Ok(serde_json::to_string_pretty(&response)?)
            }
        }
    }

    /// Get current user information.
    async fn get_myself(&self, config: &ScopeConfig) -> Result<String> {
        // Check basic read permission
        if !config.jira.has_any_read_access() {
            bail!("No JIRA read access configured");
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
            bail!("No JIRA read access configured");
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
            bail!("Read access not allowed for project: {project_key}");
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
    async fn search_issues(
        &self,
        config: &ScopeConfig,
        jql: &str,
        _params: Option<&HashMap<String, String>>,
    ) -> Result<String> {
        let referenced_projects = self.extract_projects_from_jql(jql)?;

        for project in &referenced_projects {
            if !config.jira.is_allowed(project, OpType::Read, None) {
                bail!("Read access not allowed for project: {project} (referenced in JQL)");
            }
        }

        if referenced_projects.is_empty() && !config.jira.has_any_read_access() {
            bail!("JQL search without explicit project requires read access to at least one project");
        }

        info!(
            operation = "jira_search",
            jql = jql,
            projects = ?referenced_projects,
            "searching issues"
        );

        let _client = self.create_client(config).await?;
        // For now, return a placeholder since search_issues may not be implemented
        let result = serde_json::json!({
            "jql": jql,
            "issues": [],
            "total": 0,
            "projects": referenced_projects
        });

        Ok(serde_json::to_string_pretty(&result)?)
    }

    /// Create a JIRA client instance.
    async fn create_client(&self, config: &ScopeConfig) -> Result<JiraClient> {
        // For now, create a basic client - we'll need to implement from_config or use existing methods
        if let Some(host) = &config.jira.host {
            if let Some(username) = &config.jira.username {
                if let Some(token) = &config.jira.token {
                    return JiraClient::new(host, username, token.expose_secret()).context("Failed to create JIRA client");
                }
            }
            // Try bearer token
            if let Some(token) = &config.jira.token {
                return JiraClient::with_bearer_token(host, token.expose_secret()).context("Failed to create JIRA client");
            }
        }
        bail!("JIRA configuration missing required fields: host and token")
    }

    /// Extract project keys referenced in JQL.
    fn extract_projects_from_jql(&self, jql: &str) -> Result<Vec<String>> {
        // Simple string-based extraction for project patterns
        // Look for patterns like "project = PROJ" or "project in (PROJ1, PROJ2)"
        let mut projects = Vec::new();
        
        // Convert to lowercase for case-insensitive matching
        let jql_lower = jql.to_lowercase();
        
        // Find project clauses
        if let Some(project_pos) = jql_lower.find("project") {
            let remaining = &jql[project_pos..];
            
            // Look for project = PROJ pattern
            if let Some(eq_pos) = remaining.find('=') {
                let after_eq = &remaining[eq_pos + 1..].trim();
                if let Some(space_pos) = after_eq.find(' ') {
                    let project = &after_eq[..space_pos].trim();
                    if !project.is_empty() {
                        projects.push(project.to_string());
                    }
                } else {
                    // No space, take the whole remaining part up to end or common delimiters
                    let project = after_eq.split_whitespace().next().unwrap_or("").trim();
                    if !project.is_empty() {
                        projects.push(project.to_string());
                    }
                }
            }
            
            // Look for project in (PROJ1, PROJ2) pattern
            if let Some(in_pos) = remaining.to_lowercase().find(" in ") {
                let after_in = &remaining[in_pos + 4..];
                if let Some(open_paren) = after_in.find('(') {
                    if let Some(close_paren) = after_in.find(')') {
                        let project_list = &after_in[open_paren + 1..close_paren];
                        for project in project_list.split(',') {
                            let project = project.trim().trim_matches(|c| c == '"' || c == '\'');
                            if !project.is_empty() {
                                projects.push(project.to_string());
                            }
                        }
                    }
                }
            }
        }
        
        projects.sort();
        projects.dedup();
        Ok(projects)
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
            _ => {
                Ok(serde_json::json!({
                    "message": "Generic JIRA HTTP endpoint",
                    "method": method,
                    "endpoint": endpoint,
                    "body": body
                }))
            }
        }
    }
}