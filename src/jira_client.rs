//! Native JIRA API client for service-gator.
//!
//! This module provides a native Rust client for the JIRA API using gouqi,
//! replacing the need for the `jirust-cli` CLI wrapper.
//!
//! ## Security Model
//!
//! Operations are gated by the scope configuration:
//! - Read operations: list issues, view issues, search, list projects/versions
//! - Write operations: create issues, transition issues, assign issues

use eyre::{Context, Result};
use gouqi::r#async::Jira;
use gouqi::{
    AddComment, Credentials, Issue, Project, SearchOptions, SearchResults, TransitionOption,
    TransitionTriggerOptions, Version,
};

/// A JIRA API client for a specific host.
#[derive(Clone)]
pub struct JiraClient {
    jira: Jira,
    host: String,
}

/// Response from creating an issue - contains the key for fetching full details.
#[derive(Debug)]
pub struct CreatedIssue {
    pub id: String,
    pub key: String,
    pub url: String,
}

impl JiraClient {
    /// Create a new JIRA client.
    ///
    /// # Arguments
    /// - `host` - The JIRA server URL (e.g., "https://jira.example.com")
    /// - `username` - Username for basic auth (or email for cloud)
    /// - `token` - API token or password
    pub fn new(host: &str, username: &str, token: &str) -> Result<Self> {
        let credentials = Credentials::Basic(username.to_string(), token.to_string());
        let jira = Jira::new(host, credentials)
            .with_context(|| format!("creating JIRA client for {}", host))?;

        Ok(Self {
            jira,
            host: host.to_string(),
        })
    }

    /// Create a new JIRA client with bearer token authentication.
    pub fn with_bearer_token(host: &str, token: &str) -> Result<Self> {
        let credentials = Credentials::Bearer(token.to_string());
        let jira = Jira::new(host, credentials)
            .with_context(|| format!("creating JIRA client for {}", host))?;

        Ok(Self {
            jira,
            host: host.to_string(),
        })
    }

    /// Get the host this client is connected to.
    pub fn host(&self) -> &str {
        &self.host
    }

    // =========================================================================
    // Issue operations
    // =========================================================================

    /// List issues in a project.
    pub async fn list_issues(&self, project: &str) -> Result<SearchResults> {
        let jql = format!("project = {}", project);
        let options = SearchOptions::builder().validate(false).build();

        self.jira
            .search()
            .list(&jql, &options)
            .await
            .with_context(|| format!("listing issues in project {}", project))
    }

    /// Get a specific issue by key.
    pub async fn get_issue(&self, issue_key: &str) -> Result<Issue> {
        self.jira
            .issues()
            .get(issue_key)
            .await
            .with_context(|| format!("getting issue {}", issue_key))
    }

    /// Create a new issue.
    ///
    /// Returns the created issue's key and ID. To get full issue details,
    /// call `get_issue` with the returned key.
    pub async fn create_issue(
        &self,
        project: &str,
        summary: &str,
        description: Option<&str>,
        issue_type: Option<&str>,
    ) -> Result<CreatedIssue> {
        use gouqi::issues::CreateResponse;
        use serde::Serialize;

        // Minimal fields struct for issue creation - JIRA only requires project, issuetype, and summary
        #[derive(Serialize)]
        struct MinimalFields {
            project: ProjectKey,
            issuetype: IssueTypeName,
            summary: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,
        }

        #[derive(Serialize)]
        struct ProjectKey {
            key: String,
        }

        #[derive(Serialize)]
        struct IssueTypeName {
            name: String,
        }

        #[derive(Serialize)]
        struct CreateIssueRequest {
            fields: MinimalFields,
        }

        let issue_type_name = issue_type.unwrap_or("Task");

        let request = CreateIssueRequest {
            fields: MinimalFields {
                project: ProjectKey {
                    key: project.to_string(),
                },
                issuetype: IssueTypeName {
                    name: issue_type_name.to_string(),
                },
                summary: summary.to_string(),
                description: description.map(|s| s.to_string()),
            },
        };

        let response: CreateResponse = self
            .jira
            .post("api", "/issue", request)
            .await
            .with_context(|| format!("creating issue in project {}", project))?;

        Ok(CreatedIssue {
            id: response.id,
            key: response.key,
            url: response.url,
        })
    }

    /// Get available transitions for an issue.
    pub async fn get_transitions(&self, issue_key: &str) -> Result<Vec<TransitionOption>> {
        self.jira
            .transitions(issue_key)
            .list()
            .await
            .with_context(|| format!("getting transitions for {}", issue_key))
    }

    /// Transition an issue to a new state.
    pub async fn transition_issue(&self, issue_key: &str, transition_name: &str) -> Result<()> {
        // First, get available transitions
        let transitions = self.get_transitions(issue_key).await?;

        // Find the transition by name (case-insensitive)
        let transition = transitions
            .iter()
            .find(|t| t.name.eq_ignore_ascii_case(transition_name))
            .ok_or_else(|| {
                let available: Vec<_> = transitions.iter().map(|t| t.name.as_str()).collect();
                eyre::eyre!(
                    "transition '{}' not found. Available: {}",
                    transition_name,
                    available.join(", ")
                )
            })?;

        let trigger = TransitionTriggerOptions::new(&transition.id);

        self.jira
            .transitions(issue_key)
            .trigger(trigger)
            .await
            .with_context(|| format!("transitioning {} to {}", issue_key, transition_name))
    }

    /// Assign an issue to a user.
    ///
    /// Pass `None` to unassign the issue.
    pub async fn assign_issue(&self, issue_key: &str, assignee: Option<&str>) -> Result<()> {
        self.jira
            .issues()
            .assign(issue_key, assignee.map(|s| s.to_string()))
            .await
            .with_context(|| match assignee {
                Some(user) => format!("assigning {} to {}", issue_key, user),
                None => format!("unassigning {}", issue_key),
            })
    }

    /// Add a comment to a JIRA issue.
    pub async fn add_comment(&self, issue_key: &str, body: &str) -> Result<()> {
        self.jira
            .issues()
            .comment(issue_key, AddComment::new(body))
            .await
            .with_context(|| format!("adding comment to {}", issue_key))?;
        Ok(())
    }

    // =========================================================================
    // Search operations
    // =========================================================================

    /// Search issues using JQL.
    pub async fn search(&self, jql: &str) -> Result<SearchResults> {
        let options = SearchOptions::builder().validate(false).build();

        self.jira
            .search()
            .list(jql, &options)
            .await
            .with_context(|| format!("searching with JQL: {}", jql))
    }

    // =========================================================================
    // Project operations
    // =========================================================================

    /// List all accessible projects.
    pub async fn list_projects(&self) -> Result<Vec<Project>> {
        self.jira
            .projects()
            .list()
            .await
            .context("listing projects")
    }

    // =========================================================================
    // Version operations
    // =========================================================================

    /// List versions in a project.
    pub async fn list_versions(&self, project: &str) -> Result<Vec<Version>> {
        self.jira
            .versions()
            .project_versions(project)
            .await
            .with_context(|| format!("listing versions in project {}", project))
    }
}

/// Result type for JIRA operations that can be serialized to JSON.
#[derive(Debug)]
pub enum JiraResult {
    Issue(Issue),
    CreatedIssue(CreatedIssue),
    Issues(SearchResults),
    Projects(Vec<Project>),
    Versions(Vec<Version>),
    Transitions(Vec<TransitionOption>),
    Success(String),
}

impl JiraResult {
    /// Convert the result to a JSON value.
    pub fn to_json(&self) -> Result<serde_json::Value> {
        match self {
            JiraResult::Issue(issue) => serde_json::to_value(issue).context("serializing issue"),
            JiraResult::CreatedIssue(created) => Ok(serde_json::json!({
                "id": created.id,
                "key": created.key,
                "url": created.url,
            })),
            JiraResult::Issues(results) => {
                serde_json::to_value(results).context("serializing search results")
            }
            JiraResult::Projects(projects) => {
                serde_json::to_value(projects).context("serializing projects")
            }
            JiraResult::Versions(versions) => {
                serde_json::to_value(versions).context("serializing versions")
            }
            JiraResult::Transitions(transitions) => {
                serde_json::to_value(transitions).context("serializing transitions")
            }
            JiraResult::Success(msg) => {
                Ok(serde_json::json!({ "status": "success", "message": msg }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: Integration tests require a live JIRA instance and are marked as ignored.
    // Run with: cargo test --lib jira_client -- --ignored
    //
    // Set environment variables:
    //   JIRA_HOST=https://your-instance.atlassian.net
    //   JIRA_USERNAME=your-email@example.com
    //   JIRA_API_TOKEN=your-api-token
    //   JIRA_PROJECT=YOURPROJECT (optional, for project-specific tests)

    fn get_test_client() -> Option<JiraClient> {
        let host = std::env::var("JIRA_HOST").ok()?;
        let username = std::env::var("JIRA_USERNAME").ok()?;
        let token = std::env::var("JIRA_API_TOKEN").ok()?;
        JiraClient::new(&host, &username, &token).ok()
    }

    #[test]
    fn test_client_creation_fails_without_valid_host() {
        // Invalid URL should fail
        let result = JiraClient::new("not a valid url", "user", "token");
        assert!(result.is_err());
    }

    #[test]
    fn test_client_creation_with_valid_host() {
        // Valid URL should work
        let result = JiraClient::new("https://jira.example.com", "user", "token");
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore = "requires live JIRA instance"]
    async fn test_list_projects() {
        let client = get_test_client().expect("JIRA_HOST, JIRA_USERNAME, JIRA_API_TOKEN required");
        let projects = client.list_projects().await.expect("listing projects");
        // Should return at least some projects (may be empty for new instances)
        eprintln!("Found {} projects", projects.len());
        for p in projects.iter().take(5) {
            eprintln!("  - {} ({})", p.name, p.key);
        }
    }

    #[tokio::test]
    #[ignore = "requires live JIRA instance"]
    async fn test_search_issues() {
        let client = get_test_client().expect("JIRA_HOST, JIRA_USERNAME, JIRA_API_TOKEN required");
        let project = std::env::var("JIRA_PROJECT").unwrap_or_else(|_| "TEST".to_string());

        let jql = format!("project = {} ORDER BY created DESC", project);
        let results = client.search(&jql).await.expect("searching issues");
        eprintln!("Found {} issues in {}", results.total, project);
        for issue in results.issues.iter().take(3) {
            eprintln!("  - {}: {}", issue.key, issue.summary().unwrap_or_default());
        }
    }

    #[tokio::test]
    #[ignore = "requires live JIRA instance"]
    async fn test_list_issues() {
        let client = get_test_client().expect("JIRA_HOST, JIRA_USERNAME, JIRA_API_TOKEN required");
        let project = std::env::var("JIRA_PROJECT").unwrap_or_else(|_| "TEST".to_string());

        let results = client.list_issues(&project).await.expect("listing issues");
        eprintln!("Found {} issues in {}", results.total, project);
    }

    #[tokio::test]
    #[ignore = "requires live JIRA instance and existing issue"]
    async fn test_get_issue() {
        let client = get_test_client().expect("JIRA_HOST, JIRA_USERNAME, JIRA_API_TOKEN required");
        let issue_key =
            std::env::var("JIRA_TEST_ISSUE").expect("JIRA_TEST_ISSUE required for this test");

        let issue = client.get_issue(&issue_key).await.expect("getting issue");
        eprintln!(
            "Issue {}: {}",
            issue.key,
            issue.summary().unwrap_or_default()
        );
    }

    #[tokio::test]
    #[ignore = "requires live JIRA instance and existing issue"]
    async fn test_get_transitions() {
        let client = get_test_client().expect("JIRA_HOST, JIRA_USERNAME, JIRA_API_TOKEN required");
        let issue_key =
            std::env::var("JIRA_TEST_ISSUE").expect("JIRA_TEST_ISSUE required for this test");

        let transitions = client
            .get_transitions(&issue_key)
            .await
            .expect("getting transitions");
        eprintln!("Available transitions for {}:", issue_key);
        for t in &transitions {
            eprintln!("  - {} (id: {})", t.name, t.id);
        }
    }
}
