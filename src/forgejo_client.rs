//! Native Forgejo/Gitea API client for service-gator.
//!
//! This module provides a native Rust client for the Forgejo/Gitea API,
//! replacing the need for the `tea` CLI wrapper.
//!
//! ## Security Model
//!
//! This client only exposes read-only operations:
//! - List/get pull requests
//! - List/get issues
//! - Get repository info
//! - List releases
//! - List branches
//!
//! Write operations are not exposed.

use eyre::{Context, Result};
use forgejo_api::{Auth, Forgejo};
use url::Url;

/// A Forgejo API client for a specific host.
pub struct ForgejoClient {
    api: Forgejo,
    host: String,
}

impl ForgejoClient {
    /// Create a new Forgejo client for the given host and optional token.
    pub fn new(host: &str, token: Option<&str>) -> Result<Self> {
        let url = Url::parse(&format!("https://{}", host))
            .with_context(|| format!("Invalid Forgejo host URL: {}", host))?;

        let auth = match token {
            Some(t) => Auth::Token(t),
            None => Auth::None,
        };

        let api = Forgejo::new(auth, url)
            .with_context(|| format!("Failed to create Forgejo client for {}", host))?;

        Ok(Self {
            api,
            host: host.to_string(),
        })
    }

    /// Get the host this client is connected to.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get repository information.
    pub async fn get_repo(&self, owner: &str, repo: &str) -> Result<serde_json::Value> {
        let result = self
            .api
            .repo_get(owner, repo)
            .await
            .with_context(|| format!("Failed to get repo {}/{}", owner, repo))?;

        serde_json::to_value(&result).context("Failed to serialize repository")
    }

    /// List pull requests for a repository (first page only).
    pub async fn list_pull_requests(&self, owner: &str, repo: &str) -> Result<serde_json::Value> {
        // Use .send() instead of .all() to get just the first page
        // This avoids timeouts on large repos with many PRs
        let (_headers, result) = self
            .api
            .repo_list_pull_requests(owner, repo, Default::default())
            .send()
            .await
            .with_context(|| format!("Failed to list PRs for {}/{}", owner, repo))?;

        serde_json::to_value(&result).context("Failed to serialize pull requests")
    }

    /// Get a specific pull request.
    pub async fn get_pull_request(
        &self,
        owner: &str,
        repo: &str,
        index: i64,
    ) -> Result<serde_json::Value> {
        let result = self
            .api
            .repo_get_pull_request(owner, repo, index)
            .await
            .with_context(|| format!("Failed to get PR #{} for {}/{}", index, owner, repo))?;

        serde_json::to_value(&result).context("Failed to serialize pull request")
    }

    /// List issues for a repository (first page only).
    pub async fn list_issues(&self, owner: &str, repo: &str) -> Result<serde_json::Value> {
        // Use .send() instead of .all() to get just the first page
        // This avoids timeouts on large repos with many issues
        let (_headers, result) = self
            .api
            .issue_list_issues(owner, repo, Default::default())
            .send()
            .await
            .with_context(|| format!("Failed to list issues for {}/{}", owner, repo))?;

        serde_json::to_value(&result).context("Failed to serialize issues")
    }

    /// Get a specific issue.
    pub async fn get_issue(
        &self,
        owner: &str,
        repo: &str,
        index: i64,
    ) -> Result<serde_json::Value> {
        let result = self
            .api
            .issue_get_issue(owner, repo, index)
            .await
            .with_context(|| format!("Failed to get issue #{} for {}/{}", index, owner, repo))?;

        serde_json::to_value(&result).context("Failed to serialize issue")
    }

    /// List releases for a repository (first page only).
    pub async fn list_releases(&self, owner: &str, repo: &str) -> Result<serde_json::Value> {
        // Use .send() instead of .all() to get just the first page
        let (_headers, result) = self
            .api
            .repo_list_releases(owner, repo, Default::default())
            .send()
            .await
            .with_context(|| format!("Failed to list releases for {}/{}", owner, repo))?;

        serde_json::to_value(&result).context("Failed to serialize releases")
    }

    /// List branches for a repository (first page only).
    pub async fn list_branches(&self, owner: &str, repo: &str) -> Result<serde_json::Value> {
        // Use .send() instead of .all() to get just the first page
        let (_headers, result) = self
            .api
            .repo_list_branches(owner, repo)
            .send()
            .await
            .with_context(|| format!("Failed to list branches for {}/{}", owner, repo))?;

        serde_json::to_value(&result).context("Failed to serialize branches")
    }

    /// List commits for a repository (first page only).
    pub async fn list_commits(&self, owner: &str, repo: &str) -> Result<serde_json::Value> {
        // Use .send() instead of .all() to get just the first page
        let (_headers, result) = self
            .api
            .repo_get_all_commits(owner, repo, Default::default())
            .send()
            .await
            .with_context(|| format!("Failed to list commits for {}/{}", owner, repo))?;

        serde_json::to_value(&result).context("Failed to serialize commits")
    }

    /// Get file contents from a repository.
    pub async fn get_contents(
        &self,
        owner: &str,
        repo: &str,
        path: &str,
        ref_: Option<&str>,
    ) -> Result<serde_json::Value> {
        let query = forgejo_api::structs::RepoGetContentsQuery {
            r#ref: ref_.map(String::from),
        };
        let result = self
            .api
            .repo_get_contents(owner, repo, path, query)
            .await
            .with_context(|| format!("Failed to get contents of {} in {}/{}", path, owner, repo))?;

        serde_json::to_value(&result).context("Failed to serialize contents")
    }
}

/// Parse an API path and route to the appropriate method.
///
/// Supports paths like:
/// - `/api/v1/repos/{owner}/{repo}` -> get_repo
/// - `/api/v1/repos/{owner}/{repo}/pulls` -> list_pull_requests
/// - `/api/v1/repos/{owner}/{repo}/pulls/{index}` -> get_pull_request
/// - `/api/v1/repos/{owner}/{repo}/issues` -> list_issues
/// - `/api/v1/repos/{owner}/{repo}/issues/{index}` -> get_issue
/// - `/api/v1/repos/{owner}/{repo}/releases` -> list_releases
/// - `/api/v1/repos/{owner}/{repo}/branches` -> list_branches
/// - `/api/v1/repos/{owner}/{repo}/commits` -> list_commits
/// - `/api/v1/repos/{owner}/{repo}/contents/{path}` -> get_contents
pub async fn execute_api_path(client: &ForgejoClient, path: &str) -> Result<serde_json::Value> {
    let path = path.trim_start_matches('/');

    // Strip api/v1 prefix if present
    let path = path.strip_prefix("api/v1/").unwrap_or(path);

    // Parse repos/{owner}/{repo}/...
    if let Some(rest) = path.strip_prefix("repos/") {
        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() < 2 {
            eyre::bail!("Invalid repo path: expected repos/{{owner}}/{{repo}}/...");
        }

        let owner = parts[0];
        let repo = parts[1];
        let remainder = parts.get(2).copied().unwrap_or("");

        return route_repo_path(client, owner, repo, remainder).await;
    }

    eyre::bail!(
        "Unsupported API path: {}. Supported: /api/v1/repos/{{owner}}/{{repo}}/...",
        path
    )
}

/// Route a repo-specific path to the appropriate method.
async fn route_repo_path(
    client: &ForgejoClient,
    owner: &str,
    repo: &str,
    remainder: &str,
) -> Result<serde_json::Value> {
    // Empty remainder = get repo info
    if remainder.is_empty() {
        return client.get_repo(owner, repo).await;
    }

    // Parse the resource type
    let parts: Vec<&str> = remainder.splitn(2, '/').collect();
    let resource = parts[0];
    let sub_path = parts.get(1).copied().unwrap_or("");

    match resource {
        "pulls" => {
            if sub_path.is_empty() {
                client.list_pull_requests(owner, repo).await
            } else {
                // Try to parse as PR number
                let index: i64 = sub_path
                    .split('/')
                    .next()
                    .unwrap_or(sub_path)
                    .parse()
                    .with_context(|| format!("Invalid PR number: {}", sub_path))?;
                client.get_pull_request(owner, repo, index).await
            }
        }
        "issues" => {
            if sub_path.is_empty() {
                client.list_issues(owner, repo).await
            } else {
                let index: i64 = sub_path
                    .split('/')
                    .next()
                    .unwrap_or(sub_path)
                    .parse()
                    .with_context(|| format!("Invalid issue number: {}", sub_path))?;
                client.get_issue(owner, repo, index).await
            }
        }
        "releases" => {
            if sub_path.is_empty() {
                client.list_releases(owner, repo).await
            } else {
                eyre::bail!("Getting specific release by ID not yet supported");
            }
        }
        "branches" => {
            if sub_path.is_empty() {
                client.list_branches(owner, repo).await
            } else {
                eyre::bail!("Getting specific branch not yet supported");
            }
        }
        "commits" => {
            if sub_path.is_empty() {
                client.list_commits(owner, repo).await
            } else {
                eyre::bail!("Getting specific commit not yet supported");
            }
        }
        "contents" => {
            let file_path = if sub_path.is_empty() { "" } else { sub_path };
            client.get_contents(owner, repo, file_path, None).await
        }
        _ => {
            eyre::bail!(
                "Unsupported resource type: {}. Supported: pulls, issues, releases, branches, commits, contents",
                resource
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a live Forgejo instance and are marked as ignored.
    // Run with: cargo test --lib forgejo_client -- --ignored

    #[tokio::test]
    #[ignore = "requires live Forgejo instance"]
    async fn test_get_repo() {
        let client = ForgejoClient::new("codeberg.org", None).unwrap();
        let result = client.get_repo("forgejo", "forgejo").await.unwrap();
        assert!(result.get("name").is_some());
    }

    #[tokio::test]
    #[ignore = "requires live Forgejo instance"]
    async fn test_list_pull_requests() {
        let client = ForgejoClient::new("codeberg.org", None).unwrap();
        let result = client
            .list_pull_requests("forgejo", "forgejo")
            .await
            .unwrap();
        assert!(result.is_array());
    }

    #[test]
    fn test_client_creation() {
        let client = ForgejoClient::new("codeberg.org", None);
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_creation_with_token() {
        let client = ForgejoClient::new("codeberg.org", Some("test-token"));
        assert!(client.is_ok());
    }

    #[test]
    fn test_invalid_host() {
        // Hosts with spaces are invalid URLs
        let client = ForgejoClient::new("not a valid url", None);
        assert!(client.is_err());

        // But simple hostnames work fine
        let client = ForgejoClient::new("example.com", None);
        assert!(client.is_ok());
    }
}
