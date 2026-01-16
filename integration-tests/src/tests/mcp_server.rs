//! Integration tests for the MCP server with GitHub scope restrictions
//!
//! These tests verify that the MCP server correctly enforces scope restrictions
//! when accessing GitHub repositories.

use eyre::{Context, Result};
use integration_tests::integration_test;
use serde_json::{json, Value};

use crate::McpServerHandle;

/// Get the test repository from environment or use default
///
/// Set TEST_GITHUB_REPO to override (e.g., "myorg/myrepo")
fn get_test_repo() -> String {
    std::env::var("TEST_GITHUB_REPO").unwrap_or_else(|_| "cgwalters/playground".to_string())
}

/// Get the test owner from the test repo
fn get_test_owner() -> String {
    let repo = get_test_repo();
    repo.split('/').next().unwrap_or("cgwalters").to_string()
}

/// Get a repo that should be denied (different from the allowed one)
///
/// Set TEST_GITHUB_DENIED_REPO to override
fn get_denied_repo() -> String {
    std::env::var("TEST_GITHUB_DENIED_REPO").unwrap_or_else(|_| {
        let owner = get_test_owner();
        // Use a different repo under the same owner, or a well-known public repo
        if owner == "cgwalters" {
            "cgwalters/service-gator".to_string()
        } else {
            format!("{}/nonexistent-test-repo", owner)
        }
    })
}

/// An MCP client session that maintains state across requests
struct McpSession {
    client: reqwest::blocking::Client,
    mcp_url: String,
    session_id: Option<String>,
    request_id: u64,
}

impl McpSession {
    fn new(mcp_url: &str) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            mcp_url: mcp_url.to_string(),
            session_id: None,
            request_id: 0,
        }
    }

    fn next_id(&mut self) -> u64 {
        self.request_id += 1;
        self.request_id
    }

    /// Send an MCP request and return the response
    fn send_request(&mut self, request: Value) -> Result<Value> {
        let mut req_builder = self
            .client
            .post(&self.mcp_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        // Include session ID if we have one
        if let Some(ref session_id) = self.session_id {
            req_builder = req_builder.header("Mcp-Session-Id", session_id);
        }

        let response = req_builder
            .json(&request)
            .send()
            .context("sending MCP request")?;

        // Extract session ID from response headers
        if let Some(session_id) = response.headers().get("mcp-session-id") {
            if let Ok(id) = session_id.to_str() {
                self.session_id = Some(id.to_string());
            }
        }

        let status = response.status();
        let body = response.text().context("reading response body")?;

        // Parse SSE response - the actual JSON is in the "data:" lines
        let mut json_response: Option<Value> = None;
        for line in body.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                if !data.is_empty() {
                    if let Ok(parsed) = serde_json::from_str::<Value>(data) {
                        json_response = Some(parsed);
                    }
                }
            }
        }

        json_response.ok_or_else(|| {
            eyre::eyre!(
                "No valid JSON response found in SSE stream (status {}): {}",
                status,
                body
            )
        })
    }

    /// Initialize the MCP session
    fn initialize(&mut self) -> Result<Value> {
        let id = self.next_id();
        let request = json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "integration-test",
                    "version": "1.0"
                }
            },
            "id": id
        });

        self.send_request(request)
    }

    /// Send initialized notification (required after initialize)
    fn send_initialized(&mut self) -> Result<()> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        // For notifications, we don't expect a response with result
        let mut req_builder = self
            .client
            .post(&self.mcp_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(ref session_id) = self.session_id {
            req_builder = req_builder.header("Mcp-Session-Id", session_id);
        }

        let _response = req_builder
            .json(&request)
            .send()
            .context("sending initialized notification")?;

        Ok(())
    }

    /// Call the gh tool via MCP
    fn call_gh(&mut self, args: Vec<&str>) -> Result<Value> {
        let id = self.next_id();
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "gh",
                "arguments": {
                    "args": args
                }
            },
            "id": id
        });

        self.send_request(request)
    }
}

/// Test that the MCP server initializes correctly
fn test_mcp_server_initializes() -> Result<()> {
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());
    let response = session.initialize()?;

    // Verify we got a successful response
    assert!(
        response.get("result").is_some(),
        "Expected 'result' in response, got: {}",
        response
    );

    let result = &response["result"];
    assert!(
        result.get("serverInfo").is_some(),
        "Expected 'serverInfo' in result"
    );

    Ok(())
}
integration_test!(test_mcp_server_initializes);

/// Test that access to allowed repository works
fn test_mcp_github_allowed_repo_access() -> Result<()> {
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try to access the allowed repo
    let api_path = format!("repos/{}", test_repo);
    let response = session.call_gh(vec!["api", &api_path])?;

    // Check for successful response with content
    let result = response
        .get("result")
        .ok_or_else(|| eyre::eyre!("Expected 'result' in response, got: {}", response))?;

    let content = result
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| eyre::eyre!("Expected 'content' array in result"))?;

    assert!(!content.is_empty(), "Expected non-empty content array");

    // The first content item should have text with repo info
    let text = content[0]
        .get("text")
        .and_then(|t| t.as_str())
        .ok_or_else(|| eyre::eyre!("Expected 'text' in content"))?;

    // Verify we got actual repo data (should contain repo name or owner)
    let repo_name = test_repo.split('/').last().unwrap_or(&test_repo);
    assert!(
        text.contains(repo_name) || text.contains(&get_test_owner()),
        "Expected repo info in response, got: {}",
        text
    );

    // Verify it's not an error
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        !is_error,
        "Expected successful response, got error: {}",
        text
    );

    Ok(())
}
integration_test!(test_mcp_github_allowed_repo_access);

/// Test that access to non-allowed repository is denied
fn test_mcp_github_denied_repo_access() -> Result<()> {
    let test_repo = get_test_repo();
    let denied_repo = get_denied_repo();

    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try to access a repo that is NOT in the allowed list
    let api_path = format!("repos/{}", denied_repo);
    let response = session.call_gh(vec!["api", &api_path])?;

    // Check for error response
    let result = response
        .get("result")
        .ok_or_else(|| eyre::eyre!("Expected 'result' in response, got: {}", response))?;

    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        is_error,
        "Expected access to be denied for {}, got: {}",
        denied_repo, result
    );

    // Verify the error message mentions access denied
    let content = result
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| eyre::eyre!("Expected 'content' array in result"))?;

    let error_text = content
        .first()
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");

    assert!(
        error_text.contains("not allowed") || error_text.contains("access"),
        "Expected 'not allowed' in error message, got: {}",
        error_text
    );

    Ok(())
}
integration_test!(test_mcp_github_denied_repo_access);

/// Test that wildcard patterns work correctly
fn test_mcp_github_wildcard_pattern() -> Result<()> {
    let test_owner = get_test_owner();
    let test_repo = get_test_repo();

    let config = format!(
        r#"
[gh.repos]
"{}/*" = {{ read = true }}
"#,
        test_owner
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // The test repo should be accessible with wildcard
    let api_path = format!("repos/{}", test_repo);
    let response1 = session.call_gh(vec!["api", &api_path])?;

    let result1 = &response1["result"];
    let is_error1 = result1
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        !is_error1,
        "Expected {} to be accessible with wildcard, got: {}",
        test_repo, result1
    );

    // A different owner should be denied
    let response2 = session.call_gh(vec!["api", "repos/torvalds/linux"])?;

    let result2 = &response2["result"];
    let is_error2 = result2
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        is_error2,
        "Expected torvalds/linux to be denied, got: {}",
        result2
    );

    Ok(())
}
integration_test!(test_mcp_github_wildcard_pattern);

/// Test that only gh api is allowed (not other subcommands)
fn test_mcp_github_api_only() -> Result<()> {
    let test_owner = get_test_owner();
    let test_repo = get_test_repo();

    let config = format!(
        r#"
[gh.repos]
"{}/*" = {{ read = true }}
"#,
        test_owner
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try to use a non-api subcommand (should fail)
    let response = session.call_gh(vec!["pr", "list", "-R", &test_repo])?;

    let result = &response["result"];
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        is_error,
        "Expected 'pr list' to be rejected (only api allowed), got: {}",
        result
    );

    let error_text = result
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");

    assert!(
        error_text.contains("api") || error_text.contains("supported"),
        "Expected error to mention 'api' restriction, got: {}",
        error_text
    );

    Ok(())
}
integration_test!(test_mcp_github_api_only);
