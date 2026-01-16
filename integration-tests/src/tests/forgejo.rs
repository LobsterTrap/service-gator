//! Integration tests for the MCP server with Forgejo scope restrictions
//!
//! These tests verify that the MCP server correctly enforces scope restrictions
//! when accessing Forgejo repositories via the native API client.
//!
//! Tests run against Codeberg.org (a public Forgejo instance) without authentication,
//! accessing public repositories only.

use eyre::{Context, Result};
use integration_tests::integration_test;
use serde_json::{json, Value};

use crate::McpServerHandle;

/// Get the test Forgejo host
fn get_test_host() -> String {
    std::env::var("TEST_FORGEJO_HOST").unwrap_or_else(|_| "codeberg.org".to_string())
}

/// Get the test repository from environment or use default
///
/// Set TEST_FORGEJO_REPO to override (e.g., "myorg/myrepo")
fn get_test_repo() -> String {
    std::env::var("TEST_FORGEJO_REPO").unwrap_or_else(|_| "forgejo/forgejo".to_string())
}

/// Get the test owner from the test repo
fn get_test_owner() -> String {
    let repo = get_test_repo();
    repo.split('/').next().unwrap_or("forgejo").to_string()
}

/// Get a repo that should be denied (different from the allowed one)
fn get_denied_repo() -> String {
    std::env::var("TEST_FORGEJO_DENIED_REPO").unwrap_or_else(|_| "codeberg/community".to_string())
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

    /// Call the forgejo tool via MCP
    fn call_forgejo(&mut self, args: Vec<&str>, host: Option<&str>) -> Result<Value> {
        let id = self.next_id();
        let mut arguments = json!({
            "args": args
        });

        if let Some(h) = host {
            arguments["host"] = json!(h);
        }

        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "forgejo",
                "arguments": arguments
            },
            "id": id
        });

        self.send_request(request)
    }
}

/// Test that the MCP server with Forgejo config initializes correctly
fn test_forgejo_mcp_server_initializes() -> Result<()> {
    let test_host = get_test_host();
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[[forgejo]]
host = "{}"

[forgejo.repos]
"{}" = {{ read = true }}
"#,
        test_host, test_repo
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
integration_test!(test_forgejo_mcp_server_initializes);

/// Test that access to allowed Forgejo repository works
fn test_forgejo_allowed_repo_access() -> Result<()> {
    let test_host = get_test_host();
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[[forgejo]]
host = "{}"

[forgejo.repos]
"{}" = {{ read = true }}
"#,
        test_host, test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try to access the allowed repo via API
    let api_path = format!("/api/v1/repos/{}", test_repo);
    let response = session.call_forgejo(vec!["api", &api_path], Some(&test_host))?;

    // Check for successful response with content
    let result = response
        .get("result")
        .ok_or_else(|| eyre::eyre!("Expected 'result' in response, got: {}", response))?;

    let content = result
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| eyre::eyre!("Expected 'content' array in result"))?;

    assert!(!content.is_empty(), "Expected non-empty content array");

    // The first content item should have text with repo info (JSON)
    let text = content[0]
        .get("text")
        .and_then(|t| t.as_str())
        .ok_or_else(|| eyre::eyre!("Expected 'text' in content"))?;

    // Verify we got actual repo data (should be parseable JSON with name field)
    let repo_json: Value =
        serde_json::from_str(text).with_context(|| format!("Response should be JSON: {}", text))?;

    assert!(
        repo_json.get("name").is_some() || repo_json.get("full_name").is_some(),
        "Expected repo info with 'name' or 'full_name' field, got: {}",
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
integration_test!(test_forgejo_allowed_repo_access);

/// Test that access to non-allowed Forgejo repository is denied
fn test_forgejo_denied_repo_access() -> Result<()> {
    let test_host = get_test_host();
    let test_repo = get_test_repo();
    let denied_repo = get_denied_repo();

    let config = format!(
        r#"
[[forgejo]]
host = "{}"

[forgejo.repos]
"{}" = {{ read = true }}
"#,
        test_host, test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try to access a repo that is NOT in the allowed list
    let api_path = format!("/api/v1/repos/{}", denied_repo);
    let response = session.call_forgejo(vec!["api", &api_path], Some(&test_host))?;

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
integration_test!(test_forgejo_denied_repo_access);

/// Test that wildcard patterns work correctly for Forgejo
fn test_forgejo_wildcard_pattern() -> Result<()> {
    let test_host = get_test_host();
    let test_owner = get_test_owner();
    let test_repo = get_test_repo();

    let config = format!(
        r#"
[[forgejo]]
host = "{}"

[forgejo.repos]
"{}/*" = {{ read = true }}
"#,
        test_host, test_owner
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // The test repo should be accessible with wildcard
    let api_path = format!("/api/v1/repos/{}", test_repo);
    let response1 = session.call_forgejo(vec!["api", &api_path], Some(&test_host))?;

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
    let response2 = session.call_forgejo(
        vec!["api", "/api/v1/repos/codeberg/community"],
        Some(&test_host),
    )?;

    let result2 = &response2["result"];
    let is_error2 = result2
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);

    // Only check if owner is different from codeberg
    if test_owner != "codeberg" {
        assert!(
            is_error2,
            "Expected codeberg/community to be denied, got: {}",
            result2
        );
    }

    Ok(())
}
integration_test!(test_forgejo_wildcard_pattern);

/// Test that only api subcommand is allowed for Forgejo
fn test_forgejo_api_only() -> Result<()> {
    let test_host = get_test_host();
    let test_repo = get_test_repo();

    let config = format!(
        r#"
[[forgejo]]
host = "{}"

[forgejo.repos]
"{}" = {{ read = true }}
"#,
        test_host, test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try to use a non-api subcommand (should fail)
    let response = session.call_forgejo(vec!["pr", "list"], Some(&test_host))?;

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
integration_test!(test_forgejo_api_only);

/// Test listing pull requests from Forgejo
fn test_forgejo_list_pull_requests() -> Result<()> {
    let test_host = get_test_host();
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[[forgejo]]
host = "{}"

[forgejo.repos]
"{}" = {{ read = true }}
"#,
        test_host, test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // List pull requests
    let api_path = format!("/api/v1/repos/{}/pulls", test_repo);
    let response = session.call_forgejo(vec!["api", &api_path], Some(&test_host))?;

    let result = response
        .get("result")
        .ok_or_else(|| eyre::eyre!("Expected 'result' in response, got: {}", response))?;

    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(!is_error, "Expected successful response, got: {}", result);

    let content = result
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| eyre::eyre!("Expected 'content' array in result"))?;

    let text = content[0]
        .get("text")
        .and_then(|t| t.as_str())
        .ok_or_else(|| eyre::eyre!("Expected 'text' in content"))?;

    // Should be a JSON array (even if empty)
    let prs: Value = serde_json::from_str(text)
        .with_context(|| format!("Response should be JSON array: {}", text))?;

    assert!(
        prs.is_array(),
        "Expected array of pull requests, got: {}",
        text
    );

    Ok(())
}
integration_test!(test_forgejo_list_pull_requests);

/// Test listing issues from Forgejo
fn test_forgejo_list_issues() -> Result<()> {
    let test_host = get_test_host();
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[[forgejo]]
host = "{}"

[forgejo.repos]
"{}" = {{ read = true }}
"#,
        test_host, test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // List issues
    let api_path = format!("/api/v1/repos/{}/issues", test_repo);
    let response = session.call_forgejo(vec!["api", &api_path], Some(&test_host))?;

    let result = response
        .get("result")
        .ok_or_else(|| eyre::eyre!("Expected 'result' in response, got: {}", response))?;

    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(!is_error, "Expected successful response, got: {}", result);

    let content = result
        .get("content")
        .and_then(|c| c.as_array())
        .ok_or_else(|| eyre::eyre!("Expected 'content' array in result"))?;

    let text = content[0]
        .get("text")
        .and_then(|t| t.as_str())
        .ok_or_else(|| eyre::eyre!("Expected 'text' in content"))?;

    // Should be a JSON array (even if empty)
    let issues: Value = serde_json::from_str(text)
        .with_context(|| format!("Response should be JSON array: {}", text))?;

    assert!(issues.is_array(), "Expected array of issues, got: {}", text);

    Ok(())
}
integration_test!(test_forgejo_list_issues);

/// Test that --jq option is rejected for Forgejo (not supported with native client)
fn test_forgejo_jq_rejected() -> Result<()> {
    let test_host = get_test_host();
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[[forgejo]]
host = "{}"

[forgejo.repos]
"{}" = {{ read = true }}
"#,
        test_host, test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Initialize session
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try to use --jq option (should fail)
    let api_path = format!("/api/v1/repos/{}", test_repo);
    let response =
        session.call_forgejo(vec!["api", &api_path, "--jq", ".name"], Some(&test_host))?;

    let result = &response["result"];
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(is_error, "Expected --jq to be rejected, got: {}", result);

    let error_text = result
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");

    assert!(
        error_text.contains("jq") || error_text.contains("not supported"),
        "Expected error to mention --jq not supported, got: {}",
        error_text
    );

    Ok(())
}
integration_test!(test_forgejo_jq_rejected);
