//! Integration tests for the MCP server with JIRA scope restrictions
//!
//! These tests verify that the MCP server correctly enforces scope restrictions
//! when accessing JIRA projects. Tests are read-only operations only.
//!
//! Required environment variables:
//! - JIRA_API_TOKEN: API token for JIRA authentication
//! - TEST_JIRA_PROJECT: Project key to test (e.g., "RHEL")
//! - JIRA_URL: JIRA server URL (e.g., "https://issues.redhat.com")

use eyre::{Context, Result};
use integration_tests::integration_test;
use serde_json::{json, Value};

use crate::{get_jira_token, McpServerHandle, McpServerOptions};

/// Get the test JIRA project from environment
fn get_test_project() -> Option<String> {
    std::env::var("TEST_JIRA_PROJECT").ok()
}

/// Get the JIRA URL from environment
fn get_jira_url() -> Option<String> {
    std::env::var("JIRA_URL").ok()
}

/// Check if JIRA tests can run (all required env vars present)
fn can_run_jira_tests() -> bool {
    get_jira_token().is_some() && get_test_project().is_some() && get_jira_url().is_some()
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

        if let Some(ref session_id) = self.session_id {
            req_builder = req_builder.header("Mcp-Session-Id", session_id);
        }

        let response = req_builder
            .json(&request)
            .send()
            .context("sending MCP request")?;

        if let Some(session_id) = response.headers().get("mcp-session-id") {
            if let Ok(id) = session_id.to_str() {
                self.session_id = Some(id.to_string());
            }
        }

        let status = response.status();
        let body = response.text().context("reading response body")?;

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

    /// Send initialized notification
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

    /// Call the jira tool via MCP
    fn call_jira(&mut self, args: Vec<&str>) -> Result<Value> {
        let id = self.next_id();
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "jira",
                "arguments": {
                    "args": args
                }
            },
            "id": id
        });

        self.send_request(request)
    }
}

/// Test that read access to allowed JIRA project works
fn test_jira_allowed_project_read() -> Result<()> {
    if !can_run_jira_tests() {
        eprintln!("Skipping JIRA test: missing required environment variables");
        return Ok(());
    }

    let test_project = get_test_project().unwrap();
    let config = format!(
        r#"
[jira.projects]
"{}" = {{ read = true }}
"#,
        test_project
    );

    let server = McpServerHandle::start_with_options(
        &config,
        McpServerOptions {
            gh_token: None,
            jira_token: get_jira_token(),
            jira_url: get_jira_url(),
        },
    )?;

    let mut session = McpSession::new(&server.mcp_url());
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try a read-only operation: list issues in the project
    let response = session.call_jira(vec!["issue", "list", "-p", &test_project])?;

    let result = response
        .get("result")
        .ok_or_else(|| eyre::eyre!("Expected 'result' in response, got: {}", response))?;

    // The command might fail if jirust-cli is not installed, but it should NOT
    // fail due to scope restrictions. Check that it's not a "not allowed" error.
    let content = result.get("content").and_then(|c| c.as_array());
    if let Some(content) = content {
        if let Some(text) = content
            .first()
            .and_then(|c| c.get("text"))
            .and_then(|t| t.as_str())
        {
            // If we get "not allowed", the scope check failed
            assert!(
                !text.contains("not allowed") && !text.contains("Operation not allowed"),
                "Expected read access to be allowed for {}, got: {}",
                test_project,
                text
            );
        }
    }

    Ok(())
}
integration_test!(test_jira_allowed_project_read);

/// Test that access to non-allowed JIRA project is denied
fn test_jira_denied_project_access() -> Result<()> {
    if !can_run_jira_tests() {
        eprintln!("Skipping JIRA test: missing required environment variables");
        return Ok(());
    }

    let test_project = get_test_project().unwrap();
    // Configure a DIFFERENT project as allowed, so our test project is denied
    let config = r#"
[jira.projects]
"SOMEOTHERPROJECT" = { read = true }
"#;

    let server = McpServerHandle::start_with_options(
        config,
        McpServerOptions {
            gh_token: None,
            jira_token: get_jira_token(),
            jira_url: get_jira_url(),
        },
    )?;

    let mut session = McpSession::new(&server.mcp_url());
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try to access our test project (which is NOT in allowed list)
    let response = session.call_jira(vec!["issue", "list", "-p", &test_project])?;

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
        test_project, result
    );

    let error_text = result
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or("");

    assert!(
        error_text.contains("not allowed") || error_text.contains("Operation not allowed"),
        "Expected 'not allowed' in error message, got: {}",
        error_text
    );

    Ok(())
}
integration_test!(test_jira_denied_project_access);

/// Test that read-only config denies write operations
fn test_jira_read_only_denies_write() -> Result<()> {
    if !can_run_jira_tests() {
        eprintln!("Skipping JIRA test: missing required environment variables");
        return Ok(());
    }

    let test_project = get_test_project().unwrap();
    // Configure read-only access (no write)
    let config = format!(
        r#"
[jira.projects]
"{}" = {{ read = true }}
"#,
        test_project
    );

    let server = McpServerHandle::start_with_options(
        &config,
        McpServerOptions {
            gh_token: None,
            jira_token: get_jira_token(),
            jira_url: get_jira_url(),
        },
    )?;

    let mut session = McpSession::new(&server.mcp_url());
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try a write operation (issue create) - should be denied by scope
    let response = session.call_jira(vec!["issue", "create", "-p", &test_project])?;

    let result = response
        .get("result")
        .ok_or_else(|| eyre::eyre!("Expected 'result' in response, got: {}", response))?;

    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        is_error,
        "Expected write operation to be denied for read-only project, got: {}",
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
        error_text.contains("not allowed") || error_text.contains("Operation not allowed"),
        "Expected 'not allowed' in error message for write op, got: {}",
        error_text
    );

    Ok(())
}
integration_test!(test_jira_read_only_denies_write);
