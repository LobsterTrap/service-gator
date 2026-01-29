//! Tests for the status functionality in the MCP server

use eyre::{Context, Result};
use integration_tests::integration_test;
use serde_json::json;

use crate::McpServerHandle;

/// Simple MCP session for status testing
struct StatusTestSession {
    client: reqwest::blocking::Client,
    mcp_url: String,
    session_id: Option<String>,
    request_id: u64,
}

impl StatusTestSession {
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

    fn build_request(&self) -> reqwest::blocking::RequestBuilder {
        let mut req_builder = self
            .client
            .post(&self.mcp_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(ref session_id) = self.session_id {
            req_builder = req_builder.header("Mcp-Session-Id", session_id);
        }

        req_builder
    }

    fn send_request(&mut self, request: serde_json::Value) -> Result<serde_json::Value> {
        let response = self
            .build_request()
            .json(&request)
            .send()
            .context("sending MCP request")?;

        // Extract session ID from response headers
        if let Some(session_id) = response.headers().get("mcp-session-id") {
            if let Ok(id) = session_id.to_str() {
                self.session_id = Some(id.to_string());
            }
        }

        let body = response.text().context("reading response body")?;

        // Parse SSE response - the actual JSON is in the "data:" lines
        for line in body.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                if !data.is_empty() {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data) {
                        return Ok(parsed);
                    }
                }
            }
        }

        eyre::bail!("No valid JSON response found in SSE stream: {}", body)
    }

    fn initialize(&mut self) -> Result<serde_json::Value> {
        let id = self.next_id();
        let request = json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "status-test",
                    "version": "1.0"
                }
            },
            "id": id
        });

        self.send_request(request)
    }

    fn send_initialized(&mut self) -> Result<()> {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        // For notifications, we don't expect a response with result
        let _response = self
            .build_request()
            .json(&request)
            .send()
            .context("sending initialized notification")?;

        Ok(())
    }

    fn call_tool(&mut self, tool_name: &str, args: serde_json::Value) -> Result<serde_json::Value> {
        let id = self.next_id();
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            },
            "id": id
        });

        self.send_request(request)
    }

    fn list_tools(&mut self) -> Result<serde_json::Value> {
        let id = self.next_id();
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": id
        });

        self.send_request(request)
    }
}

/// Extract text content from a tool call result
fn extract_text_content(response: &serde_json::Value) -> Option<String> {
    response
        .get("result")?
        .get("content")?
        .as_array()?
        .first()?
        .get("text")?
        .as_str()
        .map(|s| s.to_string())
}

/// Check if a tool call result is an error
fn is_error_result(response: &serde_json::Value) -> bool {
    response
        .get("result")
        .and_then(|r| r.get("isError"))
        .and_then(|e| e.as_bool())
        .unwrap_or(false)
}

/// Test the overall status tool
fn test_overall_status() -> Result<()> {
    let config = r#"
[gh]
repos = { "test/repo" = { read = true, create_draft = true }, "another/repo" = { read = true } }
graphql = "read"

[gitlab]
host = "gitlab.example.com"
projects = { "group/project" = { read = true, create_draft = true }, "group/another" = { read = true } }

[jira]
host = "https://company.atlassian.net"
projects = { "PROJ" = { read = true, create = true }, "TEST" = { read = true, write = true } }

[[forgejo]]
host = "codeberg.org"
repos = { "user/repo" = { read = true, create_draft = true }, "user/another" = { read = true } }

[[forgejo]]
host = "git.example.com"
repos = { "team/project" = { read = true, write = true } }
"#;

    let server = McpServerHandle::start(config)?;
    let mut session = StatusTestSession::new(&server.mcp_url());

    // Initialize session
    let _init_response = session.initialize()?;
    session.send_initialized()?;

    // Test overall status tool
    let response = session.call_tool("status", json!({}))?;

    assert!(
        !is_error_result(&response),
        "Status tool should not error: {:?}",
        response
    );

    let status_text = extract_text_content(&response).expect("Should have text content");

    // Verify the status contains service information
    assert!(
        status_text.contains("Service-Gator Overall Status"),
        "Status should have header"
    );

    println!("Overall Status Output:\n{}", status_text);
    Ok(())
}

/// Test that tools are listed correctly
fn test_tools_list_includes_status() -> Result<()> {
    let config = r#"
[gh]
repos = { "test/repo" = { read = true } }
"#;

    let server = McpServerHandle::start(config)?;
    let mut session = StatusTestSession::new(&server.mcp_url());

    // Initialize session
    let _init_response = session.initialize()?;
    session.send_initialized()?;

    // List tools
    let response = session.list_tools()?;

    let tools = response
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
        .expect("Should have tools list");

    let tool_names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool.get("name").and_then(|n| n.as_str()))
        .collect();

    println!("Available tools: {:?}", tool_names);

    // Verify status tool is available
    assert!(
        tool_names.contains(&"status"),
        "Status tool should be available in tools list"
    );

    // Verify service tools are available
    let expected_service_tools = vec!["github", "gl", "forgejo", "jira"];
    for service in expected_service_tools {
        assert!(
            tool_names.contains(&service),
            "Service tool '{}' should be available",
            service
        );
    }

    Ok(())
}

integration_test!(test_overall_status);
integration_test!(test_tools_list_includes_status);
