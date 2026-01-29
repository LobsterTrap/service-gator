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
    base_url: String,
    session_id: Option<String>,
    request_id: u64,
    /// Optional Bearer token for authenticated requests
    bearer_token: Option<String>,
}

impl McpSession {
    fn new(mcp_url: &str) -> Self {
        // Extract base_url from mcp_url (remove /mcp suffix)
        let base_url = mcp_url.trim_end_matches("/mcp").to_string();
        Self {
            client: reqwest::blocking::Client::new(),
            mcp_url: mcp_url.to_string(),
            base_url,
            session_id: None,
            request_id: 0,
            bearer_token: None,
        }
    }

    /// Create a session with a Bearer token for authentication
    fn with_token(mcp_url: &str, token: &str) -> Self {
        let mut session = Self::new(mcp_url);
        session.bearer_token = Some(token.to_string());
        session
    }

    fn next_id(&mut self) -> u64 {
        self.request_id += 1;
        self.request_id
    }

    /// Build a base request builder with common headers (auth, session).
    fn build_mcp_request(&self) -> reqwest::blocking::RequestBuilder {
        let mut req_builder = self
            .client
            .post(&self.mcp_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(ref session_id) = self.session_id {
            req_builder = req_builder.header("Mcp-Session-Id", session_id);
        }

        if let Some(ref token) = self.bearer_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }

        req_builder
    }

    /// Send an MCP request and return the response
    fn send_request(&mut self, request: Value) -> Result<Value> {
        let response = self
            .build_mcp_request()
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
        let _response = self
            .build_mcp_request()
            .json(&request)
            .send()
            .context("sending initialized notification")?;

        Ok(())
    }

    /// Mint a new token from the admin endpoint
    fn mint_token(&self, admin_key: &str, scopes_json: &Value, expires_in: u64) -> Result<String> {
        let url = format!("{}/admin/mint-token", self.base_url);
        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Admin-Key", admin_key)
            .json(&json!({
                "scopes": scopes_json,
                "expires-in": expires_in
            }))
            .send()
            .context("minting token")?;

        if !response.status().is_success() {
            let body = response.text()?;
            return Err(eyre::eyre!("Failed to mint token: {}", body));
        }

        let body: Value = response.json()?;
        let token = body["token"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("No token in response"))?;
        Ok(token.to_string())
    }

    /// Send a raw request and return the HTTP response status and body
    fn send_raw_request(&self, request: Value) -> Result<(u16, String)> {
        let response = self
            .build_mcp_request()
            .json(&request)
            .send()
            .context("sending MCP request")?;

        let status = response.status().as_u16();
        let body = response.text().context("reading response body")?;
        Ok((status, body))
    }

    /// Call the github tool's api operation via MCP
    fn call_github_api(&mut self, endpoint: &str, jq: Option<&str>) -> Result<Value> {
        let id = self.next_id();
        let mut arguments = json!({
            "operation": "api",
            "endpoint": endpoint
        });
        if let Some(jq_expr) = jq {
            arguments["jq"] = json!(jq_expr);
        }
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "github",
                "arguments": arguments
            },
            "id": id
        });

        self.send_request(request)
    }

    /// Legacy wrapper for tests that used call_gh with ["api", endpoint] pattern
    fn call_gh(&mut self, args: Vec<&str>) -> Result<Value> {
        // Parse the old format: ["api", endpoint] or ["api", endpoint, "--jq", expr]
        if args.first() == Some(&"api") && args.len() >= 2 {
            let endpoint = args[1];
            let jq = if args.len() >= 4 && args[2] == "--jq" {
                Some(args[3])
            } else {
                None
            };
            self.call_github_api(endpoint, jq)
        } else {
            // For non-api calls (like "pr list"), return an error since they're no longer supported
            let id = self.next_id();
            let request = json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "github",
                    "arguments": {
                        "operation": "api",
                        "endpoint": "invalid-test-call"
                    }
                },
                "id": id
            });
            self.send_request(request)
        }
    }

    /// Call the github tool's api operation with method and body
    fn call_github_api_with_method(
        &mut self,
        endpoint: &str,
        method: &str,
        body: Option<Value>,
        jq: Option<&str>,
    ) -> Result<Value> {
        let id = self.next_id();
        let mut arguments = json!({
            "operation": "api",
            "endpoint": endpoint,
            "method": method
        });
        if let Some(body_value) = body {
            arguments["body"] = body_value;
        }
        if let Some(jq_expr) = jq {
            arguments["jq"] = json!(jq_expr);
        }
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "github",
                "arguments": arguments
            },
            "id": id
        });

        self.send_request(request)
    }

    /// Call the github tool's create-draft-pr operation
    fn call_github_create_draft_pr(
        &mut self,
        repo: &str,
        head: &str,
        base: &str,
        title: &str,
        body: Option<&str>,
    ) -> Result<Value> {
        let id = self.next_id();
        let mut arguments = json!({
            "operation": "create-draft-pr",
            "repo": repo,
            "head": head,
            "base": base,
            "title": title
        });
        if let Some(body_text) = body {
            arguments["body"] = json!(body_text);
        }
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "github",
                "arguments": arguments
            },
            "id": id
        });

        self.send_request(request)
    }

    /// Call the github tool's pending-review operation
    fn call_github_pending_review(
        &mut self,
        review_operation: &str,
        repo: &str,
        pull_number: u64,
        review_id: Option<u64>,
        body: Option<&str>,
    ) -> Result<Value> {
        let id = self.next_id();
        let mut arguments = json!({
            "operation": "pending-review",
            "review-operation": review_operation,
            "repo": repo,
            "pull_number": pull_number
        });
        if let Some(rid) = review_id {
            arguments["review_id"] = json!(rid);
        }
        if let Some(body_text) = body {
            arguments["body"] = json!(body_text);
        }
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "github",
                "arguments": arguments
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

/// Test that github tool api operation requires valid repo paths
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

    // Valid api call should work
    let api_path = format!("repos/{}", test_repo);
    let response = session.call_github_api(&api_path, None)?;

    let result = &response["result"];
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        !is_error,
        "Expected valid api call to succeed, got: {}",
        result
    );

    // Non-repo endpoint should be rejected
    let invalid_response = session.call_github_api("user", None)?;

    let invalid_result = &invalid_response["result"];
    let invalid_is_error = invalid_result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        invalid_is_error,
        "Expected non-repo endpoint to be rejected, got: {}",
        invalid_result
    );

    Ok(())
}
integration_test!(test_mcp_github_api_only);

// ============================================================================
// Token Authentication Tests
// ============================================================================

/// Test that token authentication works with auth mode "required"
fn test_mcp_token_auth_required_mode() -> Result<()> {
    let test_repo = get_test_repo();
    let denied_repo = get_denied_repo();

    // Configure server with auth mode "required" - no default scopes
    // The token will provide the scopes
    let config = r#"
[server]
secret = "test-secret-for-integration-tests"
admin-key = "test-admin-key"
mode = "required"

[gh.repos]
# No repos allowed by default - token must provide scopes
"#;

    let server = McpServerHandle::start(config)?;
    let session = McpSession::new(&server.mcp_url());

    // Try to access without token - should be rejected
    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "1.0" }
        },
        "id": 1
    });

    let (status, _body) = session.send_raw_request(init_request)?;
    assert_eq!(status, 401, "Expected 401 Unauthorized without token");

    // Mint a token that allows access to test_repo only
    let token_scopes = json!({
        "gh": {
            "repos": {
                &test_repo: { "read": true }
            }
        }
    });

    let token = session.mint_token("test-admin-key", &token_scopes, 3600)?;

    // Create a new session with the token
    let mut auth_session = McpSession::with_token(&server.mcp_url(), &token);

    // Initialize should now work
    let init_response = auth_session.initialize()?;
    assert!(
        init_response.get("result").is_some(),
        "Expected successful init with token"
    );
    auth_session.send_initialized()?;

    // Access to test_repo should work
    let api_path = format!("repos/{}", test_repo);
    let response = auth_session.call_gh(vec!["api", &api_path])?;

    let result = &response["result"];
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        !is_error,
        "Expected access to {} to succeed with token, got: {}",
        test_repo, result
    );

    // Access to denied_repo should fail (not in token scopes)
    let denied_path = format!("repos/{}", denied_repo);
    let denied_response = auth_session.call_gh(vec!["api", &denied_path])?;

    let denied_result = &denied_response["result"];
    let denied_is_error = denied_result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        denied_is_error,
        "Expected access to {} to be denied by token scopes, got: {}",
        denied_repo, denied_result
    );

    Ok(())
}
integration_test!(test_mcp_token_auth_required_mode);

/// Test that token scopes override server default scopes
fn test_mcp_token_scopes_override_defaults() -> Result<()> {
    let test_repo = get_test_repo();
    let denied_repo = get_denied_repo();

    // Server allows denied_repo by default, but NOT test_repo
    let config = format!(
        r#"
[server]
secret = "test-secret"
admin-key = "admin-key"
mode = "optional"

[gh.repos]
"{}" = {{ read = true }}
"#,
        denied_repo
    );

    let server = McpServerHandle::start(&config)?;
    let session = McpSession::new(&server.mcp_url());

    // Without token, denied_repo should be accessible (server default)
    let mut no_token_session = McpSession::new(&server.mcp_url());
    let _ = no_token_session.initialize()?;
    no_token_session.send_initialized()?;

    let default_path = format!("repos/{}", denied_repo);
    let default_response = no_token_session.call_gh(vec!["api", &default_path])?;
    let default_is_error = default_response["result"]
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        !default_is_error,
        "Expected denied_repo to be accessible with default scopes"
    );

    // Now mint a token that only allows test_repo (different from server default)
    let token_scopes = json!({
        "gh": {
            "repos": {
                &test_repo: { "read": true }
            }
        }
    });

    let token = session.mint_token("admin-key", &token_scopes, 3600)?;

    // With token, test_repo should be accessible
    let mut auth_session = McpSession::with_token(&server.mcp_url(), &token);
    let _ = auth_session.initialize()?;
    auth_session.send_initialized()?;

    let test_path = format!("repos/{}", test_repo);
    let test_response = auth_session.call_gh(vec!["api", &test_path])?;
    let test_is_error = test_response["result"]
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        !test_is_error,
        "Expected test_repo to be accessible with token scopes, got: {}",
        test_response["result"]
    );

    // With token, denied_repo should NOT be accessible (token scopes don't include it)
    let denied_with_token = auth_session.call_gh(vec!["api", &default_path])?;
    let denied_with_token_error = denied_with_token["result"]
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        denied_with_token_error,
        "Expected denied_repo to be blocked by token scopes (overrides server default), got: {}",
        denied_with_token["result"]
    );

    Ok(())
}
integration_test!(test_mcp_token_scopes_override_defaults);

/// Test that invalid tokens are rejected
fn test_mcp_invalid_token_rejected() -> Result<()> {
    let config = r#"
[server]
secret = "correct-secret"
admin-key = "admin-key"
mode = "required"

[gh.repos]
"example/repo" = { read = true }
"#;

    let server = McpServerHandle::start(config)?;

    // Try with a completely invalid token
    let session = McpSession::with_token(&server.mcp_url(), "not-a-valid-jwt");

    let init_request = json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "1.0" }
        },
        "id": 1
    });

    let (status, _body) = session.send_raw_request(init_request)?;
    assert_eq!(status, 401, "Expected 401 for invalid token");

    Ok(())
}
integration_test!(test_mcp_invalid_token_rejected);

/// Test auth mode "none" allows unauthenticated access with default scopes
fn test_mcp_auth_mode_none() -> Result<()> {
    let test_repo = get_test_repo();

    // Auth mode "none" - tokens are ignored, default scopes always used
    let config = format!(
        r#"
[server]
secret = "some-secret"
admin-key = "admin-key"
mode = "none"

[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());

    // Should work without any token
    let _ = session.initialize()?;
    session.send_initialized()?;

    let api_path = format!("repos/{}", test_repo);
    let response = session.call_gh(vec!["api", &api_path])?;

    let is_error = response["result"]
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        !is_error,
        "Expected access in mode=none without token, got: {}",
        response["result"]
    );

    Ok(())
}
integration_test!(test_mcp_auth_mode_none);

// ============================================================================
// GitHub Tool Security Tests
// ============================================================================

/// Test that API write operations are denied without write permission
fn test_mcp_github_api_write_denied_without_permission() -> Result<()> {
    let test_repo = get_test_repo();

    // Only read permission, no write
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try to POST to the repo API
    let response = session.call_github_api_with_method(
        &format!("repos/{}/issues", test_repo),
        "POST",
        Some(json!({"title": "Test issue", "body": "Should be denied"})),
        None,
    )?;

    let result = &response["result"];
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        is_error,
        "Expected write to be denied without write permission, got: {}",
        result
    );

    let error_text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        error_text.contains("not allowed") || error_text.contains("Write access"),
        "Expected permission error, got: {}",
        error_text
    );

    Ok(())
}
integration_test!(test_mcp_github_api_write_denied_without_permission);

/// Test that create-draft-pr is denied without create-draft permission
fn test_mcp_github_create_draft_pr_denied() -> Result<()> {
    let test_repo = get_test_repo();

    // Read-only permission (explicitly disable create-draft)
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true, create-draft = false, pending-review = false }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());
    let _ = session.initialize()?;
    session.send_initialized()?;

    let response =
        session.call_github_create_draft_pr(&test_repo, "test-branch", "main", "Test PR", None)?;

    let result = &response["result"];
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        is_error,
        "Expected create-draft-pr to be denied without permission, got: {}",
        result
    );

    let error_text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        error_text.contains("not granted") || error_text.contains("create-draft"),
        "Expected permission error, got: {}",
        error_text
    );

    Ok(())
}
integration_test!(test_mcp_github_create_draft_pr_denied);

/// Test that pending-review is denied without pending-review permission
fn test_mcp_github_pending_review_denied() -> Result<()> {
    let test_repo = get_test_repo();

    // Read-only permission (explicitly disable pending-review)
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true, create-draft = false, pending-review = false }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());
    let _ = session.initialize()?;
    session.send_initialized()?;

    let response = session.call_github_pending_review("list", &test_repo, 1, None, None)?;

    let result = &response["result"];
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        is_error,
        "Expected pending-review to be denied, got: {}",
        result
    );

    let error_text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        error_text.contains("not granted") || error_text.contains("pending-review"),
        "Expected permission error, got: {}",
        error_text
    );

    Ok(())
}
integration_test!(test_mcp_github_pending_review_denied);

/// Test that non-repo endpoints are rejected
fn test_mcp_github_api_non_repo_endpoint_rejected() -> Result<()> {
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
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try to access /user endpoint (not a repo endpoint)
    let response = session.call_github_api("user", None)?;

    let result = &response["result"];
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(is_error, "Expected non-repo endpoint to be rejected");

    let error_text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        error_text.contains("Could not determine target repository"),
        "Expected repo path error, got: {}",
        error_text
    );

    Ok(())
}
integration_test!(test_mcp_github_api_non_repo_endpoint_rejected);

/// Test HTTP method validation rejects invalid methods
fn test_mcp_github_api_invalid_method_rejected() -> Result<()> {
    let test_repo = get_test_repo();

    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true, write = true }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;
    let mut session = McpSession::new(&server.mcp_url());
    let _ = session.initialize()?;
    session.send_initialized()?;

    // Try an invalid HTTP method
    let response = session.call_github_api_with_method(
        &format!("repos/{}", test_repo),
        "TRACE",
        None,
        None,
    )?;

    let result = &response["result"];
    let is_error = result
        .get("isError")
        .and_then(|e| e.as_bool())
        .unwrap_or(false);
    assert!(
        is_error,
        "Expected invalid method to be rejected, got: {}",
        result
    );

    let error_text = result["content"][0]["text"].as_str().unwrap_or("");
    assert!(
        error_text.contains("Invalid HTTP method"),
        "Expected method validation error, got: {}",
        error_text
    );

    Ok(())
}
integration_test!(test_mcp_github_api_invalid_method_rejected);
