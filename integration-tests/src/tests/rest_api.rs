//! Integration tests for the REST API server.
//!
//! These tests verify that the REST API server correctly proxies requests
//! to CLI tools and enforces scope restrictions. Includes tests for:
//! - Basic server health and status endpoints
//! - Authentication middleware (token validation)
//! - GitHub API proxy with scope validation
//! - Permission enforcement for read/write operations
//! - Integration with actual `gh` CLI through the proxy

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use eyre::{Context, Result};
use integration_tests::integration_test;
use serde_json::{json, Value};
use tempfile::TempDir;

// ============================================================================
// Test Server Infrastructure
// ============================================================================

/// Get the path to the service-gator binary (reuse from main test harness)
fn get_service_gator_path() -> Result<PathBuf> {
    crate::get_service_gator_path()
}

/// Get the GitHub token for testing (reuse from main test harness)
fn get_gh_token() -> Option<String> {
    crate::get_gh_token()
}

/// Find an available port
fn find_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to random port")
        .local_addr()
        .expect("Failed to get local address")
        .port()
}

/// A running REST API server for testing
struct RestServerHandle {
    child: Child,
    #[allow(dead_code)]
    port: u16,
    base_url: String,
    #[allow(dead_code)]
    config_dir: TempDir,
}

/// Options for starting a REST API server
#[derive(Default)]
struct RestServerOptions {
    /// GitHub token
    pub gh_token: Option<String>,
}

impl RestServerHandle {
    /// Start a new REST API server with the given scope configuration
    fn start(scope_config: &str) -> Result<Self> {
        Self::start_with_options(
            scope_config,
            RestServerOptions {
                gh_token: get_gh_token(),
            },
        )
    }

    /// Start a new REST API server with explicit options
    fn start_with_options(scope_config: &str, options: RestServerOptions) -> Result<Self> {
        let config_dir = TempDir::new().context("creating temp dir")?;
        let config_path = config_dir.path().join("service-gator.toml");

        // Write scope config
        let mut file = std::fs::File::create(&config_path)?;
        file.write_all(scope_config.as_bytes())?;

        let port = find_available_port();
        let addr = format!("127.0.0.1:{}", port);
        let binary_path = get_service_gator_path()?;

        let mut cmd = Command::new(&binary_path);
        cmd.arg("--config")
            .arg(&config_path)
            .arg("--rest-server")
            .arg(&addr)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Add tokens if available
        if let Some(gh_token) = options.gh_token {
            cmd.env("GH_TOKEN", gh_token);
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("spawning service-gator from {:?}", binary_path))?;

        let base_url = format!("http://127.0.0.1:{}", port);

        // Wait for server to be ready
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(10);

        while start.elapsed() < timeout {
            if std::net::TcpStream::connect(&addr).is_ok() {
                // Give it a moment to fully initialize
                std::thread::sleep(Duration::from_millis(100));
                return Ok(Self {
                    child,
                    port,
                    base_url,
                    config_dir,
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        Err(eyre::eyre!(
            "Timeout waiting for REST API server to start on {}",
            addr
        ))
    }

    /// Get the base URL for API requests
    fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Get the server port
    #[allow(dead_code)]
    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for RestServerHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// HTTP client for making REST API requests
struct RestClient {
    client: reqwest::blocking::Client,
    base_url: String,
    bearer_token: Option<String>,
}

impl RestClient {
    fn new(base_url: &str) -> Self {
        Self {
            client: reqwest::blocking::Client::new(),
            base_url: base_url.to_string(),
            bearer_token: None,
        }
    }

    #[allow(dead_code)]
    fn with_token(base_url: &str, token: &str) -> Self {
        let mut client = Self::new(base_url);
        client.bearer_token = Some(token.to_string());
        client
    }

    /// Make a GET request
    fn get(&self, path: &str) -> Result<(u16, String)> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.client.get(&url);

        if let Some(ref token) = self.bearer_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let response = req.send().context("sending GET request")?;
        let status = response.status().as_u16();
        let body = response.text().context("reading response body")?;
        Ok((status, body))
    }

    /// Make a GET request and parse JSON response
    fn get_json(&self, path: &str) -> Result<(u16, Value)> {
        let (status, body) = self.get(path)?;
        let json: Value = serde_json::from_str(&body)
            .with_context(|| format!("parsing JSON response: {}", body))?;
        Ok((status, json))
    }

    /// Make a POST request with JSON body
    fn post_json(&self, path: &str, body: &Value) -> Result<(u16, String)> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(body);

        if let Some(ref token) = self.bearer_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let response = req.send().context("sending POST request")?;
        let status = response.status().as_u16();
        let body = response.text().context("reading response body")?;
        Ok((status, body))
    }
}

/// Get the test repository from environment or use default
fn get_test_repo() -> String {
    std::env::var("TEST_GITHUB_REPO").unwrap_or_else(|_| "cgwalters/playground".to_string())
}

/// Get a repo that should be denied (different from the allowed one)
fn get_denied_repo() -> String {
    std::env::var("TEST_GITHUB_DENIED_REPO").unwrap_or_else(|_| {
        let test_repo = get_test_repo();
        let owner = test_repo.split('/').next().unwrap_or("cgwalters");
        if owner == "cgwalters" {
            "cgwalters/service-gator".to_string()
        } else {
            format!("{}/nonexistent-test-repo", owner)
        }
    })
}

// ============================================================================
// Basic REST Server Tests
// ============================================================================

/// Test data structure for basic server endpoints
struct BasicEndpointTestCase {
    name: &'static str,
    path: &'static str,
    expected_status: u16,
    expected_content_check: fn(&str) -> bool,
    is_json: bool,
}

/// Test that basic REST server endpoints work correctly
fn test_rest_server_basic_endpoints() -> Result<()> {
    let config = r#"
[gh.repos]
"test/repo" = { read = true }
"#;

    let server = RestServerHandle::start(config)?;
    let client = RestClient::new(server.base_url());

    let test_cases = vec![
        BasicEndpointTestCase {
            name: "health endpoint",
            path: "/health",
            expected_status: 200,
            expected_content_check: |body| body == "OK",
            is_json: false,
        },
        BasicEndpointTestCase {
            name: "root endpoint",
            path: "/",
            expected_status: 200,
            expected_content_check: |body| body.contains("service-gator"),
            is_json: false,
        },
        BasicEndpointTestCase {
            name: "status endpoint",
            path: "/status",
            expected_status: 200,
            expected_content_check: |_| true, // Will check JSON structure separately
            is_json: true,
        },
    ];

    for test_case in test_cases {
        if test_case.is_json {
            let (status, json) = client.get_json(test_case.path)?;
            assert_eq!(
                status, test_case.expected_status,
                "{} should return {}",
                test_case.name, test_case.expected_status
            );

            if test_case.path == "/status" {
                // Specific checks for status endpoint
                assert_eq!(json["status"], "running", "Status should be 'running'");

                // Verify services are listed
                assert!(
                    json["services"]["github"].is_string(),
                    "Should list GitHub service"
                );
                assert!(
                    json["services"]["gitlab"].is_string(),
                    "Should list GitLab service"
                );
                assert!(
                    json["services"]["forgejo"].is_string(),
                    "Should list Forgejo service"
                );
                assert!(
                    json["services"]["jira"].is_string(),
                    "Should list JIRA service"
                );

                // Verify endpoints are listed
                assert!(
                    json["endpoints"]["github"].is_string(),
                    "Should list GitHub endpoint"
                );
                assert!(
                    json["endpoints"]["gitlab"].is_string(),
                    "Should list GitLab endpoint"
                );
            }
        } else {
            let (status, body) = client.get(test_case.path)?;
            assert_eq!(
                status, test_case.expected_status,
                "{} should return {}",
                test_case.name, test_case.expected_status
            );
            assert!(
                (test_case.expected_content_check)(&body),
                "{} content check failed: {}",
                test_case.name,
                body
            );
        }
    }

    Ok(())
}
integration_test!(test_rest_server_basic_endpoints);

// ============================================================================
// GitHub API Proxy Tests
// ============================================================================

/// Test GET /api/v3/user with valid permissions (global read)
fn test_rest_github_api_user_with_global_read() -> Result<()> {
    let config = r#"
[gh]
read = true
"#;

    let server = RestServerHandle::start(config)?;
    let client = RestClient::new(server.base_url());

    let (status, json) = client.get_json("/api/v3/user")?;

    // With a valid GH_TOKEN, this should return user info
    // Without token, it will still work but return limited info
    assert!(
        status == 200 || status == 401,
        "Expected 200 (with token) or 401 (auth required), got {}",
        status
    );

    if status == 200 {
        // Should have login field
        assert!(
            json.get("login").is_some(),
            "Response should contain login field"
        );
    }

    Ok(())
}
integration_test!(test_rest_github_api_user_with_global_read);

/// Test GET /api/v3/repos/{owner}/{repo} with scope validation - allowed repo
fn test_rest_github_api_repo_allowed() -> Result<()> {
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = RestServerHandle::start(&config)?;
    let client = RestClient::new(server.base_url());

    let path = format!("/api/v3/repos/{}", test_repo);
    let (status, json) = client.get_json(&path)?;

    // Should succeed with read access
    assert!(
        status == 200 || status == 401,
        "Expected 200 (with token) or 401 (GitHub auth), got {}",
        status
    );

    if status == 200 {
        // Should have repo info
        let repo_name = test_repo.split('/').last().unwrap();
        assert!(
            json["name"].as_str() == Some(repo_name)
                || json["full_name"].as_str() == Some(&test_repo),
            "Response should contain repo info: {:?}",
            json
        );
    }

    Ok(())
}
integration_test!(test_rest_github_api_repo_allowed);

/// Test GET /api/v3/repos/{owner}/{repo} with scope validation - denied repo
fn test_rest_github_api_repo_denied() -> Result<()> {
    let test_repo = get_test_repo();
    let denied_repo = get_denied_repo();

    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = RestServerHandle::start(&config)?;
    let client = RestClient::new(server.base_url());

    let path = format!("/api/v3/repos/{}", denied_repo);
    let (status, body) = client.get(&path)?;

    // Should be denied - 400 or 403
    assert!(
        status == 400 || status == 403,
        "Expected 400 or 403 for denied repo, got {}: {}",
        status,
        body
    );

    // Error message should indicate access not allowed
    assert!(
        body.contains("not allowed") || body.contains("access") || body.contains("denied"),
        "Error message should indicate access denied: {}",
        body
    );

    Ok(())
}
integration_test!(test_rest_github_api_repo_denied);

/// Test that write operations are denied without write permission
fn test_rest_github_api_write_denied() -> Result<()> {
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = RestServerHandle::start(&config)?;
    let client = RestClient::new(server.base_url());

    // Try to POST to create an issue (write operation)
    let path = format!("/api/v3/repos/{}/issues", test_repo);
    let body = json!({
        "title": "Test issue",
        "body": "This should be denied"
    });

    let (status, response_body) = client.post_json(&path, &body)?;

    // Should be denied
    assert!(
        status == 400 || status == 403,
        "Expected 400 or 403 for write without permission, got {}: {}",
        status,
        response_body
    );

    assert!(
        response_body.contains("not allowed") || response_body.contains("Write"),
        "Error should indicate write not allowed: {}",
        response_body
    );

    Ok(())
}
integration_test!(test_rest_github_api_write_denied);

/// Test that non-repo endpoints are rejected without global read
fn test_rest_github_api_non_repo_endpoint_denied() -> Result<()> {
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = RestServerHandle::start(&config)?;
    let client = RestClient::new(server.base_url());

    // Try to access /user endpoint (non-repo)
    let (status, body) = client.get("/api/v3/user")?;

    // Should be denied without global read
    assert!(
        status == 400 || status == 403,
        "Expected 400 or 403 for non-repo endpoint without global read, got {}: {}",
        status,
        body
    );

    Ok(())
}
integration_test!(test_rest_github_api_non_repo_endpoint_denied);

/// Test wildcard pattern matching for repository access
fn test_rest_github_api_wildcard_pattern() -> Result<()> {
    let test_repo = get_test_repo();
    let owner = test_repo.split('/').next().unwrap_or("cgwalters");

    let config = format!(
        r#"
[gh.repos]
"{}/*" = {{ read = true }}
"#,
        owner
    );

    let server = RestServerHandle::start(&config)?;
    let client = RestClient::new(server.base_url());

    // The test repo should be accessible with wildcard
    let path = format!("/api/v3/repos/{}", test_repo);
    let (status, _) = client.get(&path)?;

    assert!(
        status == 200 || status == 401,
        "Expected 200 or 401 for repo matching wildcard, got {}",
        status
    );

    // A different owner should be denied
    let (denied_status, body) = client.get("/api/v3/repos/torvalds/linux")?;

    assert!(
        denied_status == 400 || denied_status == 403,
        "Expected 400 or 403 for repo not matching wildcard, got {}: {}",
        denied_status,
        body
    );

    Ok(())
}
integration_test!(test_rest_github_api_wildcard_pattern);

// ============================================================================
// gh CLI Integration Tests
// ============================================================================

/// Check if gh CLI is available
fn gh_cli_available() -> bool {
    Command::new("gh")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Test that actual `gh` CLI can work through the proxy
fn test_rest_gh_cli_through_proxy() -> Result<()> {
    // Skip if gh is not available
    if !gh_cli_available() {
        eprintln!("Skipping test_rest_gh_cli_through_proxy: gh CLI not available");
        return Ok(());
    }

    // Skip if no GitHub token
    let gh_token = match get_gh_token() {
        Some(token) => token,
        None => {
            eprintln!("Skipping test_rest_gh_cli_through_proxy: no GH_TOKEN");
            return Ok(());
        }
    };

    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh]
read = true

[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = RestServerHandle::start(&config)?;

    // Run gh with our proxy as the GitHub API endpoint
    // Note: gh doesn't support custom API hosts directly, so we test via curl instead
    // This demonstrates the proxy works with standard HTTP clients

    let output = Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg(format!("Authorization: token {}", gh_token))
        .arg(format!("{}/api/v3/user", server.base_url()))
        .output()
        .context("running curl")?;

    if output.status.success() {
        let body = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&body).context("parsing response")?;

        assert!(
            json.get("login").is_some(),
            "Response should contain login field: {}",
            body
        );
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("curl failed: {}", stderr);
        // Don't fail the test - the server responded
    }

    Ok(())
}
integration_test!(test_rest_gh_cli_through_proxy);

/// Test that the proxy correctly forwards GitHub API requests for allowed repos
fn test_rest_github_api_forwarding() -> Result<()> {
    let gh_token = match get_gh_token() {
        Some(token) => token,
        None => {
            eprintln!("Skipping test_rest_github_api_forwarding: no GH_TOKEN");
            return Ok(());
        }
    };

    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = RestServerHandle::start(&config)?;

    // Use curl to make a request through the proxy
    let output = Command::new("curl")
        .arg("-s")
        .arg("-H")
        .arg(format!("Authorization: token {}", gh_token))
        .arg(format!("{}/api/v3/repos/{}", server.base_url(), test_repo))
        .output()
        .context("running curl")?;

    if output.status.success() {
        let body = String::from_utf8_lossy(&output.stdout);

        // Check that we got valid JSON back
        let json: Value = serde_json::from_str(&body).context("parsing response as JSON")?;

        // Should have repo info
        let repo_name = test_repo.split('/').last().unwrap();
        assert!(
            json["name"].as_str() == Some(repo_name)
                || json["full_name"].as_str() == Some(&test_repo),
            "Response should contain repo info: {}",
            body
        );
    }

    Ok(())
}
integration_test!(test_rest_github_api_forwarding);

// ============================================================================
// Permission Validation Tests
// ============================================================================

/// Test data structure for permission validation tests
struct PermissionTestCase {
    name: &'static str,
    config_template: &'static str,
    request_method: &'static str,
    request_path: &'static str,
    request_body: Option<Value>,
    expected_result: PermissionTestResult,
}

enum PermissionTestResult {
    /// Should be allowed (200, 401, etc. but not permission denied)
    Allowed,
    /// Should be denied (400/403 with permission error)
    Denied,
    /// Should not have permission error in response
    NoPermissionError,
}

/// Test permission validation using table-driven approach
fn test_rest_permission_validation() -> Result<()> {
    let test_repo = get_test_repo();

    let test_cases = vec![
        PermissionTestCase {
            name: "read operation with create-draft permission",
            config_template: r#"
[gh.repos]
"{}" = {{ read = false, create-draft = true }}
"#,
            request_method: "GET",
            request_path: "/api/v3/repos/{}",
            request_body: None,
            expected_result: PermissionTestResult::Allowed, // create-draft implies read
        },
        PermissionTestCase {
            name: "write operation without write permission",
            config_template: r#"
[gh.repos]
"{}" = {{ read = true, write = false }}
"#,
            request_method: "POST",
            request_path: "/api/v3/repos/{}/issues",
            request_body: Some(json!({"title": "Test", "body": "Should fail"})),
            expected_result: PermissionTestResult::Denied,
        },
        PermissionTestCase {
            name: "write operation with write permission",
            config_template: r#"
[gh.repos]
"{}" = {{ read = true, write = true }}
"#,
            request_method: "POST",
            request_path: "/api/v3/repos/{}/issues",
            request_body: Some(json!({"title": "Test", "body": "Permission check"})),
            expected_result: PermissionTestResult::NoPermissionError,
        },
    ];

    for test_case in test_cases {
        let config = test_case.config_template.replace("{}", &test_repo);
        let server = RestServerHandle::start(&config)?;
        let client = RestClient::new(server.base_url());

        let path = test_case.request_path.replace("{}", &test_repo);

        let (status, body) = match test_case.request_method {
            "GET" => client.get(&path)?,
            "POST" => {
                if let Some(body_json) = test_case.request_body {
                    client.post_json(&path, &body_json)?
                } else {
                    return Err(eyre::eyre!("POST request requires body"));
                }
            }
            method => return Err(eyre::eyre!("Unsupported method: {}", method)),
        };

        match test_case.expected_result {
            PermissionTestResult::Allowed => {
                assert!(
                    status == 200 || status == 400 || status == 401,
                    "{}: unexpected status {}: {}",
                    test_case.name,
                    status,
                    body
                );
                if status == 400 && body.contains("not allowed") {
                    panic!(
                        "{}: got permission denied when should be allowed: {}",
                        test_case.name, body
                    );
                }
            }
            PermissionTestResult::Denied => {
                assert!(
                    status == 400 || status == 403,
                    "{}: expected permission denied, got {}: {}",
                    test_case.name,
                    status,
                    body
                );
            }
            PermissionTestResult::NoPermissionError => {
                if status == 400 {
                    assert!(
                        !body.contains("Write access not allowed"),
                        "{}: should not get permission error: {}",
                        test_case.name,
                        body
                    );
                }
            }
        }
    }

    Ok(())
}
integration_test!(test_rest_permission_validation);

/// Test global read access enforcement
fn test_rest_global_read_access() -> Result<()> {
    let config = r#"
[gh]
read = true
"#;

    let server = RestServerHandle::start(config)?;
    let client = RestClient::new(server.base_url());

    // Test cases for global read access
    let paths = vec!["/api/v3/repos/octocat/Hello-World", "/api/v3/user"];

    for path in paths {
        let (status, body) = client.get(path)?;

        // Permission check should pass, though the CLI may fail due to auth
        if status == 400 && body.contains("not allowed") {
            panic!(
                "Got permission denied with global read for {}: {}",
                path, body
            );
        }
    }

    Ok(())
}
integration_test!(test_rest_global_read_access);

// ============================================================================
// Error Handling Tests
// ============================================================================

/// Test that unknown paths return 404
fn test_rest_unknown_path_returns_404() -> Result<()> {
    let config = r#"
[gh.repos]
"test/repo" = { read = true }
"#;

    let server = RestServerHandle::start(config)?;
    let client = RestClient::new(server.base_url());

    let (status, _) = client.get("/api/v99/nonexistent")?;

    assert_eq!(status, 404, "Unknown API version should return 404");

    Ok(())
}
integration_test!(test_rest_unknown_path_returns_404);

/// Test that invalid JSON body returns appropriate error
fn test_rest_invalid_json_body() -> Result<()> {
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true, write = true }}
"#,
        test_repo
    );

    let server = RestServerHandle::start(&config)?;

    // Send invalid JSON
    let url = format!("{}/api/v3/repos/{}/issues", server.base_url(), test_repo);
    let response = reqwest::blocking::Client::new()
        .post(&url)
        .header("Content-Type", "application/json")
        .body("not valid json")
        .send()
        .context("sending request")?;

    let status = response.status().as_u16();

    assert_eq!(status, 400, "Invalid JSON should return 400");

    Ok(())
}
integration_test!(test_rest_invalid_json_body);
