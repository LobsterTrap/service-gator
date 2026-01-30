//! Integration tests using the rmcp crate for proper MCP protocol handling
//!
//! These tests use the official rmcp library to connect to the service-gator
//! MCP server, providing better protocol compliance testing than raw HTTP.

use eyre::Result;
use integration_tests::integration_test;

use crate::mcp_client::{get_result_text, is_error_result, RmcpSession};
use crate::McpServerHandle;

/// Get the test repository from environment or use default
fn get_test_repo() -> String {
    std::env::var("TEST_GITHUB_REPO").unwrap_or_else(|_| "cgwalters/playground".to_string())
}

/// Get the test owner from the test repo
fn get_test_owner() -> String {
    let repo = get_test_repo();
    repo.split('/').next().unwrap_or("cgwalters").to_string()
}

/// Test that the MCP server can be connected to using the rmcp client
fn test_rmcp_client_connect() -> Result<()> {
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;

    // Use tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let session = RmcpSession::connect(&server.mcp_url()).await?;

        // Verify we can get server info
        let server_info = session.server_info();
        assert!(
            server_info.is_some(),
            "Expected server info after connection"
        );

        let info = server_info.unwrap();
        assert!(
            info.server_info.name.contains("service-gator") || !info.server_info.name.is_empty(),
            "Expected valid server name, got: {}",
            info.server_info.name
        );

        session.close().await?;
        Ok(())
    })
}
integration_test!(test_rmcp_client_connect);

/// Test listing tools via the rmcp client
fn test_rmcp_client_list_tools() -> Result<()> {
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let session = RmcpSession::connect(&server.mcp_url()).await?;

        let tools = session.list_tools().await?;
        assert!(!tools.is_empty(), "Expected at least one tool");

        // Verify the 'github_api_tool' is present
        let gh_tool = tools.iter().find(|t| t.name == "github_api_tool");
        assert!(
            gh_tool.is_some(),
            "Expected 'github_api_tool' to be available"
        );

        session.close().await?;
        Ok(())
    })
}
integration_test!(test_rmcp_client_list_tools);

/// Test calling the gh tool to access an allowed repository
fn test_rmcp_client_gh_allowed_repo() -> Result<()> {
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let session = RmcpSession::connect(&server.mcp_url()).await?;

        // Call github_api_tool to get repo info
        let api_path = format!("repos/{}", test_repo);
        let result = session
            .call_tool(
                "github_api_tool",
                serde_json::json!({
                    "endpoint": api_path
                }),
            )
            .await?;

        assert!(
            !is_error_result(&result),
            "Expected successful response, got error: {:?}",
            get_result_text(&result)
        );

        // Verify we got repo data
        let text = get_result_text(&result).expect("Expected text content");
        let repo_name = test_repo.split('/').last().unwrap_or(&test_repo);
        assert!(
            text.contains(repo_name) || text.contains(&get_test_owner()),
            "Expected repo info in response, got: {}",
            text
        );

        session.close().await?;
        Ok(())
    })
}
integration_test!(test_rmcp_client_gh_allowed_repo);

/// Test that accessing a denied repository returns an error
fn test_rmcp_client_gh_denied_repo() -> Result<()> {
    let test_repo = get_test_repo();
    let config = format!(
        r#"
[gh.repos]
"{}" = {{ read = true }}
"#,
        test_repo
    );

    let server = McpServerHandle::start(&config)?;

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let session = RmcpSession::connect(&server.mcp_url()).await?;

        // Try to access a repo that is NOT in the allowed list
        let result = session
            .call_tool(
                "github_api_tool",
                serde_json::json!({
                    "endpoint": "repos/torvalds/linux"
                }),
            )
            .await?;

        assert!(
            is_error_result(&result),
            "Expected access to be denied for torvalds/linux, got: {:?}",
            get_result_text(&result)
        );

        // Verify the error message mentions access denied
        let error_text = get_result_text(&result).unwrap_or_default();
        assert!(
            error_text.contains("not allowed") || error_text.contains("access"),
            "Expected 'not allowed' in error message, got: {}",
            error_text
        );

        session.close().await?;
        Ok(())
    })
}
integration_test!(test_rmcp_client_gh_denied_repo);

/// Test wildcard patterns work correctly with rmcp client
fn test_rmcp_client_wildcard_pattern() -> Result<()> {
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

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let session = RmcpSession::connect(&server.mcp_url()).await?;

        // The test repo should be accessible with wildcard
        let api_path = format!("repos/{}", test_repo);
        let result = session
            .call_tool(
                "github_api_tool",
                serde_json::json!({
                    "endpoint": api_path
                }),
            )
            .await?;

        assert!(
            !is_error_result(&result),
            "Expected {} to be accessible with wildcard, got error: {:?}",
            test_repo,
            get_result_text(&result)
        );

        // A different owner should be denied
        let denied_result = session
            .call_tool(
                "github_api_tool",
                serde_json::json!({
                    "endpoint": "repos/torvalds/linux"
                }),
            )
            .await?;

        assert!(
            is_error_result(&denied_result),
            "Expected torvalds/linux to be denied, got: {:?}",
            get_result_text(&denied_result)
        );

        session.close().await?;
        Ok(())
    })
}
integration_test!(test_rmcp_client_wildcard_pattern);
