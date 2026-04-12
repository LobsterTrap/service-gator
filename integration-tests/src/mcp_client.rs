//! MCP client helpers using the rmcp crate
//!
//! This module provides a proper MCP client implementation for integration tests
//! using the rmcp crate's streamable HTTP transport, which correctly handles
//! the MCP protocol including SSE streams and session management.

use eyre::{Context, Result};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult, ClientInfo, Implementation},
    service::RunningService,
    transport::streamable_http_client::{
        StreamableHttpClientTransport, StreamableHttpClientTransportConfig,
    },
    ClientHandler, RoleClient, ServiceExt,
};

/// A minimal client handler for integration tests
#[derive(Clone, Default)]
pub struct TestClientHandler;

impl ClientHandler for TestClientHandler {
    fn get_info(&self) -> ClientInfo {
        ClientInfo {
            client_info: Implementation {
                name: "integration-test".into(),
                version: "1.0.0".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

/// A connected MCP client session using the rmcp library
pub struct RmcpSession {
    service: RunningService<RoleClient, TestClientHandler>,
}

impl RmcpSession {
    /// Connect to an MCP server at the given URL
    pub async fn connect(mcp_url: &str) -> Result<Self> {
        Self::connect_with_token(mcp_url, None).await
    }

    /// Connect to an MCP server with an optional Bearer token
    pub async fn connect_with_token(mcp_url: &str, token: Option<&str>) -> Result<Self> {
        let mut config = StreamableHttpClientTransportConfig::with_uri(mcp_url);

        if let Some(token) = token {
            config = config.auth_header(token);
        }

        let transport = StreamableHttpClientTransport::from_config(config);

        let service = TestClientHandler
            .serve(transport)
            .await
            .context("connecting to MCP server")?;

        Ok(Self { service })
    }

    /// List all available tools from the server
    pub async fn list_tools(&self) -> Result<Vec<rmcp::model::Tool>> {
        self.service
            .list_all_tools()
            .await
            .context("listing tools")
            .map_err(Into::into)
    }

    /// Call a tool by name with the given arguments
    pub async fn call_tool(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<CallToolResult> {
        let args = arguments.as_object().cloned();

        self.service
            .call_tool(CallToolRequestParams {
                name: name.to_string().into(),
                arguments: args,
                meta: None,
                task: None,
            })
            .await
            .context("calling tool")
            .map_err(Into::into)
    }

    /// Get the server info from the connected server
    pub fn server_info(&self) -> Option<&rmcp::model::ServerInfo> {
        self.service.peer_info()
    }

    /// Cancel and close the session
    pub async fn close(self) -> Result<()> {
        self.service.cancel().await.context("closing session")?;
        Ok(())
    }
}

/// Helper to extract text content from a CallToolResult
pub fn get_result_text(result: &CallToolResult) -> Option<String> {
    result.content.first().and_then(|c| {
        if let rmcp::model::RawContent::Text(text) = &c.raw {
            Some(text.text.clone())
        } else {
            None
        }
    })
}

/// Helper to check if a CallToolResult is an error
pub fn is_error_result(result: &CallToolResult) -> bool {
    result.is_error.unwrap_or(false)
}
