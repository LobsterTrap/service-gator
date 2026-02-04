//! MCP (Model Context Protocol) server implementation.

use eyre::Result;
use std::future::Future;
use std::pin::Pin;

use crate::auth::ServerConfig;
use crate::servers::Server;

/// MCP server implementation.
pub struct McpServerImpl;

impl McpServerImpl {
    /// Create a new MCP server.
    pub fn new() -> Self {
        Self
    }
}

impl Default for McpServerImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl Server for McpServerImpl {
    fn start(
        &self,
        addr: String,
        config: ServerConfig,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move {
            // Delegate to the existing MCP server implementation
            crate::mcp::start_server_with_config(&addr, config).await
        })
    }
}

/// Start the MCP server with the given configuration.
///
/// This is the new entry point that wraps the existing implementation.
pub async fn start_server(addr: &str, config: ServerConfig) -> Result<()> {
    let server = McpServerImpl::new();
    server.start(addr.to_string(), config).await
}
