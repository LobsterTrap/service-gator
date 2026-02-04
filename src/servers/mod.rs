//! Server implementations for service-gator.
//!
//! This module provides the dual server architecture supporting both:
//! - MCP (Model Context Protocol) server for AI agents
//! - REST API server for HTTP-based integration
//!
//! Both servers share the same core authentication and scope validation logic
//! through shared middleware.

use eyre::Result;
use std::future::Future;
use std::pin::Pin;

use crate::auth::ServerConfig;

pub mod mcp;
pub mod middleware;
pub mod rest;
pub mod rest_auth;

/// Trait for server implementations.
///
/// This allows both MCP and REST servers to be started uniformly.
pub trait Server: Send + Sync {
    /// Start the server and run until shutdown.
    fn start(
        &self,
        addr: String,
        config: ServerConfig,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>>;
}

/// Server factory for creating different types of servers.
pub struct ServerFactory;

impl ServerFactory {
    /// Create a new MCP server instance.
    pub fn create_mcp_server() -> Box<dyn Server> {
        Box::new(mcp::McpServerImpl::new())
    }

    /// Create a new REST API server instance.
    pub fn create_rest_server() -> Box<dyn Server> {
        Box::new(rest::RestServerImpl::new())
    }
}

/// Server mode enumeration.
#[derive(Debug, Clone)]
pub enum ServerMode {
    /// Only MCP server
    Mcp,
    /// Only REST server
    Rest,
    /// Both servers (dual mode)
    Dual,
}

/// Run server(s) based on the specified mode.
pub async fn run_servers(
    mode: ServerMode,
    mcp_addr: Option<&str>,
    rest_addr: Option<&str>,
    config: ServerConfig,
    scope_file: Option<std::path::PathBuf>,
) -> Result<()> {
    use eyre::Context;

    // Set up scopes: file-watched if --scope-file provided, static otherwise
    let scopes = match &scope_file {
        Some(path) => crate::config_watcher::watch_scopes(path)
            .await
            .with_context(|| format!("loading scope file {}", path.display()))?,
        None => crate::config_watcher::static_scopes(config.scopes.clone()),
    };

    match mode {
        ServerMode::Mcp => {
            let addr = mcp_addr.unwrap_or("127.0.0.1:8080");
            crate::mcp::start_mcp_server(addr, config, scopes).await
        }
        ServerMode::Rest => {
            let addr = rest_addr.unwrap_or("127.0.0.1:8081");
            rest::start_rest_server_with_scopes(addr, config, scopes).await
        }
        ServerMode::Dual => {
            let mcp_addr = mcp_addr.unwrap_or("127.0.0.1:8080");
            let rest_addr = rest_addr.unwrap_or("127.0.0.1:8081");

            // Clone config for the REST server
            let rest_config = ServerConfig {
                server: config.server.clone(),
                scopes: config.scopes.clone(),
            };

            // Clone scopes receiver for REST server
            let rest_scopes = scopes.clone();

            // Run both servers concurrently
            tokio::try_join!(
                crate::mcp::start_mcp_server(mcp_addr, config, scopes),
                rest::start_rest_server_with_scopes(rest_addr, rest_config, rest_scopes)
            )?;

            Ok(())
        }
    }
}
