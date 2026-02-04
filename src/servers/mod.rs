//! Server implementations for service-gator.
//!
//! This module provides the dual server architecture supporting both:
//! - MCP (Model Context Protocol) server for AI agents
//! - REST API server for HTTP-based integration
//!
//! Both servers share the same core authentication and scope validation logic
//! through shared middleware.

use eyre::Result;
use tokio::sync::watch;

use crate::auth::ServerConfig;
use crate::scope::ScopeConfig;

pub mod mcp;
pub mod middleware;
pub mod rest;
pub mod rest_auth;

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

/// Run server(s) based on the specified mode with dynamic scope support.
///
/// The `scopes` receiver provides live-reloadable scope configuration.
/// Both MCP and REST servers will observe scope changes.
pub async fn run_servers(
    mode: ServerMode,
    mcp_addr: Option<&str>,
    rest_addr: Option<&str>,
    config: ServerConfig,
    scopes: watch::Receiver<ScopeConfig>,
) -> Result<()> {
    match mode {
        ServerMode::Mcp => {
            let addr = mcp_addr.unwrap_or("127.0.0.1:8080");
            crate::mcp::start_mcp_server(addr, config, scopes).await
        }
        ServerMode::Rest => {
            let addr = rest_addr.unwrap_or("127.0.0.1:8081");
            rest::start_rest_server(addr, config, scopes).await
        }
        ServerMode::Dual => {
            let mcp_addr = mcp_addr.unwrap_or("127.0.0.1:8080");
            let rest_addr = rest_addr.unwrap_or("127.0.0.1:8081");

            // Clone config for the second server
            let rest_config = ServerConfig {
                server: config.server.clone(),
                scopes: config.scopes.clone(),
            };

            // Clone the scopes receiver for the REST server
            let rest_scopes = scopes.clone();

            // Run both servers concurrently
            tokio::try_join!(
                crate::mcp::start_mcp_server(mcp_addr, config, scopes),
                rest::start_rest_server(rest_addr, rest_config, rest_scopes)
            )?;

            Ok(())
        }
    }
}
