//! MCP (Model Context Protocol) server wrapper.
//!
//! This module re-exports the main MCP server implementation.
//! The actual implementation is in `crate::mcp`.

// Re-export from the main mcp module for backwards compatibility
pub use crate::mcp::start_mcp_server;
