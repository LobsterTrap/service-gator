//! Shared middleware for service-gator servers.
//!
//! This module contains middleware that can be used by both MCP and REST servers
//! to provide consistent authentication, CORS, and logging behavior.

pub mod auth;
pub mod cors;
pub mod logging;
