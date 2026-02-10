//! Simple authentication middleware for REST API server.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use tokio::sync::watch;

use crate::auth::ServerConfig;
use crate::mcp::ResolvedScopes;
use crate::scope::ScopeConfig;

/// Simple authentication middleware state.
#[derive(Clone)]
pub struct RestAuthState {
    pub config: ServerConfig,
    /// Dynamic scopes receiver for live reload support.
    pub scopes: watch::Receiver<ScopeConfig>,
}

/// Authentication middleware function for the REST server.
/// This is a simplified version that always uses the current scopes from the watcher.
/// TODO: Add JWT token validation when needed.
pub async fn rest_auth_middleware(
    State(auth_state): State<RestAuthState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get current scopes from the watcher (supports live reload)
    let scopes = auth_state.scopes.borrow().clone();

    // Insert resolved scopes into request extensions
    req.extensions_mut().insert(ResolvedScopes(scopes));

    // Continue to the next middleware/handler
    Ok(next.run(req).await)
}

impl RestAuthState {
    pub fn new(config: ServerConfig, scopes: watch::Receiver<ScopeConfig>) -> Self {
        Self { config, scopes }
    }
}
