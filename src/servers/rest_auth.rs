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
    /// Scopes configuration receiver (updated by file watcher if enabled).
    pub scopes: watch::Receiver<ScopeConfig>,
}

/// Authentication middleware function for the REST server.
/// This middleware reads the current scopes from the watch receiver,
/// enabling live reload of permissions when --scope-file is used.
pub async fn rest_auth_middleware(
    State(auth_state): State<RestAuthState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get the current scopes from the watch receiver (supports live reload)
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
