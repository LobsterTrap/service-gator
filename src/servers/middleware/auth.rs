//! Authentication middleware for service-gator servers.
//!
//! This middleware handles JWT token validation and scope resolution
//! for both MCP and REST API servers.

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};

use crate::auth::{AuthMode, ServerConfig, TokenAuthority, TokenError};
use crate::mcp::ResolvedScopes;
use crate::scope::ScopeConfig;

/// Authentication middleware that validates JWT tokens and resolves scopes.
#[derive(Clone)]
pub struct AuthMiddleware {
    config: ServerConfig,
    token_authority: Option<TokenAuthority>,
}

impl AuthMiddleware {
    /// Create a new authentication middleware.
    pub fn new(config: ServerConfig) -> Self {
        let token_authority = config
            .server
            .secret
            .as_ref()
            .map(|secret| TokenAuthority::new(secret.expose_secret()));

        Self {
            config,
            token_authority,
        }
    }

    // TODO: Add auth middleware integration later
}

/// Authentication middleware function for axum.
pub async fn auth_middleware_fn(
    axum::extract::State(auth): axum::extract::State<AuthMiddleware>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Resolve scopes based on auth mode and token
    let resolved_scopes = auth.resolve_scopes_from_request(&req).await?;

    // Insert resolved scopes into request extensions
    req.extensions_mut().insert(ResolvedScopes(resolved_scopes));

    // Continue to the next middleware/handler
    Ok(next.run(req).await)
}

impl AuthMiddleware {
    /// Resolve scopes from the incoming request based on auth configuration.
    pub async fn resolve_scopes_from_request(
        &self,
        req: &Request<Body>,
    ) -> Result<ScopeConfig, StatusCode> {
        match self.config.server.mode {
            AuthMode::None => {
                // No authentication required, use default scopes
                Ok(self.config.scopes.clone())
            }
            AuthMode::Optional => {
                // Check for Authorization header
                if let Some(auth_header) = req.headers().get("authorization") {
                    self.validate_token_and_get_scopes(auth_header).await
                } else {
                    // No token provided, use default scopes
                    Ok(self.config.scopes.clone())
                }
            }
            AuthMode::Required => {
                // Token is required
                let auth_header = req
                    .headers()
                    .get("authorization")
                    .ok_or(StatusCode::UNAUTHORIZED)?;
                self.validate_token_and_get_scopes(auth_header).await
            }
        }
    }

    /// Validate JWT token and extract scopes.
    async fn validate_token_and_get_scopes(
        &self,
        auth_header: &HeaderValue,
    ) -> Result<ScopeConfig, StatusCode> {
        let token_authority = self
            .token_authority
            .as_ref()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

        // Extract token from "Bearer <token>" format
        let auth_str = auth_header.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
        let token = auth_str
            .strip_prefix("Bearer ")
            .ok_or(StatusCode::BAD_REQUEST)?;

        // Validate and decode the token
        match token_authority.validate(token) {
            Ok(claims) => Ok(claims.scopes),
            Err(TokenError::Expired) => Err(StatusCode::UNAUTHORIZED),
            Err(TokenError::InvalidSignature) => Err(StatusCode::UNAUTHORIZED),
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}
