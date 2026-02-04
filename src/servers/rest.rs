//! Simplified REST API server implementation.
//!
//! This server provides HTTP endpoints that expose service-gator functionality
//! via REST API instead of MCP protocol. It includes GitHub, GitLab, Forgejo,
//! and JIRA API compatibility endpoints using a unified service architecture.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use axum::{
    extract::{Query, State},
    http::{Method, StatusCode},
    middleware,
    response::{IntoResponse, Json, Response},
    routing::{any, get},
    Router,
};
use eyre::{Context, Result};
use serde_json::Value;
use tokio::sync::watch;
use tower_http::cors::CorsLayer;
use tracing::{error, info};

use crate::auth::ServerConfig;
use crate::mcp::ResolvedScopes;
use crate::scope::ScopeConfig;
use crate::servers::rest_auth::{rest_auth_middleware, RestAuthState};
use crate::servers::Server;
use crate::services::{ServiceContext, ServiceRegistry};

/// REST API server implementation.
pub struct RestServerImpl;

impl RestServerImpl {
    /// Create a new REST API server.
    pub fn new() -> Self {
        Self
    }
}

impl Default for RestServerImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl Server for RestServerImpl {
    fn start(
        &self,
        addr: String,
        config: ServerConfig,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> {
        Box::pin(async move { start_rest_server(&addr, config).await })
    }
}

/// Application state for the REST API server.
#[derive(Clone)]
pub struct RestApiState {
    pub config: ServerConfig,
    pub service_registry: ServiceRegistry,
    /// Scopes configuration receiver (updated by file watcher if enabled).
    pub scopes: watch::Receiver<ScopeConfig>,
}

/// Start the REST API server (legacy, uses static scopes).
async fn start_rest_server(addr: &str, config: ServerConfig) -> Result<()> {
    let scopes = crate::config_watcher::static_scopes(config.scopes.clone());
    start_rest_server_with_scopes(addr, config, scopes).await
}

/// Start the REST API server with scopes configuration.
///
/// The `scopes` receiver provides access to scope configuration,
/// and may be updated by a file watcher for live reload.
pub async fn start_rest_server_with_scopes(
    addr: &str,
    config: ServerConfig,
    scopes: watch::Receiver<ScopeConfig>,
) -> Result<()> {
    let socket_addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid REST server address: {}", addr))?;

    let state = RestApiState {
        config: config.clone(),
        service_registry: ServiceRegistry::new(),
        scopes: scopes.clone(),
    };

    let auth_state = RestAuthState::new(config.clone(), scopes);

    // Create authenticated API routes using generic handlers
    let api_routes = Router::new()
        // GitHub API v3 compatibility endpoints
        .route("/api/v3/{*path}", any(generic_api_handler))
        // GitLab API v4 compatibility endpoints
        .route("/api/v4/{*path}", any(generic_api_handler))
        // Forgejo/Gitea API v1 compatibility endpoints
        .route("/api/v1/{*path}", any(generic_api_handler))
        // JIRA REST API v2 compatibility endpoints
        .route("/rest/api/2/{*path}", any(generic_api_handler))
        .route("/rest/api/{*path}", any(generic_api_handler))
        // GitHub API without /api/v3 prefix (for github.localhost compatibility)
        // gh CLI with GH_HOST=github.localhost hits paths like /user, /repos, etc. directly
        .route("/user", any(github_localhost_handler))
        .route("/user/{*path}", any(github_localhost_handler))
        .route("/repos/{*path}", any(github_localhost_handler))
        .route("/gists", any(github_localhost_handler))
        .route("/gists/{*path}", any(github_localhost_handler))
        .route("/orgs/{*path}", any(github_localhost_handler))
        .route("/search/{*path}", any(github_localhost_handler))
        .route("/graphql", any(github_localhost_handler))
        // Add authentication middleware for all API routes
        .layer(middleware::from_fn_with_state(
            auth_state,
            rest_auth_middleware,
        ))
        .with_state(state.clone());

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/status", get(status))
        // Merge the authenticated API routes
        .merge(api_routes)
        // Add CORS middleware
        .layer(CorsLayer::permissive())
        .with_state(state);

    info!("Starting REST API server on {}", socket_addr);
    info!("GitHub API v3 compatibility endpoints available at /api/v3/*");
    info!("GitLab API v4 compatibility endpoints available at /api/v4/*");
    info!("Forgejo/Gitea API v1 compatibility endpoints available at /api/v1/*");
    info!("JIRA REST API v2 compatibility endpoints available at /rest/api/2/*");
    
    let listener = tokio::net::TcpListener::bind(socket_addr).await?;

    axum::serve(listener, app)
        .await
        .context("REST API server failed")?;

    Ok(())
}

/// Generic API handler that routes requests to the appropriate service.
async fn generic_api_handler(
    State(state): State<RestApiState>,
    axum::extract::Extension(scopes): axum::extract::Extension<ResolvedScopes>,
    method: Method,
    uri: axum::http::Uri,
    Query(params): Query<HashMap<String, String>>,
    body: String,
) -> Response {
    let path = uri.path();
    let method_str = method.as_str();

    // Parse JSON body if provided
    let json_body = if !body.is_empty() {
        match serde_json::from_str::<Value>(&body) {
            Ok(json) => Some(json),
            Err(e) => {
                error!(body = %body, error = %e, "Failed to parse JSON body");
                return api_error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid JSON body: {}", e),
                );
            }
        }
    } else {
        None
    };

    // Get service for this path
    let service = match state.service_registry.get_service(path) {
        Some(s) => s,
        None => {
            return api_error_response(
                StatusCode::NOT_FOUND,
                &format!("No service found for path: {}", path),
            );
        }
    };

    // Extract endpoint (remove API prefix)
    let endpoint = if path.starts_with("/api/v3/") {
        &path[8..] // Remove "/api/v3"
    } else if path.starts_with("/api/v4/") {
        &path[8..] // Remove "/api/v4"
    } else if path.starts_with("/api/v1/") {
        &path[8..] // Remove "/api/v1"
    } else if path.starts_with("/rest/api/2/") {
        &path[11..] // Remove "/rest/api/2"
    } else if path.starts_with("/rest/api/") {
        &path[9..] // Remove "/rest/api"
    } else {
        path
    };

    // Extract jq parameter
    let jq = params.get("jq").map(|s| s.as_str());

    // Extract host parameter for multi-host services (like Forgejo)
    let host = params.get("host").or_else(|| params.get("hostname")).map(|s| s.to_string());

    // Create service context
    let context = ServiceContext {
        host,
        params: params.clone(),
    };

    // Execute the API request
    match service
        .execute_api(
            &scopes.0,
            endpoint,
            method_str,
            json_body,
            jq,
            Some(&context),
        )
        .await
    {
        Ok(result) => {
            // Try to parse as JSON for proper response formatting
            match serde_json::from_str::<Value>(&result) {
                Ok(json) => Json(json).into_response(),
                Err(_) => {
                    // Return as text if not valid JSON
                    result.into_response()
                }
            }
        }
        Err(e) => {
            error!(
                path = %path,
                method = %method_str,
                endpoint = %endpoint,
                error = %e,
                "API request failed"
            );
            api_error_response(StatusCode::BAD_REQUEST, &format!("API request failed: {}", e))
        }
    }
}

/// Root endpoint.
async fn root() -> &'static str {
    "service-gator REST API"
}

/// Health check endpoint.
async fn health() -> &'static str {
    "OK"
}

/// Status endpoint.
async fn status(State(state): State<RestApiState>) -> Json<Value> {
    // Get current scopes from the watch receiver (supports live reload)
    let scopes = state.scopes.borrow().clone();

    Json(serde_json::json!({
        "status": "running",
        "services": {
            "github": "available",
            "gitlab": "available", 
            "forgejo": "available",
            "jira": "available"
        },
        "endpoints": {
            "github": "/api/v3/*",
            "gitlab": "/api/v4/*",
            "forgejo": "/api/v1/*",
            "jira": "/rest/api/2/*"
        },
        "scopes": {
            "gh": {
                "read": scopes.gh.read,
                "repos_count": scopes.gh.repos.len()
            },
            "gitlab": {
                "projects_count": scopes.gitlab.projects.len()
            },
            "jira": {
                "projects_count": scopes.jira.projects.len()
            }
        }
    }))
}

/// Handler for github.localhost routes (without /api/v3 prefix).
///
/// When gh CLI uses GH_HOST=github.localhost, it hits paths like /user, /repos, etc.
/// directly without the /api/v3 prefix. This handler forwards these to the GitHub service.
async fn github_localhost_handler(
    State(state): State<RestApiState>,
    axum::extract::Extension(scopes): axum::extract::Extension<ResolvedScopes>,
    method: Method,
    uri: axum::http::Uri,
    Query(params): Query<HashMap<String, String>>,
    body: String,
) -> Response {
    let path = uri.path();
    let method_str = method.as_str();

    // Parse JSON body if provided
    let json_body = if !body.is_empty() {
        match serde_json::from_str::<Value>(&body) {
            Ok(json) => Some(json),
            Err(e) => {
                error!(body = %body, error = %e, "Failed to parse JSON body");
                return api_error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Invalid JSON body: {}", e),
                );
            }
        }
    } else {
        None
    };

    // For github.localhost, use the GitHub service directly
    let service = state
        .service_registry
        .get_service_by_name("github")
        .expect("GitHub service should always be available");

    // The endpoint is the path without leading slash
    let endpoint = path.strip_prefix('/').unwrap_or(path);

    // Extract jq parameter
    let jq = params.get("jq").map(|s| s.as_str());

    // Create service context
    let context = ServiceContext {
        host: None,
        params: params.clone(),
    };

    // Execute the API request
    match service
        .execute_api(
            &scopes.0,
            endpoint,
            method_str,
            json_body,
            jq,
            Some(&context),
        )
        .await
    {
        Ok(result) => {
            // Try to parse as JSON for proper response formatting
            match serde_json::from_str::<Value>(&result) {
                Ok(json) => Json(json).into_response(),
                Err(_) => {
                    // Return as text if not valid JSON
                    result.into_response()
                }
            }
        }
        Err(e) => {
            error!(
                path = %path,
                method = %method_str,
                endpoint = %endpoint,
                error = %e,
                "GitHub API request failed"
            );
            api_error_response(
                StatusCode::BAD_REQUEST,
                &format!("API request failed: {}", e),
            )
        }
    }
}

/// Create a generic API error response.
fn api_error_response(status: StatusCode, message: &str) -> Response {
    let error_json = serde_json::json!({
        "error": message,
        "status": status.as_u16()
    });
    (status, Json(error_json)).into_response()
}