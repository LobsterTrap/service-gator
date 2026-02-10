//! Per-forge REST API server implementation.
//!
//! Each forge (GitHub, GitLab, Forgejo, JIRA) runs on its own port with only
//! its own routes. This avoids path collisions (e.g., GitHub and Forgejo both
//! use `/repos/*`).

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

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
use crate::services::{ApiService, ServiceContext};

/// Which forge a REST server instance serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgeKind {
    GitHub,
    GitLab,
    Forgejo,
    Jira,
}

impl fmt::Display for ForgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForgeKind::GitHub => write!(f, "GitHub"),
            ForgeKind::GitLab => write!(f, "GitLab"),
            ForgeKind::Forgejo => write!(f, "Forgejo"),
            ForgeKind::Jira => write!(f, "JIRA"),
        }
    }
}

impl ForgeKind {
    /// The API prefix used for path stripping (with trailing slash).
    fn api_prefix(self) -> &'static str {
        match self {
            ForgeKind::GitHub => "/api/v3/",
            ForgeKind::GitLab => "/api/v4/",
            ForgeKind::Forgejo => "/api/v1/",
            ForgeKind::Jira => "/rest/api/2/",
        }
    }

    /// Alternative API prefix (JIRA has `/rest/api/` as a legacy prefix).
    fn alt_prefix(self) -> Option<&'static str> {
        match self {
            ForgeKind::Jira => Some("/rest/api/"),
            _ => None,
        }
    }

    /// All four forge kinds.
    pub const ALL: [ForgeKind; 4] = [
        ForgeKind::GitHub,
        ForgeKind::GitLab,
        ForgeKind::Forgejo,
        ForgeKind::Jira,
    ];
}

/// Application state for a single-forge REST API server.
#[derive(Clone)]
pub struct RestApiState {
    pub config: ServerConfig,
    /// The API service for this forge.
    pub service: ApiService,
    /// Which forge this server serves.
    pub forge: ForgeKind,
    /// Dynamic scopes receiver for live reload support.
    pub scopes: watch::Receiver<ScopeConfig>,
}

/// Start a REST API server for a single forge.
pub async fn start_forge_server(
    addr: &str,
    forge: ForgeKind,
    service: ApiService,
    config: ServerConfig,
    scopes: watch::Receiver<ScopeConfig>,
) -> Result<()> {
    let socket_addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid {} server address: {}", forge, addr))?;

    let state = RestApiState {
        config: config.clone(),
        service,
        forge,
        scopes: scopes.clone(),
    };

    let auth_state = RestAuthState::new(config.clone(), scopes);

    // Build forge-specific routes
    let api_routes = build_forge_routes(forge)
        .layer(middleware::from_fn_with_state(
            auth_state,
            rest_auth_middleware,
        ))
        .with_state(state.clone());

    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health))
        .route("/status", get(status))
        .merge(api_routes)
        .layer(CorsLayer::permissive())
        .with_state(state);

    info!("Starting {} REST API server on {}", forge, socket_addr);
    info!("{} endpoints available at {}*", forge, forge.api_prefix());

    let listener = tokio::net::TcpListener::bind(socket_addr).await?;

    axum::serve(listener, app)
        .await
        .with_context(|| format!("{} REST API server failed", forge))?;

    Ok(())
}

/// Build the axum Router with routes specific to each forge.
fn build_forge_routes(forge: ForgeKind) -> Router<RestApiState> {
    match forge {
        ForgeKind::GitHub => Router::new()
            // Primary API prefix
            .route("/api/v3/{*path}", any(forge_api_handler))
            // Bare paths for github.localhost compatibility (gh CLI hits these directly)
            .route("/user", any(forge_api_handler))
            .route("/user/{*path}", any(forge_api_handler))
            .route("/repos/{*path}", any(forge_api_handler))
            .route("/gists", any(forge_api_handler))
            .route("/gists/{*path}", any(forge_api_handler))
            .route("/orgs/{*path}", any(forge_api_handler))
            .route("/search/{*path}", any(forge_api_handler))
            .route("/graphql", any(forge_api_handler)),

        ForgeKind::GitLab => Router::new().route("/api/v4/{*path}", any(forge_api_handler)),

        ForgeKind::Forgejo => Router::new().route("/api/v1/{*path}", any(forge_api_handler)),

        ForgeKind::Jira => Router::new()
            .route("/rest/api/2/{*path}", any(forge_api_handler))
            .route("/rest/api/{*path}", any(forge_api_handler)),
    }
}

/// Unified handler for all forge API requests.
///
/// Strips the known prefix from the path and forwards to the forge's service.
/// For GitHub bare paths (e.g. `/user`, `/repos/...`), strips only the leading `/`.
async fn forge_api_handler(
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
    let json_body = match parse_json_body(&body) {
        Ok(body) => body,
        Err(response) => return response,
    };

    // Strip the API prefix to get the endpoint.
    // Try the primary prefix first, then the alt prefix (for JIRA), then bare `/`.
    let endpoint = path
        .strip_prefix(state.forge.api_prefix())
        .or_else(|| {
            state
                .forge
                .alt_prefix()
                .and_then(|alt| path.strip_prefix(alt))
        })
        .or_else(|| path.strip_prefix('/'))
        .unwrap_or(path);

    // Extract host parameter for multi-host services (like Forgejo)
    let host = params
        .get("host")
        .or_else(|| params.get("hostname"))
        .map(|s| s.to_string());

    let context = ServiceContext {
        host,
        params: params.clone(),
    };

    execute_api_request(
        &state.service,
        &scopes,
        endpoint,
        method_str,
        json_body,
        context,
        &params,
        path,
    )
    .await
}

/// Shared API execution logic.
#[allow(clippy::too_many_arguments)]
async fn execute_api_request(
    service: &ApiService,
    scopes: &ResolvedScopes,
    endpoint: &str,
    method_str: &str,
    json_body: Option<Value>,
    context: ServiceContext,
    params: &HashMap<String, String>,
    path: &str,
) -> Response {
    let jq = params.get("jq").map(|s| s.as_str());

    let api_result = service
        .execute_api(
            &scopes.0,
            endpoint,
            method_str,
            json_body,
            jq,
            Some(&context),
        )
        .await;

    match api_result {
        Ok(result) => format_api_response(result),
        Err(e) => {
            error!(
                path = %path,
                method = %method_str,
                endpoint = %endpoint,
                error = %e,
                "API request failed"
            );

            let status_code = map_error_to_status_code(&e);
            api_error_response(status_code, &format!("API request failed: {}", e))
        }
    }
}

/// Map service errors to appropriate HTTP status codes.
///
/// Prefers typed `ServiceError` downcasting over string matching.
fn map_error_to_status_code(error: &eyre::Error) -> StatusCode {
    use crate::services::ServiceError;

    // Try typed error first
    if let Some(svc_err) = error.downcast_ref::<ServiceError>() {
        return match svc_err {
            ServiceError::ReadDenied { .. }
            | ServiceError::WriteDenied { .. }
            | ServiceError::GraphQlMutationDenied
            | ServiceError::GraphQlReadDenied { .. } => StatusCode::FORBIDDEN,

            ServiceError::NoHostsConfigured { .. }
            | ServiceError::HostNotFound { .. }
            | ServiceError::NoHostAccess { .. } => StatusCode::NOT_FOUND,

            ServiceError::MissingResourcePath { .. }
            | ServiceError::InsufficientScope { .. }
            | ServiceError::InvalidInput(_) => StatusCode::BAD_REQUEST,
        };
    }

    // Fallback: string matching for errors from other layers (CLI, JIRA client, etc.)
    let error_str = error.to_string().to_lowercase();
    if error_str.contains("not found") || error_str.contains("404") {
        StatusCode::NOT_FOUND
    } else if error_str.contains("unauthorized") || error_str.contains("401") {
        StatusCode::UNAUTHORIZED
    } else if error_str.contains("timeout") || error_str.contains("connection") {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// Format API response as JSON or text.
fn format_api_response(result: String) -> Response {
    match serde_json::from_str::<Value>(&result) {
        Ok(json) => Json(json).into_response(),
        Err(_) => result.into_response(),
    }
}

/// Parse JSON body from request.
#[allow(clippy::result_large_err)]
fn parse_json_body(body: &str) -> Result<Option<Value>, Response> {
    if body.is_empty() {
        return Ok(None);
    }

    match serde_json::from_str::<Value>(body) {
        Ok(json) => Ok(Some(json)),
        Err(e) => {
            error!(body = %body, error = %e, "Failed to parse JSON body");
            Err(api_error_response(
                StatusCode::BAD_REQUEST,
                &format!("Invalid JSON body: {}", e),
            ))
        }
    }
}

/// Root endpoint.
async fn root(State(state): State<RestApiState>) -> String {
    format!("service-gator {} REST API", state.forge)
}

/// Health check endpoint.
async fn health() -> &'static str {
    "OK"
}

/// Status endpoint -- shows only this forge's info.
async fn status(State(state): State<RestApiState>) -> Json<Value> {
    let current_scopes = state.scopes.borrow();

    let forge_status = match state.forge {
        ForgeKind::GitHub => serde_json::json!({
            "status": "running",
            "forge": "github",
            "endpoint": "/api/v3/*",
            "scopes": {
                "read": current_scopes.gh.read,
                "repos_count": current_scopes.gh.repos.len()
            }
        }),
        ForgeKind::GitLab => serde_json::json!({
            "status": "running",
            "forge": "gitlab",
            "endpoint": "/api/v4/*",
            "scopes": {
                "projects_count": current_scopes.gitlab.projects.len(),
                "host": current_scopes.gitlab.host
            }
        }),
        ForgeKind::Forgejo => serde_json::json!({
            "status": "running",
            "forge": "forgejo",
            "endpoint": "/api/v1/*",
            "scopes": {
                "hosts_count": current_scopes.forgejo.len()
            }
        }),
        ForgeKind::Jira => serde_json::json!({
            "status": "running",
            "forge": "jira",
            "endpoint": "/rest/api/2/*",
            "scopes": {
                "projects_count": current_scopes.jira.projects.len(),
                "host": current_scopes.jira.host
            }
        }),
    };

    Json(forge_status)
}

/// Create a generic API error response.
fn api_error_response(status: StatusCode, message: &str) -> Response {
    let error_json = serde_json::json!({
        "error": message,
        "status": status.as_u16()
    });
    (status, Json(error_json)).into_response()
}
