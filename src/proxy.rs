//! HTTP proxy for transparent CLI tool integration.
//!
//! This module provides an HTTP proxy server that intercepts requests to
//! external services (GitHub, GitLab, etc.) and applies scope-based validation
//! before forwarding them to the real services.
//!
//! # Usage
//!
//! ```sh
//! service-gator --http-proxy localhost:8081
//! export https_proxy=http://localhost:8081
//! gh api repos/owner/repo/pulls  # Works transparently with scope validation
//! ```

use std::net::SocketAddr;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::Router,
};
use eyre::{Context, Result};
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::auth::{AuthMode, ServerConfig};
use crate::scope::ScopeConfig;

/// HTTP proxy server state.
#[derive(Clone)]
pub struct ProxyState {
    /// HTTP client for forwarding requests.
    client: Client<hyper_util::client::legacy::connect::HttpConnector, Body>,
    /// Server configuration including auth settings.
    server_config: ServerConfig,
}

/// Start the HTTP proxy server.
pub async fn start_proxy_server(addr: &str, config: ServerConfig) -> Result<()> {
    let socket_addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid proxy address: {}", addr))?;

    let state = ProxyState {
        client: Client::builder(TokioExecutor::new()).build_http(),
        server_config: config,
    };

    let app = Router::new()
        // Handle all methods including CONNECT for all paths
        .fallback(handle_proxy_request)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(tower_http::cors::CorsLayer::permissive()),
        )
        .with_state(state);

    info!("Starting HTTP proxy server on {}", socket_addr);
    let listener = tokio::net::TcpListener::bind(socket_addr).await?;

    axum::serve(listener, app)
        .await
        .context("HTTP proxy server failed")?;

    Ok(())
}

/// Handle incoming proxy requests.
async fn handle_proxy_request(
    State(state): State<ProxyState>,
    request: Request,
) -> Result<Response, StatusCode> {
    let (parts, body) = request.into_parts();

    // Handle CONNECT requests for HTTPS tunneling
    if parts.method == Method::CONNECT {
        return handle_connect_request(&parts).await;
    }

    let uri = &parts.uri;

    // Extract the target host and determine if this is a service we should intercept
    let target_info = match extract_target_service(uri) {
        Some(info) => info,
        None => {
            // Not a service we handle - forward normally
            return forward_request_normally(state, parts, body).await;
        }
    };

    info!(
        method = ?parts.method,
        service = %target_info.service,
        path = %target_info.path,
        "intercepting request"
    );

    // Determine scopes to use for this request
    let scopes = resolve_scopes_for_request(&state.server_config, &parts).await?;

    // Validate permissions for this service/operation
    if let Err(e) = validate_service_permission(&scopes, &target_info, &parts.method) {
        warn!(
            method = ?parts.method,
            service = %target_info.service,
            path = %target_info.path,
            error = %e,
            "request blocked by scope validation"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Forward the request to the real service
    forward_to_service(state, parts, body, target_info).await
}

/// Handle CONNECT requests for HTTPS tunneling.
///
/// For now, we reject all CONNECT requests since we need to inspect the actual
/// HTTP requests inside the tunnel, which requires more complex implementation.
async fn handle_connect_request(parts: &http::request::Parts) -> Result<Response, StatusCode> {
    let target = parts
        .uri
        .authority()
        .map(|auth| auth.as_str())
        .unwrap_or("unknown");

    info!(
        target = %target,
        "rejecting CONNECT request - HTTPS tunneling not supported in spike"
    );

    // Return 405 Method Not Allowed for CONNECT requests
    Ok(Response::builder()
        .status(StatusCode::METHOD_NOT_ALLOWED)
        .header("content-type", "text/plain")
        .body(Body::from(
            "HTTPS tunneling not supported. Use HTTP endpoints or configure tools for HTTP proxy mode."
        ))
        .unwrap())
}

/// Information about the target service for a request.
#[derive(Debug)]
struct TargetServiceInfo {
    service: String,
    original_host: String,
    path: String,
}

/// Extract target service info from the request URI.
fn extract_target_service(uri: &Uri) -> Option<TargetServiceInfo> {
    // In proxy mode, we get requests like:
    // - https://api.github.com/repos/owner/repo/pulls
    // - https://gitlab.com/api/v4/projects/123/merge_requests

    let host = uri.host()?;
    let path = uri.path_and_query()?.as_str();

    let service = match host {
        "api.github.com" => "github",
        host if host.ends_with("gitlab.com") => "gitlab",
        host if host.contains("codeberg.org") => "forgejo",
        _ => return None,
    };

    Some(TargetServiceInfo {
        service: service.to_string(),
        original_host: host.to_string(),
        path: path.to_string(),
    })
}

/// Resolve scopes for the incoming request.
async fn resolve_scopes_for_request(
    config: &ServerConfig,
    parts: &http::request::Parts,
) -> Result<ScopeConfig, StatusCode> {
    // For now, use the default scopes from config
    // In a full implementation, this would:
    // 1. Extract JWT token from Authorization header
    // 2. Validate and decode the token
    // 3. Return the scopes from the token
    // 4. Fall back to default scopes if no token and auth is optional

    match config.server.mode {
        AuthMode::None => Ok(config.scopes.clone()),
        AuthMode::Optional => {
            // Check for Authorization header
            if let Some(_auth_header) = parts.headers.get("authorization") {
                // TODO: Decode JWT token and extract scopes
                // For spike, just use default scopes
                Ok(config.scopes.clone())
            } else {
                Ok(config.scopes.clone())
            }
        }
        AuthMode::Required => {
            // TODO: Require and validate JWT token
            // For spike, just use default scopes
            Ok(config.scopes.clone())
        }
    }
}

/// Validate that the request is allowed by the resolved scopes.
fn validate_service_permission(
    scopes: &ScopeConfig,
    target: &TargetServiceInfo,
    method: &Method,
) -> Result<(), String> {
    match target.service.as_str() {
        "github" => validate_github_permission(scopes, target, method),
        "gitlab" => validate_gitlab_permission(scopes, target, method),
        "forgejo" => validate_forgejo_permission(scopes, target, method),
        _ => Err(format!("unknown service: {}", target.service)),
    }
}

/// Validate GitHub API permissions.
fn validate_github_permission(
    scopes: &ScopeConfig,
    target: &TargetServiceInfo,
    method: &Method,
) -> Result<(), String> {
    // Extract repo from path if present (e.g., /repos/owner/repo/pulls)
    let repo = crate::github::extract_repo_from_api_path(&target.path);

    let is_write = method != Method::GET;

    if is_write {
        // Write operations need specific repo and write permission
        let repo = repo.ok_or("write operations require a repository path")?;
        if !scopes
            .gh
            .is_allowed(&repo, crate::scope::GhOpType::Write, None)
        {
            return Err(format!("write access not allowed for repository: {}", repo));
        }
    } else {
        // Read operations
        match repo {
            Some(repo) => {
                if !scopes.gh.is_read_allowed(&repo) {
                    return Err(format!("read access not allowed for repository: {}", repo));
                }
            }
            None => {
                // Global endpoint (like /user, /search)
                if !scopes.gh.global_read_allowed() {
                    return Err("global read access not allowed".to_string());
                }
            }
        }
    }

    Ok(())
}

/// Validate GitLab API permissions (placeholder).
fn validate_gitlab_permission(
    _scopes: &ScopeConfig,
    _target: &TargetServiceInfo,
    _method: &Method,
) -> Result<(), String> {
    // TODO: Implement GitLab permission validation
    Ok(())
}

/// Validate Forgejo API permissions (placeholder).
fn validate_forgejo_permission(
    _scopes: &ScopeConfig,
    _target: &TargetServiceInfo,
    _method: &Method,
) -> Result<(), String> {
    // TODO: Implement Forgejo permission validation
    Ok(())
}

/// Forward request to the target service.
async fn forward_to_service(
    state: ProxyState,
    mut parts: http::request::Parts,
    body: Body,
    target: TargetServiceInfo,
) -> Result<Response, StatusCode> {
    // Inject authentication if needed
    inject_service_auth(&mut parts, &target.service).map_err(|e| {
        warn!(error = %e, service = %target.service, "failed to inject auth");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Reconstruct the request with the original URI
    let uri = reconstruct_target_uri(&target)?;
    parts.uri = uri;

    let request = Request::from_parts(parts, body);

    // Forward to the real service
    let response = state.client.request(request).await.map_err(|e| {
        warn!(error = %e, service = %target.service, "failed to forward request");
        StatusCode::BAD_GATEWAY
    })?;

    Ok(response.into_response())
}

/// Inject authentication headers for the target service.
fn inject_service_auth(parts: &mut http::request::Parts, service: &str) -> Result<(), String> {
    match service {
        "github" => {
            // Inject GitHub token if available
            if let Some(token) = crate::core::get_token_trimmed("GH_TOKEN", Some("GITHUB_TOKEN")) {
                parts.headers.insert(
                    "authorization",
                    format!("token {}", token)
                        .parse()
                        .map_err(|e| format!("invalid token: {}", e))?,
                );
            }
        }
        "gitlab" => {
            // Inject GitLab token if available
            if let Some(token) = crate::core::get_token_trimmed("GITLAB_TOKEN", None) {
                parts.headers.insert(
                    "authorization",
                    format!("Bearer {}", token)
                        .parse()
                        .map_err(|e| format!("invalid token: {}", e))?,
                );
            }
        }
        "forgejo" => {
            // Inject Forgejo token if available
            if let Some(token) = crate::core::get_token_trimmed("FORGEJO_TOKEN", None) {
                parts.headers.insert(
                    "authorization",
                    format!("token {}", token)
                        .parse()
                        .map_err(|e| format!("invalid token: {}", e))?,
                );
            }
        }
        _ => {}
    }
    Ok(())
}

/// Reconstruct the target URI for forwarding.
fn reconstruct_target_uri(target: &TargetServiceInfo) -> Result<Uri, StatusCode> {
    let target_url = format!("https://{}{}", target.original_host, target.path);
    target_url.parse().map_err(|_| StatusCode::BAD_REQUEST)
}

/// Forward request normally (for non-intercepted hosts).
async fn forward_request_normally(
    state: ProxyState,
    parts: http::request::Parts,
    body: Body,
) -> Result<Response, StatusCode> {
    let request = Request::from_parts(parts, body);

    let response = state
        .client
        .request(request)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    Ok(response.into_response())
}
