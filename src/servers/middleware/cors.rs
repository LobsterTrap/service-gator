//! CORS middleware for REST API server.

use tower_http::cors::{Any, CorsLayer};

/// Create a permissive CORS layer for development.
///
/// In production, this should be configured more restrictively.
pub fn create_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
}
