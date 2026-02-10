//! Logging middleware for service-gator servers.

use tower_http::trace::TraceLayer;

/// Create a tracing layer for HTTP request logging.
pub fn create_trace_layer(
) -> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>>
{
    TraceLayer::new_for_http()
}
