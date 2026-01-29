# GitHub Native API Client

Replace `gh` CLI invocations with direct HTTP calls using `reqwest`, enabling connection pooling and eliminating process spawn overhead.

## Motivation

Currently, every GitHub API call in service-gator:

1. Spawns a new `gh` process via `tokio::process::Command`
2. Establishes a fresh HTTPS connection (no reuse)
3. Incurs ~10-50ms overhead per request from process spawn + exec

With a native HTTP client:
- **Connection pooling**: TLS sessions reused across requests
- **No spawn overhead**: Direct async HTTP instead of process fork
- **Consistency**: Same pattern as `forgejo_client.rs` (already implemented)

## Current State

GitHub operations in `src/mcp.rs` that invoke `gh`:

| Method | Lines | Operation |
|--------|-------|-----------|
| `github_api()` | 333-441 | REST API (GET/POST/PUT/PATCH/DELETE) |
| `github_create_draft_pr()` | 444-488 | Create draft PR via API |
| `github_pending_review()` | 492-679 | List/create/update/delete pending reviews |

All use `exec_command("gh", &args)` or `exec_command_with_stdin("gh", &args, &body)`.

## Proposed Implementation

### 1. Add reqwest dependency

`reqwest` is already in the workspace (used by devaipod). Add to service-gator:

```toml
# Cargo.toml
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
```

### 2. Create `src/github_client.rs`

Model after `src/forgejo_client.rs`:

```rust
use eyre::Result;
use reqwest::{header, Client, Method};
use serde_json::Value;
use std::sync::LazyLock;

const GITHUB_API_BASE: &str = "https://api.github.com";

pub struct GithubClient {
    client: Client,
    token: Option<String>,
}

impl GithubClient {
    pub fn new(token: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .user_agent("service-gator")
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(5)
            .build()?;
        
        Ok(Self { client, token })
    }

    pub async fn request(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let url = format!("{}/{}", GITHUB_API_BASE, endpoint.trim_start_matches('/'));
        
        let mut req = self.client
            .request(method, &url)
            .header(header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        
        if let Some(ref token) = self.token {
            req = req.bearer_auth(token);
        }
        
        if let Some(body) = body {
            req = req.json(&body);
        }
        
        let resp = req.send().await?;
        
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            eyre::bail!("GitHub API error {}: {}", status, text);
        }
        
        // Handle empty responses (e.g., DELETE returns 204)
        let text = resp.text().await?;
        if text.is_empty() {
            return Ok(Value::Null);
        }
        
        Ok(serde_json::from_str(&text)?)
    }
}

/// Global client instance for connection reuse.
/// Token is read from GH_TOKEN environment variable.
pub static CLIENT: LazyLock<GithubClient> = LazyLock::new(|| {
    let token = std::env::var("GH_TOKEN").ok();
    GithubClient::new(token).expect("Failed to create GitHub client")
});
```

### 3. Handle JSON path queries (simple subset of jq)

Instead of full jq support, implement simple path extraction for common patterns:

```rust
/// Extract a value from JSON using a simple path like ".foo.bar[0].baz"
pub fn json_path(value: &Value, path: &str) -> Option<Value> {
    let path = path.trim_start_matches('.');
    if path.is_empty() {
        return Some(value.clone());
    }
    
    let mut current = value;
    for segment in path.split('.') {
        // Handle array index: "items[0]"
        if let Some((key, idx)) = parse_array_access(segment) {
            current = current.get(key)?.get(idx)?;
        } else {
            current = current.get(segment)?;
        }
    }
    Some(current.clone())
}
```

This covers ~90% of real-world jq usage in API tools (simple field access).

### 4. Update `github_api()` in `src/mcp.rs`

Replace:
```rust
// Old: spawn gh process
match self.exec_command("gh", &args).await { ... }
```

With:
```rust
// New: native HTTP
use crate::github_client::CLIENT;

let method = match method.as_str() {
    "GET" => reqwest::Method::GET,
    "POST" => reqwest::Method::POST,
    // ...
};

match CLIENT.request(method, &endpoint, body).await {
    Ok(value) => {
        let output = if let Some(jq) = jq {
            json_path(&value, jq)
                .map(|v| serde_json::to_string_pretty(&v).unwrap())
                .unwrap_or_else(|| "null".to_string())
        } else {
            serde_json::to_string_pretty(&value)?
        };
        Ok(CallToolResult::success(vec![Content::text(output)]))
    }
    Err(e) => Ok(CallToolResult::error(vec![Content::text(format!("{e:#}"))])),
}
```

### 5. Update other GitHub methods

Apply same pattern to:
- `github_create_draft_pr()` - POST to `/repos/{owner}/{repo}/pulls`
- `github_pending_review()` - Various methods to `/repos/{owner}/{repo}/pulls/{n}/reviews`

## Migration Steps

1. **Add reqwest to Cargo.toml**
2. **Create `src/github_client.rs`** with `GithubClient` and `json_path()`
3. **Add `mod github_client;` to `src/lib.rs`**
4. **Update `github_api()`** to use native client
5. **Update `github_create_draft_pr()`**
6. **Update `github_pending_review()`**
7. **Remove `exec_command*` calls for GitHub** (keep for potential fallback)
8. **Update integration tests** to work with native client
9. **Test connection pooling** - verify connections are reused

## Testing

- Existing integration tests in `integration-tests/src/tests/mcp_server.rs` should continue to pass
- Add unit tests for `json_path()` function
- Add tests for error handling (auth failures, rate limits, network errors)
- Verify connection reuse via debug logging or metrics

## Future Enhancements

- **Rate limit handling**: Parse `X-RateLimit-*` headers, implement backoff
- **Pagination**: Handle `Link` headers for paginated endpoints
- **GraphQL**: Native GraphQL support (currently blocked for mutations anyway)
- **Retry logic**: Automatic retry on transient failures (5xx, network errors)

## Alternatives Considered

### octocrab crate

Pros: Typed API, comprehensive coverage, built-in pagination
Cons: Large dependency tree (~30 deps), GitHub-only, overkill for pass-through usage

Decision: reqwest is simpler and consistent with Forgejo client pattern.

### Keep gh CLI

Pros: Zero code changes, handles all edge cases
Cons: ~10-50ms overhead per request, no connection pooling

Decision: Native client is worth the effort for performance and consistency.
