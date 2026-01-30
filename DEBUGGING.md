# Debugging service-gator MCP Server

Tips for debugging MCP connectivity issues, especially with OpenCode.

## Quick Test Setup

Start the server:
```bash
# Build first
cargo build --release

# Start with a test repo (read-only access to a playground repo)
./target/release/service-gator --mcp-server 127.0.0.1:29765 --gh-repo cgwalters/playground:read,create-draft
```

Test with OpenCode:
```bash
# List tools to verify connection
OPENCODE_CONFIG_CONTENT='{"mcp":{"service-gator":{"enabled":true,"type":"remote","url":"http://127.0.0.1:29765/mcp"}}}' opencode mcp list
```

Expected success output:
```
service-gator  http://127.0.0.1:29765/mcp  toolCount=5
```

## Common Issues

### 1. Schema Validation Errors

**Error**: `input_schema does not support oneOf, allOf, or anyOf at the top level`

OpenCode has strict JSON Schema requirements for MCP tool input schemas:
- The root schema MUST have `"type": "object"`
- The root schema MUST NOT have `oneOf`, `allOf`, or `anyOf` at the top level
- Internally-tagged enums (Rust's `#[serde(tag = "...")]`) naturally produce `oneOf` schemas via schemars

**Workaround options**:
1. Use separate tools instead of a single tool with enum variants
2. Implement custom `JsonSchema` that flattens the schema (complex)
3. Use `additionalProperties: true` with a discriminator field

### 2. MCP Initialization Sequence

OpenCode may send `tools/list` immediately after `initialize` response, before the `initialized` notification. 

rmcp versions before 0.14 were strict about requiring `initialized` first. **Use rmcp >= 0.14** which handles this correctly.

### 3. Inspecting the Schema

To see what schema rmcp is generating for your tools:

```rust
// Add this temporarily to debug
let schema = schemars::schema_for!(YourInputType);
println!("{}", serde_json::to_string_pretty(&schema).unwrap());
```

Or add a test:
```rust
#[test]
fn print_schema() {
    let schema = schemars::schema_for!(GithubToolInput);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}
```

### 4. Watching MCP Traffic

For debugging the actual JSON-RPC messages:

```bash
# Run with RUST_LOG for debug output
RUST_LOG=rmcp=debug,service_gator=debug ./target/release/service-gator --mcp-server 127.0.0.1:29765 --gh-repo cgwalters/playground:read
```

### 5. Testing with curl

Test the HTTP endpoint directly:

```bash
# Initialize (required first)
curl -X POST http://127.0.0.1:29765/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'

# List tools
curl -X POST http://127.0.0.1:29765/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

## Known MCP Client Quirks

### OpenCode
- Strict about `type: object` at schema root
- Does NOT support `oneOf`/`allOf`/`anyOf` at root level
- Sends `tools/list` before `initialized` notification

### VS Code MCP Extension
- Similar strictness about schema structure
- May have different timing expectations

## Architecture Notes

The MCP server uses:
- `rmcp` crate for MCP protocol handling
- `axum` for HTTP server
- `schemars` for JSON Schema generation
- `serde` for JSON serialization

The schema generation path:
1. `#[derive(JsonSchema)]` on input types
2. `rmcp`'s `#[tool]` macro extracts schema from type
3. Schema is returned in `tools/list` response
4. Client validates schema before calling tools
