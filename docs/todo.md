# Roadmap / TODO

Planned features and improvements for service-gator.

## In Progress

### GitLab MR Approval Operations

Add a `gl_mr_approve` tool similar to `gh_pending_review` for managing GitLab merge request approvals:

- Approve/unapprove MRs within configured scopes
- Marker-based protection (only modify AI-created approvals)
- Integration with GitLab's approval rules system

## Planned

### Write Operations

Currently all tools are read-only. Future work includes:

- **GitHub**: Support for creating issues, PRs, comments with appropriate scope restrictions
- **GitLab**: Support for creating MRs, issues, comments
- **Forgejo**: Support for creating PRs, issues, comments
- **JIRA**: Already supports create/write operations

### GraphQL Support

- **GitHub**: GraphQL is supported with `graphql: read` or `graphql: write` permission levels
- **GitLab**: GraphQL is not yet supported (requires query parsing to validate read-only)

### Google Docs Integration

Read and create Google Docs with per-document access control.

**Architecture:**
- One-time OAuth consent from user (grants `drive` scope)
- `context attach <URL>` programmatically shares doc with service account
- Agent accesses docs via wrapped MCP tools (not direct token)
- service-gator enforces scope at runtime

**Tools:**
| Tool | Permission | Description |
|------|------------|-------------|
| `gdoc_read` | `read` | Read doc content as markdown |
| `gdoc_create` | `create` | Create new doc (global perm, not per-doc) |

**Config example:**
```toml
[gdrive]
service_account = "agent@project.iam.gserviceaccount.com"

[gdrive.docs]
"1ABC123..." = { read = true }

[gdrive.settings]
create = true  # Can create new docs
```

**Implementation notes:**
- Use Drive API `permissions.create()` to share docs with service account
- Track permission IDs for cleanup on `context detach`
- Newly created docs auto-added to scope with read+write
- Skip `write` for v1 (most use cases are read context + create output)

### Additional Services

Potential future integrations (prioritized by token scoping problems):

**High priority** (tokens grant overly broad access):
- **Linear**: Personal API keys = full workspace access, no per-team scoping. Has Rust CLI.
- **Slack**: Scopes are action-based (`chat:write`), not channel-specific
- **Confluence**: Same as JIRA - `read:confluence-content.all` = ALL spaces

**Medium priority:**
- **Trello**: Only 3 scopes total (`read`, `write`, `account`) - extremely coarse
- **Asana**: Better OAuth scopes now, but still no per-project restrictions
- **Monday.com**: Personal tokens mirror ALL user UI permissions

**Skip** (already have good scoping):
- **Notion**: Already has page-level scoping built-in
- **Discord**: Different model (bots installed per-server, role-based permissions)

## Completed

### v0.1.0

- GitHub REST API support (`gh` tool)
- GitHub pending review management (`gh_pending_review` tool)
- JIRA CLI support (`jira` tool)
- Fine-grained scope-based access control
- Pattern matching with wildcards (`owner/*`)
- Resource-level grants (specific PRs/issues)

### GitLab and Forgejo Support

- GitLab REST API support (`gl` tool)
- Forgejo/Gitea REST API support (`forgejo` tool)
- Self-hosted instance support for both
- Multi-host support for Forgejo
