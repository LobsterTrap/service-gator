//! service-gator: Scope-restricted CLI wrapper for sandboxed AI agents.
//!
//! This crate provides a security wrapper around CLI tools that access external
//! services (GitHub, JIRA, etc.). It's designed for sandboxed AI agents that need
//! controlled access to services where PAT/token-based auth grants broad access
//! that needs to be restricted.
//!
//! # Security Model
//!
//! The fundamental security property is that the sandboxed AI agent cannot
//! bypass restrictions by running a different binary - it must communicate with
//! an external daemon that controls access. The daemon runs outside the sandbox
//! and has access to secrets (tokens, credentials).
//!
//! # Available Backends
//!
//! - `gh` / `gh-gator`: GitHub CLI wrapper with scope-based access control
//! - `jira` / `jira-gator`: JIRA CLI wrapper with project-based access control
//!
//! # Usage Modes
//!
//! 1. **CLI mode**: Run commands directly with scope checking
//!    ```sh
//!    service-gator gh pr list -R owner/repo
//!    ```
//!
//! 2. **MCP server mode**: Expose tools via Model Context Protocol
//!    ```sh
//!    service-gator --mcp-server 127.0.0.1:8080
//!    ```
//!
//! # Configuration
//!
//! Configure via `~/.config/service-gator.toml`:
//!
//! ```toml
//! [gh.repos]
//! "owner/repo" = { read = true, create-draft = true }
//! "owner/*" = { read = true }
//!
//! [gh.prs]
//! "owner/repo#42" = { read = true, write = true }
//!
//! [jira.projects]
//! "MYPROJ" = { read = true, create = true }
//! ```

pub mod core;
pub mod forgejo;
pub mod forgejo_client;
pub mod github;
pub mod gitlab;
pub mod jira;
pub mod jira_client;
pub mod mcp;
pub mod scope;
