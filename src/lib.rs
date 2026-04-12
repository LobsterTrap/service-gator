//! service-gator: Scope-restricted MCP server for sandboxed AI agents.
//!
//! This crate provides scope-restricted access to external services (GitHub,
//! GitLab, Forgejo/Gitea, JIRA) for sandboxed AI agents. It runs as a daemon
//! outside the agent's sandbox, holding credentials the agent cannot access
//! directly, and exposes tools via the Model Context Protocol (MCP).
//!
//! # Security Model
//!
//! The fundamental security property is that the sandboxed AI agent cannot
//! bypass restrictions by accessing credentials directly — it must communicate
//! with this daemon over MCP. The daemon runs outside the sandbox (typically
//! in a separate container) and enforces per-repo/per-project scope
//! restrictions on every operation.
//!
//! # Available Backends
//!
//! - GitHub: scope-based access control with per-repo permissions
//! - GitLab: scope-based access control with per-project permissions
//! - Forgejo/Gitea: scope-based access control with per-repo permissions
//! - JIRA: project and issue-level permissions
//!
//! # Usage
//!
//! ```sh
//! service-gator --mcp-server 127.0.0.1:8080
//! ```
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

pub mod auth;
pub mod config_watcher;
pub mod core;
pub mod forgejo;
pub mod forgejo_client;
pub mod git;
pub mod github;
pub mod gitlab;
pub mod jira;
pub mod jira_client;
pub mod jira_types;
pub mod logging;
pub mod mcp;
pub mod net;
pub mod scope;
pub mod secret;
pub mod servers;
pub mod services;
