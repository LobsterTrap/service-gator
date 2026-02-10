//! Server implementations for service-gator.
//!
//! This module provides the server architecture supporting:
//! - MCP (Model Context Protocol) server for AI agents
//! - Per-forge REST API servers for HTTP-based integration
//!
//! Both server types share the same core authentication and scope validation
//! logic through shared middleware.

use eyre::Result;
use tokio::sync::watch;
use tracing::info;

use crate::auth::ServerConfig;
use crate::scope::ScopeConfig;
use crate::services::ServiceRegistry;

pub mod mcp;
pub mod middleware;
pub mod rest;
pub mod rest_auth;

pub use rest::ForgeKind;

/// Per-forge server addresses.
///
/// Each `Some` value means "start a server for this forge on that address".
#[derive(Debug, Clone, Default)]
pub struct ForgeServers {
    pub github: Option<String>,
    pub gitlab: Option<String>,
    pub forgejo: Option<String>,
    pub jira: Option<String>,
}

impl ForgeServers {
    /// True if at least one forge server is configured.
    pub fn any(&self) -> bool {
        self.github.is_some()
            || self.gitlab.is_some()
            || self.forgejo.is_some()
            || self.jira.is_some()
    }

    /// Create ForgeServers for all four forges starting at the given base port.
    ///
    /// Allocates consecutive ports: github=base, gitlab=base+1,
    /// forgejo=base+2, jira=base+3.
    pub fn from_base_addr(base_addr: &str) -> eyre::Result<Self> {
        let socket_addr: std::net::SocketAddr = base_addr
            .parse()
            .map_err(|e| eyre::eyre!("invalid address '{}': {}", base_addr, e))?;

        let ip = socket_addr.ip();
        let base_port = socket_addr.port();

        if base_port > 65532 {
            return Err(eyre::eyre!(
                "base port {} too high; need 4 consecutive ports (max base port is 65532)",
                base_port
            ));
        }

        Ok(Self {
            github: Some(format!("{}:{}", ip, base_port)),
            gitlab: Some(format!("{}:{}", ip, base_port + 1)),
            forgejo: Some(format!("{}:{}", ip, base_port + 2)),
            jira: Some(format!("{}:{}", ip, base_port + 3)),
        })
    }
}

/// Server mode enumeration.
#[derive(Debug, Clone)]
pub enum ServerMode {
    /// Only MCP server
    Mcp,
    /// Only per-forge REST servers
    Rest,
    /// MCP + per-forge REST servers (dual mode)
    Dual,
}

/// Run server(s) based on the specified mode with dynamic scope support.
///
/// The `scopes` receiver provides live-reloadable scope configuration.
/// Both MCP and REST servers will observe scope changes.
pub async fn run_servers(
    mode: ServerMode,
    mcp_addr: Option<&str>,
    forge_servers: &ForgeServers,
    config: ServerConfig,
    scopes: watch::Receiver<ScopeConfig>,
) -> Result<()> {
    match mode {
        ServerMode::Mcp => {
            let addr = mcp_addr.unwrap_or("127.0.0.1:8080");
            crate::mcp::start_mcp_server(addr, config, scopes).await
        }
        ServerMode::Rest => run_forge_servers(forge_servers, config, scopes).await,
        ServerMode::Dual => {
            let mcp_addr = mcp_addr.unwrap_or("127.0.0.1:8080");
            let mcp_config = config.clone();
            let mcp_scopes = scopes.clone();

            tokio::try_join!(
                crate::mcp::start_mcp_server(mcp_addr, mcp_config, mcp_scopes),
                run_forge_servers(forge_servers, config, scopes),
            )?;

            Ok(())
        }
    }
}

/// Start all configured forge servers concurrently.
async fn run_forge_servers(
    servers: &ForgeServers,
    config: ServerConfig,
    scopes: watch::Receiver<ScopeConfig>,
) -> Result<()> {
    let registry = ServiceRegistry::new();
    let mut join_set = tokio::task::JoinSet::new();

    // Helper: spawn a forge server if an address is configured
    let mut spawn_if = |forge: ForgeKind, addr_opt: &Option<String>, service| {
        if let Some(addr) = addr_opt {
            let addr = addr.clone();
            let config = config.clone();
            let scopes = scopes.clone();
            info!("{} server will listen on {}", forge, addr);
            join_set.spawn(async move {
                rest::start_forge_server(&addr, forge, service, config, scopes).await
            });
        }
    };

    spawn_if(
        ForgeKind::GitHub,
        &servers.github,
        registry.github_service(),
    );
    spawn_if(
        ForgeKind::GitLab,
        &servers.gitlab,
        registry.gitlab_service(),
    );
    spawn_if(
        ForgeKind::Forgejo,
        &servers.forgejo,
        registry.forgejo_service(),
    );
    spawn_if(ForgeKind::Jira, &servers.jira, registry.jira_service());

    if join_set.is_empty() {
        return Err(eyre::eyre!(
            "No forge servers configured. Use --github-port, --gitlab-port, --forgejo-port, --jira-port, or --rest-server."
        ));
    }

    // Wait for the first server to complete (or fail). Since servers run
    // forever, this means we wait until one errors out.
    while let Some(result) = join_set.join_next().await {
        // Propagate panics and errors
        result??;
    }

    Ok(())
}
