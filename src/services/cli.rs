//! Generic CLI service for executing GitHub, GitLab, and Forgejo commands.
//!
//! This module provides a unified interface for executing commands across different
//! CLI tools (gh, glab, tea) with shared command execution and response handling.

use eyre::{bail, Result};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::error;

/// Generic CLI service for executing commands across different CLI tools.
#[derive(Clone, Debug)]
pub struct CliService {
    /// Command name (e.g., "gh", "glab", "tea")
    pub command: &'static str,
    /// API prefix for this service (e.g., "/api/v3", "/api/v4", "/api/v1")
    pub api_prefix: &'static str,
}

impl CliService {
    /// Create a new CLI service.
    pub fn new(command: &'static str, api_prefix: &'static str) -> Self {
        Self {
            command,
            api_prefix,
        }
    }

    /// Execute an API command with the given parameters.
    pub async fn execute_api(
        &self,
        endpoint: &str,
        method: &str,
        body: Option<Value>,
        jq: Option<&str>,
        host: Option<&str>,
    ) -> Result<String> {
        // Build the command args
        let mut args = vec![
            "api".to_string(),
            format!("--method={}", method),
            endpoint.to_string(),
        ];

        // Add host if provided (for multi-host services like Forgejo)
        if let Some(host_name) = host {
            args.push("--hostname".to_string());
            args.push(host_name.to_string());
        }

        // Add jq filter if provided
        if let Some(jq_expr) = jq {
            args.push("--jq".to_string());
            args.push(jq_expr.to_string());
        }

        // Execute with or without body
        if let Some(body_value) = body {
            args.push("--input".to_string());
            args.push("-".to_string());
            let body_str = body_value.to_string();
            self.exec_command_with_stdin(&args, &body_str).await
        } else {
            self.exec_command(&args).await
        }
    }

    /// Execute a command with stdin input.
    pub async fn exec_command_with_stdin(&self, args: &[String], stdin: &str) -> Result<String> {
        let mut cmd = Command::new(self.command);
        cmd.args(args);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| eyre::eyre!("Failed to spawn {}: {}", self.command, e))?;

        // Write stdin
        if let Some(mut stdin_handle) = child.stdin.take() {
            stdin_handle
                .write_all(stdin.as_bytes())
                .await
                .map_err(|e| eyre::eyre!("Failed to write stdin: {}", e))?;
            stdin_handle
                .flush()
                .await
                .map_err(|e| eyre::eyre!("Failed to flush stdin: {}", e))?;
            drop(stdin_handle);
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| eyre::eyre!("Failed to wait for {}: {}", self.command, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(command = self.command, ?args, stderr = %stderr, "Command failed");
            bail!("Command failed: {}", stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Execute a command without stdin.
    pub async fn exec_command(&self, args: &[String]) -> Result<String> {
        let output = Command::new(self.command)
            .args(args)
            .output()
            .await
            .map_err(|e| eyre::eyre!("Failed to execute {}: {}", self.command, e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(command = self.command, ?args, stderr = %stderr, "Command failed");
            bail!("Command failed: {}", stderr);
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

/// Predefined CLI services for common tools.
pub mod services {
    use super::CliService;

    /// GitHub CLI service.
    pub const GITHUB: CliService = CliService {
        command: "gh",
        api_prefix: "/api/v3",
    };

    /// GitLab CLI service.
    pub const GITLAB: CliService = CliService {
        command: "glab",
        api_prefix: "/api/v4",
    };

    /// Forgejo/Gitea CLI service.
    pub const FORGEJO: CliService = CliService {
        command: "tea",
        api_prefix: "/api/v1",
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_service_new() {
        let service = CliService::new("test-cli", "/api/test");
        assert_eq!(service.command, "test-cli");
        assert_eq!(service.api_prefix, "/api/test");
    }

    #[test]
    fn test_predefined_github_service() {
        let service = services::GITHUB;
        assert_eq!(service.command, "gh");
        assert_eq!(service.api_prefix, "/api/v3");
    }

    #[test]
    fn test_predefined_gitlab_service() {
        let service = services::GITLAB;
        assert_eq!(service.command, "glab");
        assert_eq!(service.api_prefix, "/api/v4");
    }

    #[test]
    fn test_predefined_forgejo_service() {
        let service = services::FORGEJO;
        assert_eq!(service.command, "tea");
        assert_eq!(service.api_prefix, "/api/v1");
    }
}
