//! Integration tests for service-gator
//!
//! These tests verify end-to-end functionality including the MCP server
//! with actual GitHub API access (when GH_TOKEN is available).

use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use eyre::{Context, Result};
use libtest_mimic::{Arguments, Trial};
use tempfile::TempDir;

// Re-export from lib for internal use
pub(crate) use integration_tests::INTEGRATION_TESTS;

mod mcp_client;
mod tests {
    pub mod forgejo;
    pub mod jira;
    pub mod mcp_server;
    pub mod rmcp_client;
    pub mod status_tests;
}

/// Get the path to the service-gator binary
///
/// Checks SERVICE_GATOR_PATH env var first, then falls back to "service-gator".
/// If a binary is detected in target/ directories, forces the user to set the
/// env var explicitly to avoid confusion about which binary is being tested.
pub(crate) fn get_service_gator_path() -> Result<PathBuf> {
    // Check for explicit override
    if let Ok(path) = std::env::var("SERVICE_GATOR_PATH") {
        return Ok(PathBuf::from(path));
    }

    // Force the user to set this if we're running from the project dir
    let candidates = ["target/release/service-gator", "target/debug/service-gator"];
    if let Some(path) = candidates.into_iter().find(|p| PathBuf::from(p).exists()) {
        return Err(eyre::eyre!(
            "Detected {path} - set SERVICE_GATOR_PATH={path} to run using this binary"
        ));
    }

    // Fall back to assuming it's in PATH
    Ok(PathBuf::from("service-gator"))
}

/// Get the GitHub token for testing
pub(crate) fn get_gh_token() -> Option<String> {
    // Check GH_TOKEN env var first
    if let Ok(token) = std::env::var("GH_TOKEN") {
        if !token.is_empty() {
            return Some(token);
        }
    }

    // Try reading from standard gh CLI config location
    if let Ok(home) = std::env::var("HOME") {
        let token_file = PathBuf::from(&home).join(".config/gh-full");
        if token_file.exists() {
            if let Ok(token) = std::fs::read_to_string(&token_file) {
                let token = token.trim().to_string();
                if !token.is_empty() {
                    return Some(token);
                }
            }
        }
    }

    None
}

/// Get the JIRA API token for testing
pub(crate) fn get_jira_token() -> Option<String> {
    // Check JIRA_API_TOKEN env var (set by Justfile or user)
    if let Ok(token) = std::env::var("JIRA_API_TOKEN") {
        if !token.is_empty() {
            return Some(token);
        }
    }

    None
}

/// Find an available port for the MCP server
pub(crate) fn find_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to random port")
        .local_addr()
        .expect("Failed to get local address")
        .port()
}

/// A running service-gator MCP server for testing
pub(crate) struct McpServerHandle {
    child: Child,
    #[allow(dead_code)]
    port: u16,
    base_url: String,
    #[allow(dead_code)]
    config_dir: TempDir,
}

/// Options for starting an MCP server
#[derive(Default)]
pub(crate) struct McpServerOptions {
    /// GitHub token (required for GitHub tests)
    pub gh_token: Option<String>,
    /// JIRA API token (required for JIRA tests)
    pub jira_token: Option<String>,
    /// JIRA server URL
    pub jira_url: Option<String>,
}

impl McpServerHandle {
    /// Start a new MCP server with the given scope configuration
    pub fn start(scope_config: &str) -> Result<Self> {
        Self::start_with_options(
            scope_config,
            McpServerOptions {
                gh_token: get_gh_token(),
                jira_token: get_jira_token(),
                jira_url: std::env::var("JIRA_URL").ok(),
            },
        )
    }

    /// Start a new MCP server with explicit options
    pub fn start_with_options(scope_config: &str, options: McpServerOptions) -> Result<Self> {
        let config_dir = TempDir::new().context("creating temp dir")?;
        let config_path = config_dir.path().join("service-gator.toml");

        // Write scope config
        let mut file = std::fs::File::create(&config_path)?;
        file.write_all(scope_config.as_bytes())?;

        let port = find_available_port();
        let addr = format!("127.0.0.1:{}", port);
        let binary_path = get_service_gator_path()?;

        let mut cmd = Command::new(&binary_path);
        cmd.arg("--config")
            .arg(&config_path)
            .arg("--mcp-server")
            .arg(&addr)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Add tokens if available
        if let Some(gh_token) = options.gh_token {
            cmd.env("GH_TOKEN", gh_token);
        }
        if let Some(jira_token) = options.jira_token {
            cmd.env("JIRA_API_TOKEN", jira_token);
        }
        if let Some(jira_url) = options.jira_url {
            cmd.env("JIRA_URL", jira_url);
        }

        let child = cmd
            .spawn()
            .with_context(|| format!("spawning service-gator from {:?}", binary_path))?;

        let base_url = format!("http://127.0.0.1:{}", port);

        // Wait for server to be ready
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(10);

        while start.elapsed() < timeout {
            if std::net::TcpStream::connect(&addr).is_ok() {
                return Ok(Self {
                    child,
                    port,
                    base_url,
                    config_dir,
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        Err(eyre::eyre!(
            "Timeout waiting for MCP server to start on {}",
            addr
        ))
    }

    /// Get the MCP endpoint URL
    pub fn mcp_url(&self) -> String {
        format!("{}/mcp", self.base_url)
    }
}

impl Drop for McpServerHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Captured output from a command with decoded stdout/stderr strings
pub(crate) struct CapturedOutput {
    pub output: Output,
    pub stdout: String,
    pub stderr: String,
}

impl CapturedOutput {
    /// Create from a raw Output
    pub fn new(output: Output) -> Self {
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        Self {
            output,
            stdout,
            stderr,
        }
    }

    /// Assert that the command succeeded, printing debug info on failure
    #[allow(dead_code)]
    pub fn assert_success(&self, context: &str) {
        assert!(
            self.output.status.success(),
            "{} failed (exit {:?}):\nstdout: {}\nstderr: {}",
            context,
            self.output.status.code(),
            self.stdout,
            self.stderr
        );
    }

    /// Check if the command succeeded
    #[allow(dead_code)]
    pub fn success(&self) -> bool {
        self.output.status.success()
    }
}

/// Run a command, capturing output
#[allow(dead_code)]
pub(crate) fn run_command(program: &str, args: &[&str]) -> std::io::Result<CapturedOutput> {
    let output = Command::new(program).args(args).output()?;
    Ok(CapturedOutput::new(output))
}

fn main() {
    let args = Arguments::from_args();

    // Check if GH_TOKEN is available; skip tests that require it if not
    let gh_token_available = get_gh_token().is_some();
    if !gh_token_available {
        eprintln!(
            "Warning: GH_TOKEN not available. Some tests will be skipped.\n\
             Set GH_TOKEN env var or create ~/.config/gh-full to enable all tests."
        );
    }

    let tests: Vec<Trial> = INTEGRATION_TESTS
        .iter()
        .map(|test| {
            let name = test.name;
            let f = test.f;

            // Mark tests as ignored if they require GH_TOKEN and it's not available
            let requires_token = name.contains("mcp") || name.contains("github");
            let ignored = requires_token && !gh_token_available;

            Trial::test(name, move || f().map_err(|e| format!("{:?}", e).into()))
                .with_ignored_flag(ignored)
        })
        .collect();

    libtest_mimic::run(&args, tests).exit();
}
