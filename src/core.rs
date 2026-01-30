//! Core utilities for service-gator.
//!
//! This module provides common utilities for building security wrappers
//! around CLI tools.

use std::process::{Command, ExitCode, Stdio};

use eyre::{Context, Result};

/// Read a token from environment variables, trimming whitespace.
///
/// Tokens from podman secrets or other sources may contain trailing newlines
/// (e.g., from `echo "token" | podman secret create`). This causes
/// "invalid header field value for Authorization" errors.
pub fn get_token_trimmed(primary: &str, fallback: Option<&str>) -> Option<String> {
    let raw_value = std::env::var(primary)
        .ok()
        .or_else(|| fallback.and_then(|fb| std::env::var(fb).ok()))?;

    let trimmed = raw_value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Run a CLI command and capture stdout.
pub fn run_command_capture(command: &str, args: &[String]) -> Result<(ExitCode, String)> {
    let child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("spawning {command}"))?;

    let output = child
        .wait_with_output()
        .with_context(|| format!("waiting for {command}"))?;

    let exit_code = output
        .status
        .code()
        .map(|c| ExitCode::from(c as u8))
        .unwrap_or(ExitCode::from(1));

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    // Print stdout so user sees it
    print!("{}", stdout);

    Ok((exit_code, stdout))
}

/// Run a CLI command normally (pass through).
pub fn run_command(command: &str, args: &[String]) -> Result<ExitCode> {
    let status = Command::new(command)
        .args(args)
        .status()
        .with_context(|| format!("running {command}"))?;

    let exit_code = status
        .code()
        .map(|c| ExitCode::from(c as u8))
        .unwrap_or(ExitCode::from(1));

    Ok(exit_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_get_token_trimmed_basic() {
        env::set_var("TEST_TOKEN_BASIC", "mytoken");
        assert_eq!(
            get_token_trimmed("TEST_TOKEN_BASIC", None),
            Some("mytoken".to_string())
        );
        env::remove_var("TEST_TOKEN_BASIC");
    }

    #[test]
    fn test_get_token_trimmed_with_newline() {
        env::set_var("TEST_TOKEN_NEWLINE", "mytoken\n");
        assert_eq!(
            get_token_trimmed("TEST_TOKEN_NEWLINE", None),
            Some("mytoken".to_string())
        );
        env::remove_var("TEST_TOKEN_NEWLINE");
    }

    #[test]
    fn test_get_token_trimmed_with_crlf() {
        env::set_var("TEST_TOKEN_CRLF", "mytoken\r\n");
        assert_eq!(
            get_token_trimmed("TEST_TOKEN_CRLF", None),
            Some("mytoken".to_string())
        );
        env::remove_var("TEST_TOKEN_CRLF");
    }

    #[test]
    fn test_get_token_trimmed_with_leading_whitespace() {
        env::set_var("TEST_TOKEN_LEADING", "  mytoken");
        assert_eq!(
            get_token_trimmed("TEST_TOKEN_LEADING", None),
            Some("mytoken".to_string())
        );
        env::remove_var("TEST_TOKEN_LEADING");
    }

    #[test]
    fn test_get_token_trimmed_empty() {
        env::set_var("TEST_TOKEN_EMPTY", "");
        assert_eq!(get_token_trimmed("TEST_TOKEN_EMPTY", None), None);
        env::remove_var("TEST_TOKEN_EMPTY");
    }

    #[test]
    fn test_get_token_trimmed_whitespace_only() {
        env::set_var("TEST_TOKEN_WS", "  \n\t  ");
        assert_eq!(get_token_trimmed("TEST_TOKEN_WS", None), None);
        env::remove_var("TEST_TOKEN_WS");
    }

    #[test]
    fn test_get_token_trimmed_fallback() {
        env::remove_var("TEST_TOKEN_PRIMARY");
        env::set_var("TEST_TOKEN_FALLBACK", "fallback_token\n");
        assert_eq!(
            get_token_trimmed("TEST_TOKEN_PRIMARY", Some("TEST_TOKEN_FALLBACK")),
            Some("fallback_token".to_string())
        );
        env::remove_var("TEST_TOKEN_FALLBACK");
    }

    #[test]
    fn test_get_token_trimmed_primary_preferred() {
        env::set_var("TEST_TOKEN_PRI", "primary");
        env::set_var("TEST_TOKEN_FB", "fallback");
        assert_eq!(
            get_token_trimmed("TEST_TOKEN_PRI", Some("TEST_TOKEN_FB")),
            Some("primary".to_string())
        );
        env::remove_var("TEST_TOKEN_PRI");
        env::remove_var("TEST_TOKEN_FB");
    }

    #[test]
    fn test_get_token_trimmed_missing() {
        env::remove_var("TEST_TOKEN_MISSING");
        assert_eq!(get_token_trimmed("TEST_TOKEN_MISSING", None), None);
    }
}
