//! Core utilities for service-gator.
//!
//! This module provides common utilities for building security wrappers
//! around CLI tools.

use std::process::{Command, ExitCode, Stdio};

use eyre::{Context, Result};

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
