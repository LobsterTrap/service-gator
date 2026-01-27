# service-gator development tasks
#
# Run `just --list` to see available targets organized by group.
#
# By default the layering is:
# Github Actions -> Justfile -> cargo
# --------------------------------------------------------------------

# Default recipe: show available commands
default:
    @just --list

# ============================================================================
# Core workflows - the main targets most developers will use
# ============================================================================

# Build in debug mode
[group('core')]
build:
    cargo build

# Build in release mode
[group('core')]
build-release:
    cargo build --release

# Run unit tests
[group('core')]
test:
    cargo test

# Run cargo fmt and clippy checks
[group('core')]
validate:
    cargo fmt -- --check
    cargo clippy -- -D warnings

# Matches default GHA run
[group('core')]
ci: validate build test kani
    @echo "All CI checks passed!"

# ============================================================================
# Development utilities
# ============================================================================

# Format code
[group('dev')]
fmt:
    cargo fmt

# Clean build artifacts
[group('dev')]
clean:
    cargo clean

# Run service-gator with arguments
[group('dev')]
run *ARGS:
    cargo run -- {{ARGS}}

# Build and install to ~/.cargo/bin
[group('dev')]
install:
    cargo install --path .

# ============================================================================
# MCP server
# ============================================================================

# Start MCP server on default port
[group('mcp')]
mcp-server port="8080":
    cargo run -- --mcp-server 127.0.0.1:{{port}}

# ============================================================================
# Testing and validation
# ============================================================================

# Quick smoke test
[group('testing')]
smoke-test: build
    ./target/debug/service-gator --help
    ./target/debug/service-gator gh --help
    @echo "Smoke test passed!"

# GitHub repo to test against (must be accessible with your GH_TOKEN)
TEST_GITHUB_REPO := "cgwalters/playground"

# JIRA project to test against
TEST_JIRA_PROJECT := "RHEL"
# JIRA server URL
JIRA_URL := "https://issues.redhat.com"
# Path to JIRA API token file
JIRA_TOKEN_FILE := "~/.config/jira"

# Run integration tests (requires GH_TOKEN for GitHub tests, JIRA_API_TOKEN for JIRA tests)
[group('testing')]
test-integration *ARGS: build-release
    #!/usr/bin/env bash
    set -euo pipefail
    export SERVICE_GATOR_PATH=$(pwd)/target/release/service-gator
    export TEST_GITHUB_REPO="{{ TEST_GITHUB_REPO }}"
    export TEST_JIRA_PROJECT="{{ TEST_JIRA_PROJECT }}"
    export JIRA_URL="{{ JIRA_URL }}"
    
    # Check for GH_TOKEN
    if [ -z "${GH_TOKEN:-}" ]; then
        echo "Warning: GH_TOKEN not set. GitHub tests will be skipped."
    fi
    
    # Check for JIRA_API_TOKEN
    if [ -z "${JIRA_API_TOKEN:-}" ]; then
        echo "Warning: JIRA_API_TOKEN not set. JIRA tests will be skipped."
    fi
    
    echo "Testing GitHub repo: $TEST_GITHUB_REPO"
    echo "Testing JIRA project: $TEST_JIRA_PROJECT @ $JIRA_URL"
    
    # Run integration tests
    if command -v cargo-nextest &> /dev/null; then
        cargo nextest run --release -p integration-tests {{ ARGS }}
    else
        cargo test --release -p integration-tests -- {{ ARGS }}
    fi

# ============================================================================
# Container builds
# ============================================================================

# Container image name
CONTAINER_IMAGE := "ghcr.io/cgwalters/service-gator"

# Build the container image
[group('container')]
container-build:
    podman build -t {{ CONTAINER_IMAGE }}:latest -f Containerfile .

# Test the container image
[group('container')]
container-test: container-build
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Testing container image..."
    
    # Verify the binary runs
    podman run --rm {{ CONTAINER_IMAGE }}:latest --help
    
    # Verify CLI tools are present
    podman run --rm --entrypoint gh {{ CONTAINER_IMAGE }}:latest --version
    podman run --rm --entrypoint glab {{ CONTAINER_IMAGE }}:latest --version
    podman run --rm --entrypoint tea {{ CONTAINER_IMAGE }}:latest --version
    
    echo "Container tests passed!"

# Build and push container image (for CI)
[group('container')]
container-push tag="latest": container-build
    podman push {{ CONTAINER_IMAGE }}:{{ tag }}
