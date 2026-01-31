#![forbid(unsafe_code)]
//! Network-related newtypes with strict validation.
//!
//! These types enforce constraints at parse time, providing type-safe
//! representations of network concepts like hostnames.

use std::borrow::Cow;
use std::str::FromStr;

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

// ============================================================================
// Hostname
// ============================================================================

/// A validated hostname (domain name), optionally with a port.
///
/// Validates according to RFC 1123 with the following rules:
/// - No protocol prefix (`http://`, `https://`)
/// - No path suffix (`/api/v1`)
/// - Valid characters: alphanumeric, hyphens, dots
/// - Labels separated by dots, each 1-63 chars
/// - Labels cannot start or end with hyphen
/// - Total hostname length max 253 chars
/// - Cannot start or end with dot
/// - Optional port suffix (`:1234`) with port 1-65535
///
/// Examples of valid hostnames:
/// - `gitlab.example.com`
/// - `codeberg.org`
/// - `git.example.com:8443`
/// - `localhost`
///
/// Examples of invalid hostnames:
/// - `https://example.com` (has protocol)
/// - `example.com/api` (has path)
/// - `-example.com` (starts with hyphen)
/// - `example..com` (empty label)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hostname(String);

impl std::ops::Deref for Hostname {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Hostname {
    /// Maximum length for a hostname (excluding port).
    pub const MAX_LEN: usize = 253;
    /// Maximum length for a single label.
    pub const MAX_LABEL_LEN: usize = 63;

    /// Get the inner string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get the hostname part (without port).
    pub fn host(&self) -> &str {
        match self.0.rfind(':') {
            Some(pos) => {
                // Check if this is actually a port (all digits after colon)
                let after_colon = &self.0[pos + 1..];
                if !after_colon.is_empty() && after_colon.chars().all(|c| c.is_ascii_digit()) {
                    &self.0[..pos]
                } else {
                    &self.0
                }
            }
            None => &self.0,
        }
    }

    /// Get the port if specified.
    pub fn port(&self) -> Option<u16> {
        match self.0.rfind(':') {
            Some(pos) => {
                let after_colon = &self.0[pos + 1..];
                after_colon.parse().ok()
            }
            None => None,
        }
    }
}

impl FromStr for Hostname {
    type Err = HostnameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Check for protocol prefix
        if s.starts_with("http://") || s.starts_with("https://") {
            return Err(HostnameError::HasProtocol);
        }
        if s.contains("://") {
            return Err(HostnameError::HasProtocol);
        }

        // Check for path suffix
        if s.contains('/') {
            return Err(HostnameError::HasPath);
        }

        // Split off port if present
        let (hostname, port_str) = match s.rfind(':') {
            Some(pos) => {
                let after_colon = &s[pos + 1..];
                // Only treat as port if it's all digits
                if !after_colon.is_empty() && after_colon.chars().all(|c| c.is_ascii_digit()) {
                    (&s[..pos], Some(after_colon))
                } else {
                    (s, None)
                }
            }
            None => (s, None),
        };

        // Validate port if present
        if let Some(port) = port_str {
            let port_num: u32 = port
                .parse()
                .map_err(|_| HostnameError::InvalidPort(port.to_string()))?;
            if port_num == 0 || port_num > 65535 {
                return Err(HostnameError::InvalidPort(port.to_string()));
            }
        }

        // Validate hostname part
        if hostname.is_empty() {
            return Err(HostnameError::Empty);
        }

        if hostname.len() > Self::MAX_LEN {
            return Err(HostnameError::TooLong(hostname.len()));
        }

        if hostname.starts_with('.') {
            return Err(HostnameError::StartsWithDot);
        }

        if hostname.ends_with('.') {
            return Err(HostnameError::EndsWithDot);
        }

        // Validate each label
        for (i, label) in hostname.split('.').enumerate() {
            if label.is_empty() {
                return Err(HostnameError::EmptyLabel(i));
            }
            if label.len() > Self::MAX_LABEL_LEN {
                return Err(HostnameError::LabelTooLong(i, label.len()));
            }
            if label.starts_with('-') {
                return Err(HostnameError::LabelStartsWithHyphen(i));
            }
            if label.ends_with('-') {
                return Err(HostnameError::LabelEndsWithHyphen(i));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(HostnameError::InvalidChars(i));
            }
        }

        Ok(Hostname(s.to_string()))
    }
}

impl std::fmt::Display for Hostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error parsing a hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostnameError {
    Empty,
    TooLong(usize),
    HasProtocol,
    HasPath,
    StartsWithDot,
    EndsWithDot,
    EmptyLabel(usize),
    LabelTooLong(usize, usize),
    LabelStartsWithHyphen(usize),
    LabelEndsWithHyphen(usize),
    InvalidChars(usize),
    InvalidPort(String),
}

impl std::fmt::Display for HostnameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "hostname cannot be empty"),
            Self::TooLong(len) => {
                write!(
                    f,
                    "hostname too long ({} chars, max {})",
                    len,
                    Hostname::MAX_LEN
                )
            }
            Self::HasProtocol => write!(
                f,
                "hostname should not include protocol (remove http:// or https://)"
            ),
            Self::HasPath => write!(f, "hostname should not include path (remove /...)"),
            Self::StartsWithDot => write!(f, "hostname cannot start with '.'"),
            Self::EndsWithDot => write!(f, "hostname cannot end with '.'"),
            Self::EmptyLabel(i) => write!(f, "hostname label {} is empty (consecutive dots)", i),
            Self::LabelTooLong(i, len) => write!(
                f,
                "hostname label {} too long ({} chars, max {})",
                i,
                len,
                Hostname::MAX_LABEL_LEN
            ),
            Self::LabelStartsWithHyphen(i) => {
                write!(f, "hostname label {} cannot start with hyphen", i)
            }
            Self::LabelEndsWithHyphen(i) => {
                write!(f, "hostname label {} cannot end with hyphen", i)
            }
            Self::InvalidChars(i) => {
                write!(
                    f,
                    "hostname label {} contains invalid characters (only alphanumeric and hyphens allowed)",
                    i
                )
            }
            Self::InvalidPort(port) => write!(f, "invalid port '{}' (must be 1-65535)", port),
        }
    }
}

impl std::error::Error for HostnameError {}

impl<'de> Deserialize<'de> for Hostname {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Serialize for Hostname {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl JsonSchema for Hostname {
    fn schema_name() -> Cow<'static, str> {
        "Hostname".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Domain name (e.g., 'gitlab.example.com' or 'git.example.com:8443')",
            "maxLength": 260,
            "pattern": "^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*(:[0-9]{1,5})?$"
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_valid() {
        // Valid hostnames
        for input in [
            "example.com",
            "gitlab.example.com",
            "codeberg.org",
            "git.example.com",
            "localhost",
            "a.b.c.d.e",
            "my-server.example.com",
            "server1.example.com",
            "EXAMPLE.COM",
            "Example.Com",
        ] {
            assert!(
                input.parse::<Hostname>().is_ok(),
                "should be valid: {input}"
            );
        }
    }

    #[test]
    fn test_hostname_with_port() {
        // Valid hostnames with port
        for (input, expected_host, expected_port) in [
            ("example.com:8080", "example.com", Some(8080)),
            ("gitlab.example.com:443", "gitlab.example.com", Some(443)),
            ("localhost:3000", "localhost", Some(3000)),
            ("example.com:1", "example.com", Some(1)),
            ("example.com:65535", "example.com", Some(65535)),
            ("example.com", "example.com", None),
        ] {
            let hostname: Hostname = input
                .parse()
                .unwrap_or_else(|e| panic!("should parse {input}: {e}"));
            assert_eq!(hostname.host(), expected_host, "host for {input}");
            assert_eq!(hostname.port(), expected_port, "port for {input}");
        }
    }

    #[test]
    fn test_hostname_invalid_protocol() {
        for input in [
            "http://example.com",
            "https://example.com",
            "ftp://example.com",
            "ssh://example.com",
        ] {
            assert_eq!(
                input.parse::<Hostname>(),
                Err(HostnameError::HasProtocol),
                "should reject protocol: {input}"
            );
        }
    }

    #[test]
    fn test_hostname_invalid_path() {
        for input in [
            "example.com/",
            "example.com/api",
            "example.com/api/v1",
            "example.com/path/to/resource",
        ] {
            assert_eq!(
                input.parse::<Hostname>(),
                Err(HostnameError::HasPath),
                "should reject path: {input}"
            );
        }
    }

    #[test]
    fn test_hostname_invalid_dots() {
        assert_eq!(
            ".example.com".parse::<Hostname>(),
            Err(HostnameError::StartsWithDot)
        );
        assert_eq!(
            "example.com.".parse::<Hostname>(),
            Err(HostnameError::EndsWithDot)
        );
        assert_eq!(
            "example..com".parse::<Hostname>(),
            Err(HostnameError::EmptyLabel(1))
        );
    }

    #[test]
    fn test_hostname_invalid_hyphens() {
        assert_eq!(
            "-example.com".parse::<Hostname>(),
            Err(HostnameError::LabelStartsWithHyphen(0))
        );
        assert_eq!(
            "example-.com".parse::<Hostname>(),
            Err(HostnameError::LabelEndsWithHyphen(0))
        );
        assert_eq!(
            "example.-com".parse::<Hostname>(),
            Err(HostnameError::LabelStartsWithHyphen(1))
        );
        assert_eq!(
            "example.com-".parse::<Hostname>(),
            Err(HostnameError::LabelEndsWithHyphen(1))
        );
    }

    #[test]
    fn test_hostname_invalid_chars() {
        assert_eq!(
            "example_host.com".parse::<Hostname>(),
            Err(HostnameError::InvalidChars(0))
        );
        assert_eq!(
            "example.com!".parse::<Hostname>(),
            Err(HostnameError::InvalidChars(1))
        );
        assert_eq!(
            "exam ple.com".parse::<Hostname>(),
            Err(HostnameError::InvalidChars(0))
        );
    }

    #[test]
    fn test_hostname_invalid_port() {
        assert_eq!(
            "example.com:0".parse::<Hostname>(),
            Err(HostnameError::InvalidPort("0".to_string()))
        );
        assert_eq!(
            "example.com:65536".parse::<Hostname>(),
            Err(HostnameError::InvalidPort("65536".to_string()))
        );
        assert_eq!(
            "example.com:99999".parse::<Hostname>(),
            Err(HostnameError::InvalidPort("99999".to_string()))
        );
    }

    #[test]
    fn test_hostname_empty() {
        assert_eq!("".parse::<Hostname>(), Err(HostnameError::Empty));
    }

    #[test]
    fn test_hostname_too_long() {
        let long_hostname = "a".repeat(254);
        let result = long_hostname.parse::<Hostname>();
        assert!(matches!(result, Err(HostnameError::TooLong(254))));
    }

    #[test]
    fn test_hostname_label_too_long() {
        let long_label = "a".repeat(64);
        let hostname = format!("{}.com", long_label);
        let result = hostname.parse::<Hostname>();
        assert!(matches!(result, Err(HostnameError::LabelTooLong(0, 64))));
    }

    #[test]
    fn test_hostname_display() {
        let hostname: Hostname = "example.com:8080".parse().unwrap();
        assert_eq!(hostname.to_string(), "example.com:8080");
        assert_eq!(hostname.as_str(), "example.com:8080");
    }

    #[test]
    fn test_hostname_deserialize() {
        let hostname: Hostname = serde_json::from_str("\"example.com\"").unwrap();
        assert_eq!(hostname.as_str(), "example.com");

        let hostname: Hostname = serde_json::from_str("\"gitlab.example.com:8443\"").unwrap();
        assert_eq!(hostname.host(), "gitlab.example.com");
        assert_eq!(hostname.port(), Some(8443));
    }

    #[test]
    fn test_hostname_deserialize_invalid() {
        let result: Result<Hostname, _> = serde_json::from_str("\"https://example.com\"");
        assert!(result.is_err());

        let result: Result<Hostname, _> = serde_json::from_str("\"example.com/path\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_serialize() {
        let hostname: Hostname = "example.com:8080".parse().unwrap();
        let json = serde_json::to_string(&hostname).unwrap();
        assert_eq!(json, "\"example.com:8080\"");
    }
}

// ============================================================================
// WorkspacePath
// ============================================================================

/// A validated workspace path that must be under `/workspaces`.
///
/// This ensures agents can only access git repositories in the designated
/// workspace directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePath(camino::Utf8PathBuf);

/// The required prefix for workspace paths.
pub const WORKSPACE_PREFIX: &str = "/workspaces";

impl WorkspacePath {
    /// Get the inner path.
    pub fn as_path(&self) -> &camino::Utf8Path {
        &self.0
    }

    /// Join a path component.
    pub fn join(&self, path: impl AsRef<camino::Utf8Path>) -> camino::Utf8PathBuf {
        self.0.join(path)
    }
}

impl FromStr for WorkspacePath {
    type Err = WorkspacePathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(WorkspacePathError::Empty);
        }

        let path = camino::Utf8PathBuf::from(s);

        // Must be absolute
        if !path.is_absolute() {
            return Err(WorkspacePathError::NotAbsolute);
        }

        // Must be under /workspaces
        if !path.starts_with(WORKSPACE_PREFIX) {
            return Err(WorkspacePathError::NotUnderWorkspaces);
        }

        // Normalize and check for path traversal
        // We don't allow .. components
        for component in path.components() {
            if let camino::Utf8Component::ParentDir = component {
                return Err(WorkspacePathError::PathTraversal);
            }
        }

        Ok(WorkspacePath(path))
    }
}

impl std::fmt::Display for WorkspacePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<camino::Utf8Path> for WorkspacePath {
    fn as_ref(&self) -> &camino::Utf8Path {
        &self.0
    }
}

/// Error parsing a workspace path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspacePathError {
    Empty,
    NotAbsolute,
    NotUnderWorkspaces,
    PathTraversal,
}

impl std::fmt::Display for WorkspacePathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "path cannot be empty"),
            Self::NotAbsolute => write!(f, "path must be absolute"),
            Self::NotUnderWorkspaces => {
                write!(f, "path must be under {}", WORKSPACE_PREFIX)
            }
            Self::PathTraversal => write!(f, "path cannot contain '..' components"),
        }
    }
}

impl std::error::Error for WorkspacePathError {}

impl<'de> Deserialize<'de> for WorkspacePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl Serialize for WorkspacePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_str().serialize(serializer)
    }
}

impl JsonSchema for WorkspacePath {
    fn schema_name() -> Cow<'static, str> {
        "WorkspacePath".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Path to a git repository under /workspaces",
            "pattern": "^/workspaces/.+"
        })
    }
}

#[cfg(test)]
mod workspace_path_tests {
    use super::*;

    #[test]
    fn test_workspace_path_valid() {
        for input in [
            "/workspaces/myproject",
            "/workspaces/org/repo",
            "/workspaces/a/b/c/d",
        ] {
            let parsed: WorkspacePath = input.parse().expect(input);
            assert_eq!(parsed.to_string(), input);
        }
    }

    #[test]
    fn test_workspace_path_invalid() {
        // Not under /workspaces
        assert!(matches!(
            "/home/user/project".parse::<WorkspacePath>(),
            Err(WorkspacePathError::NotUnderWorkspaces)
        ));

        // Not absolute
        assert!(matches!(
            "workspaces/project".parse::<WorkspacePath>(),
            Err(WorkspacePathError::NotAbsolute)
        ));

        // Empty
        assert!(matches!(
            "".parse::<WorkspacePath>(),
            Err(WorkspacePathError::Empty)
        ));

        // Path traversal
        assert!(matches!(
            "/workspaces/../etc/passwd".parse::<WorkspacePath>(),
            Err(WorkspacePathError::PathTraversal)
        ));
    }

    #[test]
    fn test_workspace_path_deserialize() {
        let path: WorkspacePath = serde_json::from_str("\"/workspaces/test\"").unwrap();
        assert_eq!(path.to_string(), "/workspaces/test");

        // Invalid should fail
        assert!(serde_json::from_str::<WorkspacePath>("\"/home/test\"").is_err());
    }
}
