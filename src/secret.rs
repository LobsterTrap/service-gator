//! Secret string newtypes to prevent accidental logging of sensitive values.
//!
//! This module provides wrapper types for secrets that redact their values
//! in Debug output, preventing accidental exposure in logs.
//!
//! # Security Model
//!
//! - `Debug` implementations always show `[REDACTED]`, never the actual value
//! - No `Display` implementation to prevent accidental printing
//! - Access requires explicit `.expose_secret()` call (deliberate friction)
//! - Values are validated on construction where appropriate

#![forbid(unsafe_code)]

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

// ============================================================================
// SecretString - Generic wrapper for sensitive strings
// ============================================================================

/// A string that should never be logged or printed.
///
/// Use this for any sensitive string value (API keys, passwords, tokens, etc.)
/// that should be protected from accidental exposure in logs.
///
/// # Security
///
/// - `Debug` always shows `[REDACTED]`, never the actual value
/// - No `Display` implementation (prevents accidental printing)
/// - Access requires explicit `.expose_secret()` call
///
/// # Example
///
/// ```
/// use service_gator::secret::SecretString;
///
/// let secret = SecretString::new("my-api-key".to_string());
///
/// // Debug output is safe for logging
/// assert_eq!(format!("{:?}", secret), "SecretString([REDACTED])");
///
/// // Explicit access required
/// assert_eq!(secret.expose_secret(), "my-api-key");
/// ```
#[derive(Clone, PartialEq, Eq, Default)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    /// Create a new secret string.
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    /// Access the secret value.
    ///
    /// This method name provides deliberate friction - you must explicitly
    /// acknowledge that you're accessing a secret value.
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecretString::new(s))
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize the actual value (needed for config round-tripping)
        // The security is in Debug, not Serialize
        self.inner.serialize(serializer)
    }
}

// ============================================================================
// ApiToken - Validated token for forge APIs
// ============================================================================

/// A validated API token for forge services (GitHub, GitLab, Forgejo, JIRA).
///
/// Unlike `SecretString`, this type validates that the token is non-empty.
///
/// # Security
///
/// - `Debug` always shows `[REDACTED]`, never the actual value
/// - No `Display` implementation (prevents accidental printing)
/// - Access requires explicit `.expose_secret()` call
/// - Validated to be non-empty on construction
///
/// # Example
///
/// ```
/// use service_gator::secret::ApiToken;
///
/// // Valid token
/// let token = ApiToken::new("ghp_xxxx".to_string()).unwrap();
/// assert_eq!(format!("{:?}", token), "ApiToken([REDACTED])");
/// assert_eq!(token.expose_secret(), "ghp_xxxx");
///
/// // Empty tokens are rejected
/// assert!(ApiToken::new("".to_string()).is_err());
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct ApiToken {
    inner: SecretString,
}

/// Error returned when an API token is invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidApiToken {
    reason: &'static str,
}

impl fmt::Display for InvalidApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid API token: {}", self.reason)
    }
}

impl std::error::Error for InvalidApiToken {}

impl ApiToken {
    /// Create a new API token, validating that it is non-empty.
    pub fn new(value: String) -> Result<Self, InvalidApiToken> {
        if value.is_empty() {
            return Err(InvalidApiToken {
                reason: "token cannot be empty",
            });
        }
        Ok(Self {
            inner: SecretString::new(value),
        })
    }

    /// Access the token value.
    ///
    /// This method name provides deliberate friction - you must explicitly
    /// acknowledge that you're accessing a secret value.
    pub fn expose_secret(&self) -> &str {
        self.inner.expose_secret()
    }
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiToken([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for ApiToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        ApiToken::new(s).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ApiToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize the actual value (needed for config round-tripping)
        // The security is in Debug, not Serialize
        self.inner.serialize(serializer)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // SecretString tests
    // ========================================================================

    #[test]
    fn test_secret_string_debug_is_redacted() {
        let secret = SecretString::new("super-secret-value".to_string());
        let debug_output = format!("{:?}", secret);

        assert_eq!(debug_output, "SecretString([REDACTED])");
        assert!(
            !debug_output.contains("super-secret-value"),
            "Debug output must not contain the secret value"
        );
    }

    #[test]
    fn test_secret_string_expose_secret() {
        let secret = SecretString::new("my-secret".to_string());
        assert_eq!(secret.expose_secret(), "my-secret");
    }

    #[test]
    fn test_secret_string_equality() {
        let s1 = SecretString::new("same".to_string());
        let s2 = SecretString::new("same".to_string());
        let s3 = SecretString::new("different".to_string());

        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_secret_string_clone() {
        let original = SecretString::new("cloneable".to_string());
        let cloned = original.clone();

        assert_eq!(original.expose_secret(), cloned.expose_secret());
    }

    #[test]
    fn test_secret_string_deserialize() {
        let json = r#""my-api-key""#;
        let secret: SecretString = serde_json::from_str(json).unwrap();
        assert_eq!(secret.expose_secret(), "my-api-key");
    }

    #[test]
    fn test_secret_string_allows_empty() {
        // SecretString doesn't validate, so empty strings are allowed
        let secret = SecretString::new(String::new());
        assert_eq!(secret.expose_secret(), "");
    }

    // ========================================================================
    // ApiToken tests
    // ========================================================================

    #[test]
    fn test_api_token_debug_is_redacted() {
        let token = ApiToken::new("ghp_xxxxxxxxxxxx".to_string()).unwrap();
        let debug_output = format!("{:?}", token);

        assert_eq!(debug_output, "ApiToken([REDACTED])");
        assert!(
            !debug_output.contains("ghp_"),
            "Debug output must not contain the token value"
        );
    }

    #[test]
    fn test_api_token_expose_secret() {
        let token = ApiToken::new("my-token".to_string()).unwrap();
        assert_eq!(token.expose_secret(), "my-token");
    }

    #[test]
    fn test_api_token_rejects_empty() {
        let result = ApiToken::new(String::new());
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(err.reason, "token cannot be empty");
    }

    #[test]
    fn test_api_token_equality() {
        let t1 = ApiToken::new("same".to_string()).unwrap();
        let t2 = ApiToken::new("same".to_string()).unwrap();
        let t3 = ApiToken::new("different".to_string()).unwrap();

        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_api_token_clone() {
        let original = ApiToken::new("cloneable".to_string()).unwrap();
        let cloned = original.clone();

        assert_eq!(original.expose_secret(), cloned.expose_secret());
    }

    #[test]
    fn test_api_token_deserialize() {
        let json = r#""my-api-token""#;
        let token: ApiToken = serde_json::from_str(json).unwrap();
        assert_eq!(token.expose_secret(), "my-api-token");
    }

    #[test]
    fn test_api_token_deserialize_empty_fails() {
        let json = r#""""#;
        let result: Result<ApiToken, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ========================================================================
    // Critical security test
    // ========================================================================

    #[test]
    fn test_debug_never_contains_secret_value() {
        // Test with various secret values, including ones that might trip up
        // naive implementations
        let test_values = vec![
            "simple-secret",
            "ghp_1234567890abcdef",
            "glpat-xxxxxxxxxxxx",
            "password with spaces",
            "secret\nwith\nnewlines",
            "secret\twith\ttabs",
            // Note: We can't test "[REDACTED]", "SecretString", or "ApiToken" as
            // values since the debug output intentionally contains those strings.
            // This is an inherent limitation of redaction.
        ];

        for value in test_values {
            let secret = SecretString::new(value.to_string());
            let token = ApiToken::new(value.to_string()).unwrap();

            let secret_debug = format!("{:?}", secret);
            let token_debug = format!("{:?}", token);

            assert!(
                !secret_debug.contains(value),
                "SecretString debug output contained secret value: {}",
                value
            );
            assert!(
                !token_debug.contains(value),
                "ApiToken debug output contained secret value: {}",
                value
            );
        }
    }

    #[test]
    fn test_format_in_struct_debug() {
        // Test that secrets are redacted even when embedded in structs
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Config {
            token: ApiToken,
            secret: SecretString,
        }

        let config = Config {
            token: ApiToken::new("ghp_secret_token".to_string()).unwrap(),
            secret: SecretString::new("my_password".to_string()),
        };

        let debug = format!("{:?}", config);
        assert!(!debug.contains("ghp_secret_token"));
        assert!(!debug.contains("my_password"));
        assert!(debug.contains("[REDACTED]"));
    }
}
