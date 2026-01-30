#![forbid(unsafe_code)]
//! JIRA-related newtypes with strict validation.
//!
//! These types enforce constraints at parse time, providing type-safe
//! representations of JIRA concepts like project keys and issue keys.

use std::borrow::Cow;
use std::str::FromStr;

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};

// ============================================================================
// JiraProjectKey
// ============================================================================

/// A validated JIRA project key.
///
/// JIRA project keys are 2-10 uppercase alphanumeric characters.
/// Must start with a letter.
///
/// Examples: `PROJ`, `ABC`, `TEST123`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JiraProjectKey(String);

impl Serialize for JiraProjectKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl JiraProjectKey {
    /// Minimum length for a project key.
    pub const MIN_LEN: usize = 2;
    /// Maximum length for a project key.
    pub const MAX_LEN: usize = 10;

    /// Get the inner string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for JiraProjectKey {
    type Err = JiraProjectKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() < Self::MIN_LEN {
            return Err(JiraProjectKeyError::TooShort(s.len()));
        }
        if s.len() > Self::MAX_LEN {
            return Err(JiraProjectKeyError::TooLong(s.len()));
        }

        let first = s.chars().next().expect("length checked above");
        if !first.is_ascii_alphabetic() {
            return Err(JiraProjectKeyError::MustStartWithLetter);
        }

        if !s.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(JiraProjectKeyError::InvalidChars);
        }

        // Store as uppercase (JIRA project keys are case-insensitive but displayed uppercase)
        Ok(JiraProjectKey(s.to_ascii_uppercase()))
    }
}

impl std::fmt::Display for JiraProjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error parsing a JIRA project key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JiraProjectKeyError {
    TooShort(usize),
    TooLong(usize),
    MustStartWithLetter,
    InvalidChars,
}

impl std::fmt::Display for JiraProjectKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort(len) => write!(
                f,
                "project key too short ({} chars, min {})",
                len,
                JiraProjectKey::MIN_LEN
            ),
            Self::TooLong(len) => write!(
                f,
                "project key too long ({} chars, max {})",
                len,
                JiraProjectKey::MAX_LEN
            ),
            Self::MustStartWithLetter => {
                write!(f, "project key must start with a letter")
            }
            Self::InvalidChars => {
                write!(f, "project key must be alphanumeric (A-Z, 0-9)")
            }
        }
    }
}

impl std::error::Error for JiraProjectKeyError {}

impl<'de> Deserialize<'de> for JiraProjectKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for JiraProjectKey {
    fn schema_name() -> Cow<'static, str> {
        "JiraProjectKey".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "JIRA project key (2-10 uppercase alphanumeric chars, starts with letter)",
            "minLength": JiraProjectKey::MIN_LEN,
            "maxLength": JiraProjectKey::MAX_LEN,
            "pattern": "^[A-Za-z][A-Za-z0-9]{1,9}$"
        })
    }
}

// ============================================================================
// JiraIssueKey
// ============================================================================

/// A validated JIRA issue key.
///
/// Format: `PROJECT-NUMBER` (e.g., `PROJ-123`, `ABC-1`)
///
/// - PROJECT part follows `JiraProjectKey` rules
/// - NUMBER is a positive integer (> 0)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JiraIssueKey {
    project: String,
    number: u64,
}

impl Serialize for JiraIssueKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl JiraIssueKey {
    /// Get the project part of the issue key.
    pub fn project(&self) -> &str {
        &self.project
    }

    /// Get the issue number.
    pub fn number(&self) -> u64 {
        self.number
    }
}

impl FromStr for JiraIssueKey {
    type Err = JiraIssueKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (project_str, number_str) = s
            .split_once('-')
            .ok_or_else(|| JiraIssueKeyError::MissingHyphen(s.to_string()))?;

        // Validate project part
        let project_key: JiraProjectKey = project_str
            .parse()
            .map_err(JiraIssueKeyError::InvalidProject)?;

        // Validate number part
        if number_str.is_empty() {
            return Err(JiraIssueKeyError::EmptyNumber);
        }

        let number: u64 = number_str
            .parse()
            .map_err(|_| JiraIssueKeyError::InvalidNumber)?;

        if number == 0 {
            return Err(JiraIssueKeyError::ZeroNumber);
        }

        Ok(JiraIssueKey {
            project: project_key.as_str().to_string(),
            number,
        })
    }
}

impl std::fmt::Display for JiraIssueKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.project, self.number)
    }
}

/// Error parsing a JIRA issue key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JiraIssueKeyError {
    MissingHyphen(String),
    InvalidProject(JiraProjectKeyError),
    EmptyNumber,
    InvalidNumber,
    ZeroNumber,
}

impl std::fmt::Display for JiraIssueKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingHyphen(s) => {
                write!(f, "expected 'PROJECT-NUMBER' format, got '{}'", s)
            }
            Self::InvalidProject(e) => write!(f, "invalid project in issue key: {}", e),
            Self::EmptyNumber => write!(f, "issue number cannot be empty"),
            Self::InvalidNumber => write!(f, "issue number must be a positive integer"),
            Self::ZeroNumber => write!(f, "issue number must be greater than 0"),
        }
    }
}

impl std::error::Error for JiraIssueKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidProject(e) => Some(e),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for JiraIssueKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for JiraIssueKey {
    fn schema_name() -> Cow<'static, str> {
        "JiraIssueKey".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "JIRA issue key in 'PROJECT-NUMBER' format (e.g., PROJ-123)",
            "pattern": "^[A-Za-z][A-Za-z0-9]{1,9}-[1-9][0-9]*$"
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // JiraProjectKey tests
    // ========================================================================

    #[test]
    fn test_project_key_valid() {
        for (input, expected) in [
            ("AB", "AB"),
            ("PROJ", "PROJ"),
            ("ABC", "ABC"),
            ("TEST123", "TEST123"),
            ("A1", "A1"),
            ("ABCDEFGHIJ", "ABCDEFGHIJ"), // exactly 10 chars
            // Case-insensitive, stored as uppercase
            ("proj", "PROJ"),
            ("Abc123", "ABC123"),
        ] {
            let parsed: JiraProjectKey = input
                .parse()
                .unwrap_or_else(|e| panic!("should parse '{}': {:?}", input, e));
            assert_eq!(parsed.as_str(), expected, "input: {}", input);
            assert_eq!(parsed.to_string(), expected, "input: {}", input);
        }
    }

    #[test]
    fn test_project_key_too_short() {
        for input in ["", "A"] {
            assert_eq!(
                input.parse::<JiraProjectKey>(),
                Err(JiraProjectKeyError::TooShort(input.len())),
                "input: '{}'",
                input
            );
        }
    }

    #[test]
    fn test_project_key_too_long() {
        let input = "ABCDEFGHIJK"; // 11 chars
        assert_eq!(
            input.parse::<JiraProjectKey>(),
            Err(JiraProjectKeyError::TooLong(11))
        );
    }

    #[test]
    fn test_project_key_must_start_with_letter() {
        for input in ["12", "1ABC", "0XYZ"] {
            assert_eq!(
                input.parse::<JiraProjectKey>(),
                Err(JiraProjectKeyError::MustStartWithLetter),
                "input: '{}'",
                input
            );
        }
    }

    #[test]
    fn test_project_key_invalid_chars() {
        for input in ["AB-C", "AB_C", "AB.C", "AB C", "AB@C"] {
            assert_eq!(
                input.parse::<JiraProjectKey>(),
                Err(JiraProjectKeyError::InvalidChars),
                "input: '{}'",
                input
            );
        }
    }

    #[test]
    fn test_project_key_deserialize() {
        let key: JiraProjectKey = serde_json::from_str("\"PROJ\"").unwrap();
        assert_eq!(key.as_str(), "PROJ");

        // Case-insensitive
        let key: JiraProjectKey = serde_json::from_str("\"proj\"").unwrap();
        assert_eq!(key.as_str(), "PROJ");

        // Invalid should fail
        assert!(serde_json::from_str::<JiraProjectKey>("\"A\"").is_err());
    }

    // ========================================================================
    // JiraIssueKey tests
    // ========================================================================

    #[test]
    fn test_issue_key_valid() {
        for (input, expected_project, expected_number) in [
            ("PROJ-123", "PROJ", 123),
            ("ABC-1", "ABC", 1),
            ("TEST123-999", "TEST123", 999),
            ("AB-42", "AB", 42),
            // Case-insensitive project part
            ("proj-123", "PROJ", 123),
            ("Abc-1", "ABC", 1),
        ] {
            let parsed: JiraIssueKey = input
                .parse()
                .unwrap_or_else(|e| panic!("should parse '{}': {:?}", input, e));
            assert_eq!(parsed.project(), expected_project, "input: {}", input);
            assert_eq!(parsed.number(), expected_number, "input: {}", input);
        }
    }

    #[test]
    fn test_issue_key_display() {
        let key: JiraIssueKey = "PROJ-123".parse().unwrap();
        assert_eq!(key.to_string(), "PROJ-123");

        // Lowercase input should display as uppercase
        let key: JiraIssueKey = "proj-42".parse().unwrap();
        assert_eq!(key.to_string(), "PROJ-42");
    }

    #[test]
    fn test_issue_key_missing_hyphen() {
        for input in ["PROJ123", "ABC", "NOHYPHEN"] {
            assert_eq!(
                input.parse::<JiraIssueKey>(),
                Err(JiraIssueKeyError::MissingHyphen(input.to_string())),
                "input: '{}'",
                input
            );
        }
    }

    #[test]
    fn test_issue_key_invalid_project() {
        for input in ["A-123", "123-456", "-123"] {
            let result = input.parse::<JiraIssueKey>();
            assert!(
                matches!(result, Err(JiraIssueKeyError::InvalidProject(_))),
                "input '{}' should have invalid project: {:?}",
                input,
                result
            );
        }
    }

    #[test]
    fn test_issue_key_empty_number() {
        assert_eq!(
            "PROJ-".parse::<JiraIssueKey>(),
            Err(JiraIssueKeyError::EmptyNumber)
        );
    }

    #[test]
    fn test_issue_key_invalid_number() {
        for input in ["PROJ-abc", "PROJ-12.3", "PROJ--1"] {
            assert_eq!(
                input.parse::<JiraIssueKey>(),
                Err(JiraIssueKeyError::InvalidNumber),
                "input: '{}'",
                input
            );
        }
    }

    #[test]
    fn test_issue_key_zero_number() {
        assert_eq!(
            "PROJ-0".parse::<JiraIssueKey>(),
            Err(JiraIssueKeyError::ZeroNumber)
        );
    }

    #[test]
    fn test_issue_key_deserialize() {
        let key: JiraIssueKey = serde_json::from_str("\"PROJ-123\"").unwrap();
        assert_eq!(key.project(), "PROJ");
        assert_eq!(key.number(), 123);

        // Invalid should fail
        assert!(serde_json::from_str::<JiraIssueKey>("\"invalid\"").is_err());
        assert!(serde_json::from_str::<JiraIssueKey>("\"PROJ-0\"").is_err());
    }

    #[test]
    fn test_issue_key_equality() {
        let key1: JiraIssueKey = "PROJ-123".parse().unwrap();
        let key2: JiraIssueKey = "proj-123".parse().unwrap();
        let key3: JiraIssueKey = "PROJ-456".parse().unwrap();

        assert_eq!(key1, key2); // Case-insensitive
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_error_display() {
        let err = JiraProjectKeyError::TooShort(1);
        assert!(err.to_string().contains("too short"));

        let err = JiraIssueKeyError::MissingHyphen("ABC".to_string());
        assert!(err.to_string().contains("PROJECT-NUMBER"));
    }

    #[test]
    fn test_issue_key_leading_zeros_normalized() {
        // Leading zeros in issue numbers are stripped (JIRA doesn't use them)
        let key: JiraIssueKey = "PROJ-007".parse().unwrap();
        assert_eq!(key.number(), 7);
        assert_eq!(key.to_string(), "PROJ-7");

        let key: JiraIssueKey = "PROJ-0042".parse().unwrap();
        assert_eq!(key.number(), 42);
        assert_eq!(key.to_string(), "PROJ-42");
    }
}
