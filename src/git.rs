#![forbid(unsafe_code)]
//! Git-related newtypes with strict validation.
//!
//! These types enforce constraints at parse time, providing type-safe
//! representations of git concepts like commit SHAs, branch names, and
//! repository identifiers.

use std::borrow::Cow;
use std::str::FromStr;

use rmcp::schemars::{self, JsonSchema};
use serde::Deserialize;

// ============================================================================
// CommitSha
// ============================================================================

/// A validated 40-character hex commit SHA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitSha(String);

impl CommitSha {
    /// Get the inner string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for CommitSha {
    type Err = CommitShaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 40 {
            return Err(CommitShaError::InvalidLength(s.len()));
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CommitShaError::InvalidChars);
        }
        Ok(CommitSha(s.to_string()))
    }
}

impl std::fmt::Display for CommitSha {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error parsing a commit SHA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitShaError {
    InvalidLength(usize),
    InvalidChars,
}

impl std::fmt::Display for CommitShaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength(len) => {
                write!(f, "commit SHA must be 40 characters, got {}", len)
            }
            Self::InvalidChars => write!(f, "commit SHA must be hexadecimal"),
        }
    }
}

impl std::error::Error for CommitShaError {}

impl<'de> Deserialize<'de> for CommitSha {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for CommitSha {
    fn schema_name() -> Cow<'static, str> {
        "CommitSha".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Git commit SHA (40-character hex string)",
            "minLength": 40,
            "maxLength": 40,
            "pattern": "^[a-fA-F0-9]{40}$"
        })
    }
}

// ============================================================================
// BranchDescription
// ============================================================================

/// A validated branch description for agent branches.
///
/// Must be 1-200 characters, ASCII alphanumeric with hyphens only,
/// cannot start or end with hyphen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchDescription(String);

impl BranchDescription {
    /// Maximum length for a branch description.
    ///
    /// 200 chars is under GitHub/GitLab's 255 char limit for branch names,
    /// leaving room for the `agent-` prefix.
    pub const MAX_LEN: usize = 200;

    /// Get the inner string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for BranchDescription {
    type Err = BranchDescriptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(BranchDescriptionError::Empty);
        }
        if s.len() > Self::MAX_LEN {
            return Err(BranchDescriptionError::TooLong(s.len()));
        }
        if s.starts_with('-') {
            return Err(BranchDescriptionError::StartsWithHyphen);
        }
        if s.ends_with('-') {
            return Err(BranchDescriptionError::EndsWithHyphen);
        }
        if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(BranchDescriptionError::InvalidChars);
        }
        Ok(BranchDescription(s.to_string()))
    }
}

impl std::fmt::Display for BranchDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error parsing a branch description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchDescriptionError {
    Empty,
    TooLong(usize),
    StartsWithHyphen,
    EndsWithHyphen,
    InvalidChars,
}

impl std::fmt::Display for BranchDescriptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "description cannot be empty"),
            Self::TooLong(len) => write!(
                f,
                "description too long ({} chars, max {})",
                len,
                BranchDescription::MAX_LEN
            ),
            Self::StartsWithHyphen => write!(f, "description cannot start with hyphen"),
            Self::EndsWithHyphen => write!(f, "description cannot end with hyphen"),
            Self::InvalidChars => {
                write!(
                    f,
                    "description must be ASCII alphanumeric with hyphens only"
                )
            }
        }
    }
}

impl std::error::Error for BranchDescriptionError {}

impl<'de> Deserialize<'de> for BranchDescription {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for BranchDescription {
    fn schema_name() -> Cow<'static, str> {
        "BranchDescription".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Short description for branch name (1-200 chars, alphanumeric + hyphens)",
            "maxLength": BranchDescription::MAX_LEN,
            "pattern": "^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$"
        })
    }
}

// ============================================================================
// RepoName (GitHub/Forgejo - strict 2-level)
// ============================================================================

/// A validated repository name in "owner/repo" format.
///
/// Used for GitHub and Forgejo which use strict 2-level paths.
/// For GitLab's nested groups, use `ProjectPath` instead.
///
/// - Owner: 1-39 chars, alphanumeric or hyphen, cannot start with hyphen
/// - Repo: 1-100 chars, alphanumeric, hyphen, underscore, or dot
/// - Neither can be empty
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoName {
    owner: String,
    repo: String,
}

impl RepoName {
    /// Maximum length for owner name (GitHub limit).
    pub const MAX_OWNER_LEN: usize = 39;
    /// Maximum length for repo name (GitHub limit).
    pub const MAX_REPO_LEN: usize = 100;

    /// Get the owner part.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the repo part.
    pub fn repo(&self) -> &str {
        &self.repo
    }
}

impl FromStr for RepoName {
    type Err = RepoNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (owner, repo) = s
            .split_once('/')
            .ok_or_else(|| RepoNameError::MissingSlash(s.to_string()))?;

        // Reject nested paths (more than one slash)
        if repo.contains('/') {
            return Err(RepoNameError::TooManyLevels(s.to_string()));
        }

        // Validate owner
        if owner.is_empty() {
            return Err(RepoNameError::EmptyOwner);
        }
        if owner.len() > Self::MAX_OWNER_LEN {
            return Err(RepoNameError::OwnerTooLong(owner.len()));
        }
        if owner.starts_with('-') {
            return Err(RepoNameError::OwnerStartsWithHyphen);
        }
        if !owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(RepoNameError::InvalidOwnerChars);
        }

        // Validate repo
        if repo.is_empty() {
            return Err(RepoNameError::EmptyRepo);
        }
        if repo.len() > Self::MAX_REPO_LEN {
            return Err(RepoNameError::RepoTooLong(repo.len()));
        }
        if !repo
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(RepoNameError::InvalidRepoChars);
        }
        // GitHub doesn't allow repos starting with dot
        if repo.starts_with('.') {
            return Err(RepoNameError::RepoStartsWithDot);
        }

        Ok(RepoName {
            owner: owner.to_string(),
            repo: repo.to_string(),
        })
    }
}

impl std::fmt::Display for RepoName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.owner, self.repo)
    }
}

impl RepoName {
    /// Get the full "owner/repo" string.
    pub fn as_str(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }
}

/// Error parsing a repository name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoNameError {
    MissingSlash(String),
    TooManyLevels(String),
    EmptyOwner,
    EmptyRepo,
    OwnerTooLong(usize),
    RepoTooLong(usize),
    OwnerStartsWithHyphen,
    RepoStartsWithDot,
    InvalidOwnerChars,
    InvalidRepoChars,
}

impl std::fmt::Display for RepoNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingSlash(s) => write!(f, "expected 'owner/repo' format, got '{}'", s),
            Self::TooManyLevels(s) => write!(
                f,
                "expected 'owner/repo' format (2 levels), got '{}' - use ProjectPath for GitLab",
                s
            ),
            Self::EmptyOwner => write!(f, "owner cannot be empty"),
            Self::EmptyRepo => write!(f, "repo cannot be empty"),
            Self::OwnerTooLong(len) => write!(
                f,
                "owner too long ({} chars, max {})",
                len,
                RepoName::MAX_OWNER_LEN
            ),
            Self::RepoTooLong(len) => write!(
                f,
                "repo too long ({} chars, max {})",
                len,
                RepoName::MAX_REPO_LEN
            ),
            Self::OwnerStartsWithHyphen => write!(f, "owner cannot start with hyphen"),
            Self::RepoStartsWithDot => write!(f, "repo cannot start with dot"),
            Self::InvalidOwnerChars => {
                write!(f, "owner must be alphanumeric with hyphens only")
            }
            Self::InvalidRepoChars => {
                write!(
                    f,
                    "repo must be alphanumeric with hyphens, underscores, or dots"
                )
            }
        }
    }
}

impl std::error::Error for RepoNameError {}

impl<'de> Deserialize<'de> for RepoName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for RepoName {
    fn schema_name() -> Cow<'static, str> {
        "RepoName".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Repository in 'owner/repo' format (GitHub/Forgejo)",
            "pattern": "^[a-zA-Z0-9][a-zA-Z0-9-]*/[a-zA-Z0-9][a-zA-Z0-9._-]*$"
        })
    }
}

// ============================================================================
// ProjectPath (GitLab - supports nested groups)
// ============================================================================

/// A validated GitLab project path supporting nested groups.
///
/// GitLab supports arbitrarily nested group paths like `group/subgroup/project`.
/// Each segment must be valid (alphanumeric, hyphen, underscore, dot).
///
/// Minimum: 2 segments (group/project)
/// Maximum: 20 segments (GitLab limit)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPath {
    segments: Vec<String>,
}

impl ProjectPath {
    /// Maximum number of path segments (GitLab's nesting limit).
    pub const MAX_DEPTH: usize = 20;
    /// Maximum length for each segment.
    pub const MAX_SEGMENT_LEN: usize = 100;

    /// Get the namespace (all segments except the last).
    pub fn namespace(&self) -> String {
        self.segments[..self.segments.len() - 1].join("/")
    }

    /// Get the project name (last segment).
    pub fn project(&self) -> &str {
        self.segments.last().expect("at least 2 segments")
    }

    /// Get all segments.
    pub fn segments(&self) -> &[String] {
        &self.segments
    }
}

impl FromStr for ProjectPath {
    type Err = ProjectPathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let segments: Vec<&str> = s.split('/').collect();

        if segments.len() < 2 {
            return Err(ProjectPathError::TooFewSegments(segments.len()));
        }
        if segments.len() > Self::MAX_DEPTH {
            return Err(ProjectPathError::TooManySegments(segments.len()));
        }

        let mut validated = Vec::with_capacity(segments.len());
        for (i, seg) in segments.iter().enumerate() {
            if seg.is_empty() {
                return Err(ProjectPathError::EmptySegment(i));
            }
            if seg.len() > Self::MAX_SEGMENT_LEN {
                return Err(ProjectPathError::SegmentTooLong(i, seg.len()));
            }
            if seg.starts_with('.') || seg.starts_with('-') {
                return Err(ProjectPathError::InvalidSegmentStart(i));
            }
            if !seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                return Err(ProjectPathError::InvalidSegmentChars(i));
            }
            validated.push((*seg).to_string());
        }

        Ok(ProjectPath {
            segments: validated,
        })
    }
}

impl std::fmt::Display for ProjectPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.segments.join("/"))
    }
}

/// Error parsing a project path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectPathError {
    TooFewSegments(usize),
    TooManySegments(usize),
    EmptySegment(usize),
    SegmentTooLong(usize, usize),
    InvalidSegmentStart(usize),
    InvalidSegmentChars(usize),
}

impl std::fmt::Display for ProjectPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooFewSegments(n) => {
                write!(
                    f,
                    "need at least 2 path segments (group/project), got {}",
                    n
                )
            }
            Self::TooManySegments(n) => write!(
                f,
                "too many path segments ({}, max {})",
                n,
                ProjectPath::MAX_DEPTH
            ),
            Self::EmptySegment(i) => write!(f, "path segment {} is empty", i),
            Self::SegmentTooLong(i, len) => write!(
                f,
                "path segment {} too long ({} chars, max {})",
                i,
                len,
                ProjectPath::MAX_SEGMENT_LEN
            ),
            Self::InvalidSegmentStart(i) => {
                write!(f, "path segment {} cannot start with '.' or '-'", i)
            }
            Self::InvalidSegmentChars(i) => {
                write!(f, "path segment {} contains invalid characters", i)
            }
        }
    }
}

impl std::error::Error for ProjectPathError {}

impl<'de> Deserialize<'de> for ProjectPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for ProjectPath {
    fn schema_name() -> Cow<'static, str> {
        "ProjectPath".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "GitLab project path (supports nested groups: 'group/subgroup/project')"
        })
    }
}

/// Convert a 2-level RepoName to a ProjectPath (for compatibility).
impl From<RepoName> for ProjectPath {
    fn from(repo: RepoName) -> Self {
        ProjectPath {
            segments: vec![repo.owner, repo.repo],
        }
    }
}

// ============================================================================
// BranchName
// ============================================================================

/// A validated git branch name.
///
/// Follows git's branch naming rules:
/// - Cannot start with '.' or '-'
/// - Cannot contain: space, ~, ^, :, ?, *, [, \, ..
/// - Cannot end with '.' or '.lock'
/// - Cannot be empty
/// - Max 255 chars
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchName(String);

impl BranchName {
    /// Maximum length for a branch name.
    pub const MAX_LEN: usize = 255;

    /// Get the inner string value.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this is an agent-managed branch (starts with "agent-").
    pub fn is_agent_branch(&self) -> bool {
        self.0.starts_with("agent-")
    }
}

impl FromStr for BranchName {
    type Err = BranchNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(BranchNameError::Empty);
        }
        if s.len() > Self::MAX_LEN {
            return Err(BranchNameError::TooLong(s.len()));
        }
        if s.starts_with('.') || s.starts_with('-') {
            return Err(BranchNameError::InvalidStart);
        }
        if s.ends_with('.') || s.ends_with(".lock") {
            return Err(BranchNameError::InvalidEnd);
        }
        if s.contains("..") {
            return Err(BranchNameError::ContainsDoubleDot);
        }

        // Check for invalid characters
        const INVALID_CHARS: &[char] = &[' ', '~', '^', ':', '?', '*', '[', '\\', '\x7f'];
        for c in s.chars() {
            if INVALID_CHARS.contains(&c) || c.is_control() {
                return Err(BranchNameError::InvalidChars);
            }
        }

        // Cannot contain @{
        if s.contains("@{") {
            return Err(BranchNameError::ContainsReflog);
        }

        Ok(BranchName(s.to_string()))
    }
}

impl std::fmt::Display for BranchName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error parsing a branch name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchNameError {
    Empty,
    TooLong(usize),
    InvalidStart,
    InvalidEnd,
    InvalidChars,
    ContainsDoubleDot,
    ContainsReflog,
}

impl std::fmt::Display for BranchNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "branch name cannot be empty"),
            Self::TooLong(len) => {
                write!(
                    f,
                    "branch name too long ({} chars, max {})",
                    len,
                    BranchName::MAX_LEN
                )
            }
            Self::InvalidStart => write!(f, "branch name cannot start with '.' or '-'"),
            Self::InvalidEnd => write!(f, "branch name cannot end with '.' or '.lock'"),
            Self::InvalidChars => write!(f, "branch name contains invalid characters"),
            Self::ContainsDoubleDot => write!(f, "branch name cannot contain '..'"),
            Self::ContainsReflog => write!(f, "branch name cannot contain '@{{'"),
        }
    }
}

impl std::error::Error for BranchNameError {}

impl<'de> Deserialize<'de> for BranchName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for BranchName {
    fn schema_name() -> Cow<'static, str> {
        "BranchName".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Git branch name",
            "maxLength": BranchName::MAX_LEN
        })
    }
}

// ============================================================================
// PullRequestNumber
// ============================================================================

/// A validated pull request / merge request / issue number.
///
/// Must be a positive integer (> 0). PR/MR/issue numbers start at 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PullRequestNumber(u64);

impl PullRequestNumber {
    /// Get the inner value.
    pub fn get(&self) -> u64 {
        self.0
    }
}

impl FromStr for PullRequestNumber {
    type Err = PullRequestNumberError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n: u64 = s
            .parse()
            .map_err(|_| PullRequestNumberError::InvalidFormat)?;
        if n == 0 {
            return Err(PullRequestNumberError::Zero);
        }
        Ok(PullRequestNumber(n))
    }
}

impl TryFrom<u64> for PullRequestNumber {
    type Error = PullRequestNumberError;

    fn try_from(n: u64) -> Result<Self, Self::Error> {
        if n == 0 {
            return Err(PullRequestNumberError::Zero);
        }
        Ok(PullRequestNumber(n))
    }
}

impl std::fmt::Display for PullRequestNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error parsing a pull request number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullRequestNumberError {
    Zero,
    InvalidFormat,
}

impl std::fmt::Display for PullRequestNumberError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Zero => write!(f, "PR/issue number must be greater than 0"),
            Self::InvalidFormat => write!(f, "invalid PR/issue number format"),
        }
    }
}

impl std::error::Error for PullRequestNumberError {}

impl<'de> Deserialize<'de> for PullRequestNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Accept both numbers and strings
        struct PrNumberVisitor;

        impl<'de> serde::de::Visitor<'de> for PrNumberVisitor {
            type Value = PullRequestNumber;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a positive integer or string")
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                PullRequestNumber::try_from(v).map_err(serde::de::Error::custom)
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v <= 0 {
                    return Err(serde::de::Error::custom(PullRequestNumberError::Zero));
                }
                PullRequestNumber::try_from(v as u64).map_err(serde::de::Error::custom)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse().map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(PrNumberVisitor)
    }
}

impl JsonSchema for PullRequestNumber {
    fn schema_name() -> Cow<'static, str> {
        "PullRequestNumber".into()
    }

    fn json_schema(_gen: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "integer",
            "description": "Pull request / merge request / issue number (must be > 0)",
            "minimum": 1
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
    fn test_commit_sha() {
        // Valid
        for input in [
            "abcdef1234567890abcdef1234567890abcdef12",
            "0000000000000000000000000000000000000000",
            "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
        ] {
            assert!(
                input.parse::<CommitSha>().is_ok(),
                "should be valid: {input}"
            );
        }

        // Invalid
        for (input, expected) in [
            ("", CommitShaError::InvalidLength(0)),
            ("abc123", CommitShaError::InvalidLength(6)),
            (
                "abcdef1234567890abcdef1234567890abcdef123",
                CommitShaError::InvalidLength(41),
            ),
            (
                "ghijkl1234567890abcdef1234567890abcdef12",
                CommitShaError::InvalidChars,
            ),
        ] {
            assert_eq!(input.parse::<CommitSha>(), Err(expected), "input: {input}");
        }
    }

    #[test]
    fn test_branch_description() {
        // Valid
        for input in ["fix-typo", "a", "CamelCase", "12345678901234567890"] {
            assert!(
                input.parse::<BranchDescription>().is_ok(),
                "should be valid: {input}"
            );
        }

        // Max length (200) should be valid
        let max_len_input = "a".repeat(BranchDescription::MAX_LEN);
        assert!(
            max_len_input.parse::<BranchDescription>().is_ok(),
            "200 chars should be valid"
        );

        // Over max length should fail
        let too_long = "a".repeat(BranchDescription::MAX_LEN + 1);
        assert_eq!(
            too_long.parse::<BranchDescription>(),
            Err(BranchDescriptionError::TooLong(201)),
            "201 chars should be too long"
        );

        // Invalid
        for (input, expected) in [
            ("", BranchDescriptionError::Empty),
            ("-starts", BranchDescriptionError::StartsWithHyphen),
            ("ends-", BranchDescriptionError::EndsWithHyphen),
            ("has space", BranchDescriptionError::InvalidChars),
            ("has/slash", BranchDescriptionError::InvalidChars),
        ] {
            assert_eq!(
                input.parse::<BranchDescription>(),
                Err(expected),
                "input: {input}"
            );
        }
    }

    #[test]
    fn test_repo_name() {
        // Valid (2-level only)
        for (input, owner, repo) in [
            ("owner/repo", "owner", "repo"),
            ("my-org/my-repo", "my-org", "my-repo"),
            ("user123/project_name", "user123", "project_name"),
            ("a/b", "a", "b"),
            ("org/repo.git", "org", "repo.git"),
        ] {
            let parsed: RepoName = input
                .parse()
                .unwrap_or_else(|_| panic!("should parse: {input}"));
            assert_eq!(parsed.owner(), owner);
            assert_eq!(parsed.repo(), repo);
            assert_eq!(parsed.to_string(), input);
        }

        // Invalid
        for (input, expected) in [
            ("noslash", RepoNameError::MissingSlash("noslash".into())),
            ("a/b/c", RepoNameError::TooManyLevels("a/b/c".into())),
            ("/repo", RepoNameError::EmptyOwner),
            ("owner/", RepoNameError::EmptyRepo),
            ("-bad/repo", RepoNameError::OwnerStartsWithHyphen),
            ("owner/.hidden", RepoNameError::RepoStartsWithDot),
            ("bad@char/repo", RepoNameError::InvalidOwnerChars),
            ("owner/bad@char", RepoNameError::InvalidRepoChars),
        ] {
            assert_eq!(input.parse::<RepoName>(), Err(expected), "input: {input}");
        }
    }

    #[test]
    fn test_project_path() {
        // Valid (supports nesting)
        for (input, expected_segments) in [
            ("group/project", vec!["group", "project"]),
            ("org/subgroup/project", vec!["org", "subgroup", "project"]),
            ("a/b/c/d", vec!["a", "b", "c", "d"]),
        ] {
            let parsed: ProjectPath = input
                .parse()
                .unwrap_or_else(|_| panic!("should parse: {input}"));
            let segments: Vec<&str> = parsed.segments().iter().map(|s| s.as_str()).collect();
            assert_eq!(segments, expected_segments);
            assert_eq!(parsed.to_string(), input);
        }

        // Check namespace/project accessors
        let path: ProjectPath = "org/sub/proj".parse().unwrap();
        assert_eq!(path.namespace(), "org/sub");
        assert_eq!(path.project(), "proj");

        // Invalid
        for (input, expected) in [
            ("single", ProjectPathError::TooFewSegments(1)),
            ("a//b", ProjectPathError::EmptySegment(1)),
            (".hidden/proj", ProjectPathError::InvalidSegmentStart(0)),
            ("group/-bad", ProjectPathError::InvalidSegmentStart(1)),
            ("group/bad@char", ProjectPathError::InvalidSegmentChars(1)),
        ] {
            assert_eq!(
                input.parse::<ProjectPath>(),
                Err(expected),
                "input: {input}"
            );
        }
    }

    #[test]
    fn test_repo_name_to_project_path() {
        let repo: RepoName = "owner/repo".parse().unwrap();
        let path: ProjectPath = repo.into();
        assert_eq!(path.to_string(), "owner/repo");
        assert_eq!(path.namespace(), "owner");
        assert_eq!(path.project(), "repo");
    }

    #[test]
    fn test_branch_name() {
        // Valid
        for input in [
            "main",
            "feature/my-feature",
            "fix/bug-123",
            "agent-42-fix-typo",
            "release/v1.0.0",
        ] {
            assert!(
                input.parse::<BranchName>().is_ok(),
                "should be valid: {input}"
            );
        }

        // Invalid
        for (input, expected) in [
            ("", BranchNameError::Empty),
            (".hidden", BranchNameError::InvalidStart),
            ("-bad", BranchNameError::InvalidStart),
            ("bad.", BranchNameError::InvalidEnd),
            ("bad.lock", BranchNameError::InvalidEnd),
            ("a..b", BranchNameError::ContainsDoubleDot),
            ("has space", BranchNameError::InvalidChars),
            ("has~tilde", BranchNameError::InvalidChars),
            ("has:colon", BranchNameError::InvalidChars),
            ("bad@{reflog", BranchNameError::ContainsReflog),
        ] {
            assert_eq!(input.parse::<BranchName>(), Err(expected), "input: {input}");
        }
    }

    #[test]
    fn test_branch_name_is_agent_branch() {
        assert!("agent-fix".parse::<BranchName>().unwrap().is_agent_branch());
        assert!("agent-42-fix"
            .parse::<BranchName>()
            .unwrap()
            .is_agent_branch());
        assert!(!"main".parse::<BranchName>().unwrap().is_agent_branch());
        assert!(!"feature/agent-like"
            .parse::<BranchName>()
            .unwrap()
            .is_agent_branch());
    }

    #[test]
    fn test_pull_request_number() {
        // Valid
        assert_eq!("1".parse::<PullRequestNumber>().unwrap().get(), 1);
        assert_eq!("42".parse::<PullRequestNumber>().unwrap().get(), 42);
        assert_eq!("999999".parse::<PullRequestNumber>().unwrap().get(), 999999);

        // From u64
        assert_eq!(PullRequestNumber::try_from(1u64).unwrap().get(), 1);
        assert_eq!(PullRequestNumber::try_from(100u64).unwrap().get(), 100);

        // Invalid
        assert_eq!(
            "0".parse::<PullRequestNumber>(),
            Err(PullRequestNumberError::Zero)
        );
        assert_eq!(
            PullRequestNumber::try_from(0u64),
            Err(PullRequestNumberError::Zero)
        );
        assert_eq!(
            "".parse::<PullRequestNumber>(),
            Err(PullRequestNumberError::InvalidFormat)
        );
        assert_eq!(
            "abc".parse::<PullRequestNumber>(),
            Err(PullRequestNumberError::InvalidFormat)
        );
        assert_eq!(
            "-1".parse::<PullRequestNumber>(),
            Err(PullRequestNumberError::InvalidFormat)
        );
    }

    #[test]
    fn test_pull_request_number_deserialize() {
        // From JSON number
        let pr: PullRequestNumber = serde_json::from_str("42").unwrap();
        assert_eq!(pr.get(), 42);

        // From JSON string
        let pr: PullRequestNumber = serde_json::from_str("\"123\"").unwrap();
        assert_eq!(pr.get(), 123);

        // Zero should fail
        assert!(serde_json::from_str::<PullRequestNumber>("0").is_err());
    }
}
