//! Scope-based access control for service-gator.
//!
//! This module provides resource scoping with fine-grained permissions.
//! Each service (gh, jira, gitlab, etc.) has its own scope configuration
//! with service-specific resource types and capabilities.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ============================================================================
// Helper functions for serde defaults
// ============================================================================

fn default_true() -> bool {
    true
}

// ============================================================================
// GitHub Permissions
// ============================================================================

/// Fine-grained permissions for a GitHub repository.
///
/// # Permission Model
///
/// There are two ways to grant access:
///
/// 1. **Repo-level** (`[gh.repos]` with `"owner/repo"`): Grants safe operations
///    that don't directly modify repository state. Defaults:
///    - `read = true` - View PRs, issues, code
///    - `create-draft = true` - Create draft PRs (require human to mark ready)
///    - `pending-review = true` - Manage pending reviews (require human to submit)
///    - `write = false` - No direct writes (merge, close, etc.)
///
/// 2. **Resource-level** (`[gh.prs]` with `"owner/repo#123"`): Grants write access
///    to a specific PR or issue. When you specify a resource, the agent can
///    work on it directly (defaults to read+write).
///
/// # Example
///
/// ```toml
/// [gh.repos]
/// "myorg/myrepo" = {}  # read + create-draft + pending-review
///
/// [gh.prs]
/// "myorg/myrepo#42" = {}  # read + write to PR #42
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GhRepoPermission {
    /// Can read the repository (view PRs, issues, code, etc.)
    /// Defaults to true.
    #[serde(default = "default_true")]
    pub read: bool,
    /// Can create draft PRs in this repo.
    /// Defaults to true - drafts require human review before merge.
    #[serde(default = "default_true")]
    pub create_draft: bool,
    /// Can create/update/delete pending PR reviews.
    /// Reviews must contain the marker token to be manageable.
    /// Defaults to true - pending reviews require human submission.
    #[serde(default = "default_true")]
    pub pending_review: bool,
    /// Full write access (merge, close, create non-draft, etc.)
    /// Defaults to false - direct writes require explicit opt-in.
    #[serde(default)]
    pub write: bool,
}

impl Default for GhRepoPermission {
    fn default() -> Self {
        Self {
            read: true,
            create_draft: true,
            pending_review: true,
            write: false,
        }
    }
}

impl GhRepoPermission {
    /// Read-only access (no draft creation, no pending reviews, no writes).
    pub fn read_only() -> Self {
        Self {
            read: true,
            create_draft: false,
            pending_review: false,
            write: false,
        }
    }

    /// Read + create draft PRs only.
    pub fn with_draft() -> Self {
        Self {
            read: true,
            create_draft: true,
            pending_review: false,
            write: false,
        }
    }

    /// Read + pending review management only.
    pub fn with_pending_review() -> Self {
        Self {
            read: true,
            create_draft: false,
            pending_review: true,
            write: false,
        }
    }

    /// Full write access (includes all other permissions).
    pub fn full_write() -> Self {
        Self {
            read: true,
            create_draft: true,
            pending_review: true,
            write: true,
        }
    }

    /// Check if reads are allowed.
    /// Any capability (create_draft, pending_review, write) implies read access.
    pub fn can_read(&self) -> bool {
        self.read || self.create_draft || self.pending_review || self.write
    }

    /// Check if creating draft PRs is allowed.
    pub fn can_create_draft(&self) -> bool {
        self.create_draft || self.write
    }

    /// Check if managing pending PR reviews is allowed.
    pub fn can_manage_pending_review(&self) -> bool {
        self.pending_review || self.write
    }

    /// Check if full writes are allowed.
    pub fn can_write(&self) -> bool {
        self.write
    }
}

/// Permissions for a specific PR or issue.
///
/// When a resource is specified (e.g., `"owner/repo#123"`), both read and write
/// default to true. The intent is that if you grant access to a specific PR,
/// you want the agent to be able to work on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GhResourcePermission {
    /// Can read this resource.
    /// Defaults to true when a resource is specified.
    #[serde(default = "default_true")]
    pub read: bool,
    /// Can write to this resource (comment, edit, etc.)
    /// Defaults to true when a resource is specified - if you grant access
    /// to a specific PR/issue, you typically want the agent to work on it.
    #[serde(default = "default_true")]
    pub write: bool,
}

impl GhResourcePermission {
    pub fn read_only() -> Self {
        Self {
            read: true,
            write: false,
        }
    }

    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
        }
    }
}

impl Default for GhResourcePermission {
    /// Default to read+write when a resource is specified.
    /// The intent is: if you explicitly grant access to PR #1234,
    /// you want the agent to be able to work on it.
    fn default() -> Self {
        Self::read_write()
    }
}

// ============================================================================
// GitHub Operation Types
// ============================================================================

/// Types of GitHub operations with their permission requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhOpType {
    /// Read operation (list, view, diff, etc.)
    Read,
    /// Create a draft PR
    CreateDraft,
    /// Manage pending PR reviews (create, update body, delete)
    ManagePendingReview,
    /// Write to a specific PR/issue (comment, edit)
    WriteResource,
    /// Full write operation (merge, close, create non-draft, etc.)
    Write,
}

// ============================================================================
// Pattern Matching
// ============================================================================

/// A scoped resource pattern with permission.
#[derive(Debug, Clone)]
pub struct PatternEntry<P> {
    /// Pattern to match (supports trailing `*` wildcard).
    pub pattern: String,
    /// Permission for matching resources.
    pub permission: P,
}

impl<P: Clone> PatternEntry<P> {
    pub fn new(pattern: impl Into<String>, permission: P) -> Self {
        Self {
            pattern: pattern.into(),
            permission,
        }
    }

    /// Check if a resource matches this pattern.
    pub fn matches(&self, resource: &str) -> bool {
        if let Some(prefix) = self.pattern.strip_suffix('*') {
            resource.starts_with(prefix)
        } else {
            self.pattern == resource
        }
    }

    /// Specificity score for pattern matching (higher = more specific).
    fn specificity(&self) -> usize {
        if self.pattern.ends_with('*') {
            self.pattern.len() - 1
        } else {
            self.pattern.len() + 1000 // exact match wins
        }
    }
}

/// A set of patterns with permissions.
#[derive(Debug, Clone, Default)]
pub struct PatternSet<P> {
    entries: Vec<PatternEntry<P>>,
}

impl<P: Clone + Default> PatternSet<P> {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a pattern with permission.
    pub fn add(&mut self, pattern: impl Into<String>, permission: P) {
        self.entries.push(PatternEntry::new(pattern, permission));
    }

    /// Get the permission for a resource.
    /// Returns the most specific matching permission.
    pub fn get(&self, resource: &str) -> Option<&P> {
        let mut best_match: Option<&PatternEntry<P>> = None;

        for entry in &self.entries {
            if entry.matches(resource) {
                match &best_match {
                    None => best_match = Some(entry),
                    Some(current) if entry.specificity() > current.specificity() => {
                        best_match = Some(entry)
                    }
                    _ => {}
                }
            }
        }

        best_match.map(|e| &e.permission)
    }
}

// ============================================================================
// GitHub Scope Configuration
// ============================================================================

/// GraphQL permission level.
///
/// Only read-only access is supported. Mutations are rejected for security reasons.
/// Accepts `"read"` or `true` for Read, `"none"` or `false` for None.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GraphQlPermission {
    /// No GraphQL access (default).
    #[default]
    None,
    /// Read-only GraphQL access (queries only, mutations are rejected).
    Read,
}

impl GraphQlPermission {
    pub fn can_read(&self) -> bool {
        matches!(self, GraphQlPermission::Read)
    }
}

impl Serialize for GraphQlPermission {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            GraphQlPermission::None => serializer.serialize_str("none"),
            GraphQlPermission::Read => serializer.serialize_str("read"),
        }
    }
}

impl<'de> Deserialize<'de> for GraphQlPermission {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor};

        struct GraphQlPermissionVisitor;

        impl<'de> Visitor<'de> for GraphQlPermissionVisitor {
            type Value = GraphQlPermission;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("\"read\", \"none\", true, or false")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(if value {
                    GraphQlPermission::Read
                } else {
                    GraphQlPermission::None
                })
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "read" => Ok(GraphQlPermission::Read),
                    "none" => Ok(GraphQlPermission::None),
                    _ => Err(de::Error::unknown_variant(value, &["read", "none"])),
                }
            }
        }

        deserializer.deserialize_any(GraphQlPermissionVisitor)
    }
}

/// GitHub-specific scope configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GithubScope {
    /// Repository permissions: "owner/repo" or "owner/*" → permission
    #[serde(default)]
    pub repos: HashMap<String, GhRepoPermission>,

    /// PR-specific permissions: "owner/repo#123" → permission
    /// These are typically set dynamically by the daemon.
    #[serde(default)]
    pub prs: HashMap<String, GhResourcePermission>,

    /// Issue-specific permissions: "owner/repo#123" → permission
    #[serde(default)]
    pub issues: HashMap<String, GhResourcePermission>,

    /// GraphQL API permission level.
    /// GraphQL queries can span multiple repos, so this is a global setting.
    #[serde(default)]
    pub graphql: GraphQlPermission,
}

impl GithubScope {
    /// Build a pattern set for repo matching.
    pub fn repo_patterns(&self) -> PatternSet<GhRepoPermission> {
        let mut set = PatternSet::new();
        for (pattern, perm) in &self.repos {
            set.add(pattern.clone(), perm.clone());
        }
        set
    }

    /// Build a pattern set for PR matching.
    pub fn pr_patterns(&self) -> PatternSet<GhResourcePermission> {
        let mut set = PatternSet::new();
        for (pattern, perm) in &self.prs {
            set.add(pattern.clone(), perm.clone());
        }
        set
    }

    /// Check if read access is allowed for a specific repository.
    pub fn is_read_allowed(&self, repo: &str) -> bool {
        let repo_patterns = self.repo_patterns();
        repo_patterns
            .get(repo)
            .map(|p| p.can_read())
            .unwrap_or(false)
    }

    /// Check if GraphQL read access is allowed.
    pub fn graphql_read_allowed(&self) -> bool {
        self.graphql.can_read()
    }

    /// Check if an operation is allowed.
    pub fn is_allowed(&self, repo: &str, op: GhOpType, resource_ref: Option<&str>) -> bool {
        let repo_patterns = self.repo_patterns();
        let repo_perm = repo_patterns.get(repo);

        match op {
            GhOpType::Read => repo_perm.map(|p| p.can_read()).unwrap_or(false),

            GhOpType::CreateDraft => repo_perm.map(|p| p.can_create_draft()).unwrap_or(false),

            GhOpType::ManagePendingReview => repo_perm
                .map(|p| p.can_manage_pending_review())
                .unwrap_or(false),

            GhOpType::WriteResource => {
                // Check if we have write permission on the specific resource
                if let Some(res_ref) = resource_ref {
                    let pr_patterns = self.pr_patterns();
                    if let Some(pr_perm) = pr_patterns.get(res_ref) {
                        return pr_perm.write;
                    }
                }
                // Fall back to repo-level full write
                repo_perm.map(|p| p.can_write()).unwrap_or(false)
            }

            GhOpType::Write => repo_perm.map(|p| p.can_write()).unwrap_or(false),
        }
    }
}

// ============================================================================
// GitLab Permissions
// ============================================================================

/// Fine-grained permissions for a GitLab project.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GlProjectPermission {
    /// Can read the project (view MRs, issues, code, etc.)
    #[serde(default)]
    pub read: bool,
    /// Can create draft MRs in this project.
    #[serde(default)]
    pub create_draft: bool,
    /// Can approve MRs in this project.
    #[serde(default)]
    pub approve: bool,
    /// Full write access (merge, close, create non-draft, etc.)
    /// Implies all other permissions.
    #[serde(default)]
    pub write: bool,
}

impl GlProjectPermission {
    pub fn read_only() -> Self {
        Self {
            read: true,
            ..Default::default()
        }
    }

    pub fn with_draft() -> Self {
        Self {
            read: true,
            create_draft: true,
            ..Default::default()
        }
    }

    pub fn with_approve() -> Self {
        Self {
            read: true,
            approve: true,
            ..Default::default()
        }
    }

    pub fn full_write() -> Self {
        Self {
            read: true,
            create_draft: true,
            approve: true,
            write: true,
        }
    }

    /// Check if reads are allowed.
    /// Any capability (create_draft, approve, write) implies read access.
    pub fn can_read(&self) -> bool {
        self.read || self.create_draft || self.approve || self.write
    }

    /// Check if creating draft PRs is allowed.
    pub fn can_create_draft(&self) -> bool {
        self.create_draft || self.write
    }

    /// Check if approving MRs is allowed.
    pub fn can_approve(&self) -> bool {
        self.approve || self.write
    }

    /// Check if full writes are allowed.
    pub fn can_write(&self) -> bool {
        self.write
    }
}

/// Permissions for a specific MR or issue (same structure as GitHub).
pub type GlResourcePermission = GhResourcePermission;

// ============================================================================
// GitLab Operation Types
// ============================================================================

/// Types of GitLab operations with their permission requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlOpType {
    /// Read operation (list, view, diff, etc.)
    Read,
    /// Create a draft MR
    CreateDraft,
    /// Approve an MR
    Approve,
    /// Write to a specific MR/issue (comment, edit)
    WriteResource,
    /// Full write operation (merge, close, create non-draft, etc.)
    Write,
}

// ============================================================================
// GitLab Scope Configuration
// ============================================================================

/// GitLab-specific scope configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GitLabScope {
    /// Project permissions: "group/project" or "group/*" → permission
    #[serde(default)]
    pub projects: HashMap<String, GlProjectPermission>,

    /// MR-specific permissions: "group/project!123" → permission
    /// These are typically set dynamically by the daemon.
    #[serde(default)]
    pub mrs: HashMap<String, GlResourcePermission>,

    /// Issue-specific permissions: "group/project#123" → permission
    #[serde(default)]
    pub issues: HashMap<String, GlResourcePermission>,

    /// GraphQL API permission level.
    /// GraphQL queries can span multiple projects, so this is a global setting.
    /// NOTE: GitLab GraphQL is currently not supported (glab api graphql requires
    /// query arguments that we can't easily validate as read-only). This field
    /// exists for future expansion.
    #[serde(default)]
    pub graphql: GraphQlPermission,

    /// Host for self-hosted GitLab instances. None means gitlab.com.
    #[serde(default)]
    pub host: Option<String>,
}

impl GitLabScope {
    /// Build a pattern set for project matching.
    pub fn project_patterns(&self) -> PatternSet<GlProjectPermission> {
        let mut set = PatternSet::new();
        for (pattern, perm) in &self.projects {
            set.add(pattern.clone(), perm.clone());
        }
        set
    }

    /// Build a pattern set for MR matching.
    pub fn mr_patterns(&self) -> PatternSet<GlResourcePermission> {
        let mut set = PatternSet::new();
        for (pattern, perm) in &self.mrs {
            set.add(pattern.clone(), perm.clone());
        }
        set
    }

    /// Build a pattern set for issue matching.
    pub fn issue_patterns(&self) -> PatternSet<GlResourcePermission> {
        let mut set = PatternSet::new();
        for (pattern, perm) in &self.issues {
            set.add(pattern.clone(), perm.clone());
        }
        set
    }

    /// Check if read access is allowed for a specific project.
    pub fn is_read_allowed(&self, project: &str) -> bool {
        let project_patterns = self.project_patterns();
        project_patterns
            .get(project)
            .map(|p| p.can_read())
            .unwrap_or(false)
    }

    /// Check if GraphQL read access is allowed.
    pub fn graphql_read_allowed(&self) -> bool {
        self.graphql.can_read()
    }

    /// Check if an operation is allowed.
    pub fn is_allowed(&self, project: &str, op: GlOpType, resource_ref: Option<&str>) -> bool {
        let project_patterns = self.project_patterns();
        let project_perm = project_patterns.get(project);

        match op {
            GlOpType::Read => project_perm.map(|p| p.can_read()).unwrap_or(false),

            GlOpType::CreateDraft => project_perm.map(|p| p.can_create_draft()).unwrap_or(false),

            GlOpType::Approve => project_perm.map(|p| p.can_approve()).unwrap_or(false),

            GlOpType::WriteResource => {
                // Check if we have write permission on the specific resource
                if let Some(res_ref) = resource_ref {
                    // Check MRs first (format: group/project!123)
                    let mr_patterns = self.mr_patterns();
                    if let Some(mr_perm) = mr_patterns.get(res_ref) {
                        return mr_perm.write;
                    }
                    // Then check issues (format: group/project#123)
                    let issue_patterns = self.issue_patterns();
                    if let Some(issue_perm) = issue_patterns.get(res_ref) {
                        return issue_perm.write;
                    }
                }
                // Fall back to project-level full write
                project_perm.map(|p| p.can_write()).unwrap_or(false)
            }

            GlOpType::Write => project_perm.map(|p| p.can_write()).unwrap_or(false),
        }
    }
}

// ============================================================================
// Forgejo Permissions
// ============================================================================

/// Fine-grained permissions for a Forgejo repository.
///
/// Forgejo is a fork of Gitea with identical REST APIs.
/// Unlike GitHub/GitLab, Forgejo is always self-hosted (host is required).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ForgejoRepoPermission {
    /// Can read the repository (view PRs, issues, code, etc.)
    #[serde(default)]
    pub read: bool,
    /// Can create draft PRs in this repo.
    #[serde(default)]
    pub create_draft: bool,
    /// Can create/update/delete pending PR reviews.
    /// Reviews must contain the marker token to be manageable.
    #[serde(default)]
    pub pending_review: bool,
    /// Full write access (merge, close, create non-draft, etc.)
    /// Implies all other permissions.
    #[serde(default)]
    pub write: bool,
}

impl ForgejoRepoPermission {
    pub fn read_only() -> Self {
        Self {
            read: true,
            ..Default::default()
        }
    }

    pub fn with_draft() -> Self {
        Self {
            read: true,
            create_draft: true,
            ..Default::default()
        }
    }

    pub fn with_pending_review() -> Self {
        Self {
            read: true,
            pending_review: true,
            ..Default::default()
        }
    }

    pub fn full_write() -> Self {
        Self {
            read: true,
            create_draft: true,
            pending_review: true,
            write: true,
        }
    }

    /// Check if reads are allowed.
    pub fn can_read(&self) -> bool {
        self.read || self.write
    }

    /// Check if creating draft PRs is allowed.
    pub fn can_create_draft(&self) -> bool {
        self.create_draft || self.write
    }

    /// Check if managing pending PR reviews is allowed.
    pub fn can_manage_pending_review(&self) -> bool {
        self.pending_review || self.write
    }

    /// Check if full writes are allowed.
    pub fn can_write(&self) -> bool {
        self.write
    }
}

/// Permissions for a specific PR or issue (same structure as GitHub).
pub type ForgejoResourcePermission = GhResourcePermission;

// ============================================================================
// Forgejo Operation Types
// ============================================================================

/// Types of Forgejo operations with their permission requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgejoOpType {
    /// Read operation (list, view, diff, etc.)
    Read,
    /// Create a draft PR
    CreateDraft,
    /// Manage pending PR reviews (create, update body, delete)
    ManagePendingReview,
    /// Write to a specific PR/issue (comment, edit)
    WriteResource,
    /// Full write operation (merge, close, create non-draft, etc.)
    Write,
}

// ============================================================================
// Forgejo Scope Configuration
// ============================================================================

/// Forgejo-specific scope configuration.
///
/// Forgejo (and Gitea) is always self-hosted, so host is required.
/// Multiple hosts can be configured via a Vec<ForgejoScope>.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ForgejoScope {
    /// Host URL (REQUIRED - Forgejo is always self-hosted).
    /// e.g., "codeberg.org", "git.example.com"
    pub host: String,

    /// API token for authentication (optional for public repos).
    /// Can also be set via environment variable FORGEJO_TOKEN or GITEA_TOKEN.
    #[serde(default)]
    pub token: Option<String>,

    /// Repository permissions: "owner/repo" or "owner/*" → permission
    #[serde(default)]
    pub repos: HashMap<String, ForgejoRepoPermission>,

    /// PR-specific permissions: "owner/repo#123" → permission
    /// These are typically set dynamically by the daemon.
    #[serde(default)]
    pub prs: HashMap<String, ForgejoResourcePermission>,

    /// Issue-specific permissions: "owner/repo#123" → permission
    #[serde(default)]
    pub issues: HashMap<String, ForgejoResourcePermission>,
}

impl ForgejoScope {
    /// Build a pattern set for repo matching.
    pub fn repo_patterns(&self) -> PatternSet<ForgejoRepoPermission> {
        let mut set = PatternSet::new();
        for (pattern, perm) in &self.repos {
            set.add(pattern.clone(), perm.clone());
        }
        set
    }

    /// Build a pattern set for PR matching.
    pub fn pr_patterns(&self) -> PatternSet<ForgejoResourcePermission> {
        let mut set = PatternSet::new();
        for (pattern, perm) in &self.prs {
            set.add(pattern.clone(), perm.clone());
        }
        set
    }

    /// Build a pattern set for issue matching.
    pub fn issue_patterns(&self) -> PatternSet<ForgejoResourcePermission> {
        let mut set = PatternSet::new();
        for (pattern, perm) in &self.issues {
            set.add(pattern.clone(), perm.clone());
        }
        set
    }

    /// Check if read access is allowed for a specific repository.
    pub fn is_read_allowed(&self, repo: &str) -> bool {
        let repo_patterns = self.repo_patterns();
        repo_patterns
            .get(repo)
            .map(|p| p.can_read())
            .unwrap_or(false)
    }

    /// Check if an operation is allowed.
    pub fn is_allowed(&self, repo: &str, op: ForgejoOpType, resource_ref: Option<&str>) -> bool {
        let repo_patterns = self.repo_patterns();
        let repo_perm = repo_patterns.get(repo);

        match op {
            ForgejoOpType::Read => repo_perm.map(|p| p.can_read()).unwrap_or(false),

            ForgejoOpType::CreateDraft => repo_perm.map(|p| p.can_create_draft()).unwrap_or(false),

            ForgejoOpType::ManagePendingReview => repo_perm
                .map(|p| p.can_manage_pending_review())
                .unwrap_or(false),

            ForgejoOpType::WriteResource => {
                // Check if we have write permission on the specific resource
                if let Some(res_ref) = resource_ref {
                    // Check PRs first (format: owner/repo#123)
                    let pr_patterns = self.pr_patterns();
                    if let Some(pr_perm) = pr_patterns.get(res_ref) {
                        return pr_perm.write;
                    }
                    // Then check issues (format: owner/repo#123)
                    let issue_patterns = self.issue_patterns();
                    if let Some(issue_perm) = issue_patterns.get(res_ref) {
                        return issue_perm.write;
                    }
                }
                // Fall back to repo-level full write
                repo_perm.map(|p| p.can_write()).unwrap_or(false)
            }

            ForgejoOpType::Write => repo_perm.map(|p| p.can_write()).unwrap_or(false),
        }
    }
}

// ============================================================================
// JIRA Scope Configuration
// ============================================================================

/// JIRA project permissions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct JiraProjectPermission {
    /// Can read the project (list issues, view, etc.)
    #[serde(default)]
    pub read: bool,
    /// Can create issues in this project.
    #[serde(default)]
    pub create: bool,
    /// Full write access.
    #[serde(default)]
    pub write: bool,
}

impl JiraProjectPermission {
    pub fn read_only() -> Self {
        Self {
            read: true,
            ..Default::default()
        }
    }

    pub fn can_read(&self) -> bool {
        self.read || self.write
    }

    pub fn can_create(&self) -> bool {
        self.create || self.write
    }

    pub fn can_write(&self) -> bool {
        self.write
    }
}

/// JIRA issue permissions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct JiraIssuePermission {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
}

/// JIRA-specific scope configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct JiraScope {
    /// JIRA server URL (e.g., "https://jira.example.com" or "https://company.atlassian.net")
    #[serde(default)]
    pub host: Option<String>,

    /// Username/email for authentication.
    /// For JIRA Cloud, this is typically your Atlassian account email.
    /// Can also be set via JIRA_USERNAME environment variable.
    #[serde(default)]
    pub username: Option<String>,

    /// API token for authentication.
    /// For JIRA Cloud, generate at: https://id.atlassian.com/manage-profile/security/api-tokens
    /// Can also be set via JIRA_API_TOKEN environment variable.
    #[serde(default)]
    pub token: Option<String>,

    /// Project permissions: "PROJ" → permission
    #[serde(default)]
    pub projects: HashMap<String, JiraProjectPermission>,

    /// Issue-specific permissions: "PROJ-123" → permission
    #[serde(default)]
    pub issues: HashMap<String, JiraIssuePermission>,
}

// ============================================================================
// Top-level Config
// ============================================================================

/// Top-level scope configuration for all services.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ScopeConfig {
    #[serde(default)]
    pub gh: GithubScope,
    #[serde(default)]
    pub gitlab: GitLabScope,
    /// Forgejo instances (Vec because multiple hosts can be configured).
    #[serde(default)]
    pub forgejo: Vec<ForgejoScope>,
    #[serde(default)]
    pub jira: JiraScope,
}

// ============================================================================
// Legacy OpType for simple read/write classification
// ============================================================================

/// Simple operation type for basic read/write classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpType {
    Read,
    Write,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gh_repo_permission_defaults() {
        // Default is read + create-draft + pending-review, but NOT write
        let p = GhRepoPermission::default();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(p.can_manage_pending_review());
        assert!(!p.can_write());
    }

    #[test]
    fn test_gh_repo_permission_read_only() {
        let p = GhRepoPermission::read_only();
        assert!(p.can_read());
        assert!(!p.can_create_draft());
        assert!(!p.can_manage_pending_review());
        assert!(!p.can_write());
    }

    #[test]
    fn test_gh_repo_permission_with_draft() {
        let p = GhRepoPermission::with_draft();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(!p.can_manage_pending_review());
        assert!(!p.can_write());
    }

    #[test]
    fn test_gh_repo_permission_full_write() {
        let p = GhRepoPermission::full_write();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(p.can_manage_pending_review());
        assert!(p.can_write());
    }

    #[test]
    fn test_pattern_matching() {
        let entry = PatternEntry::new("owner/repo", GhRepoPermission::read_only());
        assert!(entry.matches("owner/repo"));
        assert!(!entry.matches("owner/other"));

        let wildcard = PatternEntry::new("owner/*", GhRepoPermission::read_only());
        assert!(wildcard.matches("owner/repo"));
        assert!(wildcard.matches("owner/other"));
        assert!(!wildcard.matches("other/repo"));
    }

    #[test]
    fn test_pattern_set_specificity() {
        let mut set = PatternSet::new();
        set.add("owner/*", GhRepoPermission::read_only());
        set.add("owner/special", GhRepoPermission::with_draft());

        // Exact match wins
        let perm = set.get("owner/special").unwrap();
        assert!(perm.can_create_draft());

        // Wildcard for others
        let perm = set.get("owner/other").unwrap();
        assert!(!perm.can_create_draft());
    }

    #[test]
    fn test_github_scope_is_allowed() {
        let scope = GithubScope {
            repos: [
                ("owner/*".into(), GhRepoPermission::read_only()),
                ("owner/writable".into(), GhRepoPermission::with_draft()),
            ]
            .into(),
            prs: [(
                "owner/writable#42".into(),
                GhResourcePermission::read_write(),
            )]
            .into(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Read allowed on any owner/* repo
        assert!(scope.is_allowed("owner/random", GhOpType::Read, None));

        // Create draft only on owner/writable
        assert!(!scope.is_allowed("owner/random", GhOpType::CreateDraft, None));
        assert!(scope.is_allowed("owner/writable", GhOpType::CreateDraft, None));

        // Full write not allowed (only create_draft)
        assert!(!scope.is_allowed("owner/writable", GhOpType::Write, None));

        // But can write to specific PR
        assert!(scope.is_allowed(
            "owner/writable",
            GhOpType::WriteResource,
            Some("owner/writable#42")
        ));
        assert!(!scope.is_allowed(
            "owner/writable",
            GhOpType::WriteResource,
            Some("owner/writable#99")
        ));
    }

    #[test]
    fn test_config_deserialization() {
        let toml = r#"
            [gh.repos]
            "owner/repo" = { read = true, create-draft = true }
            "owner/*" = { read = true }

            [gh.prs]
            "owner/repo#42" = { read = true, write = true }

            [jira.projects]
            "MYPROJ" = { read = true, create = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();

        assert!(config.gh.repos.get("owner/repo").unwrap().create_draft);
        assert!(config.gh.prs.get("owner/repo#42").unwrap().write);
        assert!(config.jira.projects.get("MYPROJ").unwrap().create);
    }

    #[test]
    fn test_graphql_permission() {
        assert!(!GraphQlPermission::None.can_read());
        assert!(GraphQlPermission::Read.can_read());
    }

    #[test]
    fn test_github_scope_is_read_allowed() {
        let scope = GithubScope {
            repos: [
                ("owner/*".into(), GhRepoPermission::read_only()),
                ("other/repo".into(), GhRepoPermission::read_only()),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        assert!(scope.is_read_allowed("owner/repo"));
        assert!(scope.is_read_allowed("owner/other"));
        assert!(scope.is_read_allowed("other/repo"));
        assert!(!scope.is_read_allowed("unknown/repo"));
    }

    #[test]
    fn test_github_scope_graphql_permissions() {
        let scope_none = GithubScope {
            repos: HashMap::new(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };
        assert!(!scope_none.graphql_read_allowed());

        let scope_read = GithubScope {
            repos: HashMap::new(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::Read,
        };
        assert!(scope_read.graphql_read_allowed());
    }

    #[test]
    fn test_config_deserialization_with_graphql() {
        let toml = r#"
            [gh]
            graphql = "read"

            [gh.repos]
            "owner/repo" = { read = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();
        assert!(config.gh.graphql_read_allowed());
    }

    #[test]
    fn test_config_deserialization_graphql_true() {
        // graphql = true should enable read access
        let toml = r#"
            [gh]
            graphql = true
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();
        assert!(config.gh.graphql_read_allowed());
    }

    #[test]
    fn test_config_deserialization_graphql_false() {
        // graphql = false should disable access
        let toml = r#"
            [gh]
            graphql = false
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();
        assert!(!config.gh.graphql_read_allowed());
    }

    #[test]
    fn test_config_deserialization_graphql_none() {
        let toml = r#"
            [gh]
            graphql = "none"
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();
        assert!(!config.gh.graphql_read_allowed());
    }

    #[test]
    fn test_config_deserialization_graphql_default() {
        // When graphql is not specified, it defaults to None
        let toml = r#"
            [gh.repos]
            "owner/repo" = { read = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();
        assert!(!config.gh.graphql_read_allowed());
    }

    // ========================================================================
    // Tests for pending-review permission
    // ========================================================================

    #[test]
    fn test_gh_repo_permission_pending_review() {
        let p = GhRepoPermission::with_pending_review();
        assert!(p.can_read());
        assert!(!p.can_create_draft());
        assert!(p.can_manage_pending_review());
        assert!(!p.can_write());
    }

    #[test]
    fn test_gh_repo_permission_full_write_includes_pending_review() {
        let p = GhRepoPermission::full_write();
        assert!(p.can_manage_pending_review());
    }

    #[test]
    fn test_github_scope_is_allowed_pending_review() {
        let scope = GithubScope {
            repos: [
                ("owner/readonly".into(), GhRepoPermission::read_only()),
                (
                    "owner/review".into(),
                    GhRepoPermission::with_pending_review(),
                ),
                ("owner/full".into(), GhRepoPermission::full_write()),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Read-only repo cannot manage pending reviews
        assert!(!scope.is_allowed("owner/readonly", GhOpType::ManagePendingReview, None));

        // Review repo can manage pending reviews
        assert!(scope.is_allowed("owner/review", GhOpType::ManagePendingReview, None));

        // Full write can manage pending reviews
        assert!(scope.is_allowed("owner/full", GhOpType::ManagePendingReview, None));

        // Unknown repo cannot manage pending reviews
        assert!(!scope.is_allowed("owner/unknown", GhOpType::ManagePendingReview, None));
    }

    #[test]
    fn test_config_deserialization_pending_review() {
        let toml = r#"
            [gh.repos]
            "owner/repo" = { read = true, pending-review = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();
        let perm = config.gh.repos.get("owner/repo").unwrap();
        assert!(perm.can_read());
        assert!(perm.can_manage_pending_review());
        assert!(!perm.can_write());
    }

    // ========================================================================
    // GitLab scope tests
    // ========================================================================

    #[test]
    fn test_gl_project_permission_defaults() {
        let p = GlProjectPermission::default();
        assert!(!p.can_read());
        assert!(!p.can_create_draft());
        assert!(!p.can_approve());
        assert!(!p.can_write());
    }

    #[test]
    fn test_gl_project_permission_read_only() {
        let p = GlProjectPermission::read_only();
        assert!(p.can_read());
        assert!(!p.can_create_draft());
        assert!(!p.can_approve());
        assert!(!p.can_write());
    }

    #[test]
    fn test_gl_project_permission_with_draft() {
        let p = GlProjectPermission::with_draft();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(!p.can_approve());
        assert!(!p.can_write());
    }

    #[test]
    fn test_gl_project_permission_with_approve() {
        let p = GlProjectPermission::with_approve();
        assert!(p.can_read());
        assert!(!p.can_create_draft());
        assert!(p.can_approve());
        assert!(!p.can_write());
    }

    #[test]
    fn test_gl_project_permission_full_write() {
        let p = GlProjectPermission::full_write();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(p.can_approve());
        assert!(p.can_write());
    }

    #[test]
    fn test_gitlab_scope_is_allowed() {
        let scope = GitLabScope {
            projects: [
                ("group/*".into(), GlProjectPermission::read_only()),
                ("group/writable".into(), GlProjectPermission::with_draft()),
            ]
            .into(),
            mrs: [(
                "group/writable!42".into(),
                GlResourcePermission::read_write(),
            )]
            .into(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
            host: None,
        };

        // Read allowed on any group/* project
        assert!(scope.is_allowed("group/random", GlOpType::Read, None));

        // Create draft only on group/writable
        assert!(!scope.is_allowed("group/random", GlOpType::CreateDraft, None));
        assert!(scope.is_allowed("group/writable", GlOpType::CreateDraft, None));

        // Full write not allowed (only create_draft)
        assert!(!scope.is_allowed("group/writable", GlOpType::Write, None));

        // But can write to specific MR
        assert!(scope.is_allowed(
            "group/writable",
            GlOpType::WriteResource,
            Some("group/writable!42")
        ));
        assert!(!scope.is_allowed(
            "group/writable",
            GlOpType::WriteResource,
            Some("group/writable!99")
        ));
    }

    #[test]
    fn test_gitlab_scope_is_read_allowed() {
        let scope = GitLabScope {
            projects: [
                ("group/*".into(), GlProjectPermission::read_only()),
                ("other/project".into(), GlProjectPermission::read_only()),
            ]
            .into(),
            mrs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
            host: None,
        };

        assert!(scope.is_read_allowed("group/project"));
        assert!(scope.is_read_allowed("group/other"));
        assert!(scope.is_read_allowed("other/project"));
        assert!(!scope.is_read_allowed("unknown/project"));
    }

    #[test]
    fn test_gitlab_scope_approve_permission() {
        let scope = GitLabScope {
            projects: [
                ("group/readonly".into(), GlProjectPermission::read_only()),
                ("group/approver".into(), GlProjectPermission::with_approve()),
                ("group/full".into(), GlProjectPermission::full_write()),
            ]
            .into(),
            mrs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
            host: None,
        };

        // Read-only cannot approve
        assert!(!scope.is_allowed("group/readonly", GlOpType::Approve, None));

        // Approver can approve
        assert!(scope.is_allowed("group/approver", GlOpType::Approve, None));

        // Full write can approve
        assert!(scope.is_allowed("group/full", GlOpType::Approve, None));
    }

    #[test]
    fn test_gitlab_config_deserialization() {
        let toml = r#"
            [gitlab]
            host = "gitlab.example.com"

            [gitlab.projects]
            "group/project" = { read = true, create-draft = true }
            "group/*" = { read = true }

            [gitlab.mrs]
            "group/project!42" = { read = true, write = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();

        assert_eq!(config.gitlab.host.as_deref(), Some("gitlab.example.com"));
        assert!(
            config
                .gitlab
                .projects
                .get("group/project")
                .unwrap()
                .create_draft
        );
        assert!(config.gitlab.mrs.get("group/project!42").unwrap().write);
    }

    #[test]
    fn test_gitlab_config_deserialization_default_host() {
        let toml = r#"
            [gitlab.projects]
            "group/project" = { read = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();
        assert!(config.gitlab.host.is_none());
    }

    #[test]
    fn test_gitlab_scope_graphql_permissions() {
        let scope_none = GitLabScope {
            projects: HashMap::new(),
            mrs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
            host: None,
        };
        assert!(!scope_none.graphql_read_allowed());

        let scope_read = GitLabScope {
            projects: HashMap::new(),
            mrs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::Read,
            host: None,
        };
        assert!(scope_read.graphql_read_allowed());
    }

    #[test]
    fn test_gitlab_scope_issue_write_resource() {
        let scope = GitLabScope {
            projects: [("group/project".into(), GlProjectPermission::read_only())].into(),
            mrs: HashMap::new(),
            issues: [(
                "group/project#123".into(),
                GlResourcePermission::read_write(),
            )]
            .into(),
            graphql: GraphQlPermission::None,
            host: None,
        };

        // Can write to the specific issue
        assert!(scope.is_allowed(
            "group/project",
            GlOpType::WriteResource,
            Some("group/project#123")
        ));

        // Cannot write to other issues
        assert!(!scope.is_allowed(
            "group/project",
            GlOpType::WriteResource,
            Some("group/project#456")
        ));
    }

    // ========================================================================
    // Forgejo scope tests
    // ========================================================================

    #[test]
    fn test_forgejo_repo_permission_defaults() {
        let p = ForgejoRepoPermission::default();
        assert!(!p.can_read());
        assert!(!p.can_create_draft());
        assert!(!p.can_manage_pending_review());
        assert!(!p.can_write());
    }

    #[test]
    fn test_forgejo_repo_permission_read_only() {
        let p = ForgejoRepoPermission::read_only();
        assert!(p.can_read());
        assert!(!p.can_create_draft());
        assert!(!p.can_manage_pending_review());
        assert!(!p.can_write());
    }

    #[test]
    fn test_forgejo_repo_permission_with_draft() {
        let p = ForgejoRepoPermission::with_draft();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(!p.can_manage_pending_review());
        assert!(!p.can_write());
    }

    #[test]
    fn test_forgejo_repo_permission_with_pending_review() {
        let p = ForgejoRepoPermission::with_pending_review();
        assert!(p.can_read());
        assert!(!p.can_create_draft());
        assert!(p.can_manage_pending_review());
        assert!(!p.can_write());
    }

    #[test]
    fn test_forgejo_repo_permission_full_write() {
        let p = ForgejoRepoPermission::full_write();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(p.can_manage_pending_review());
        assert!(p.can_write());
    }

    #[test]
    fn test_forgejo_scope_is_allowed() {
        let scope = ForgejoScope {
            host: "codeberg.org".into(),
            token: None,
            repos: [
                ("owner/*".into(), ForgejoRepoPermission::read_only()),
                ("owner/writable".into(), ForgejoRepoPermission::with_draft()),
            ]
            .into(),
            prs: [(
                "owner/writable#42".into(),
                ForgejoResourcePermission::read_write(),
            )]
            .into(),
            issues: HashMap::new(),
        };

        // Read allowed on any owner/* repo
        assert!(scope.is_allowed("owner/random", ForgejoOpType::Read, None));

        // Create draft only on owner/writable
        assert!(!scope.is_allowed("owner/random", ForgejoOpType::CreateDraft, None));
        assert!(scope.is_allowed("owner/writable", ForgejoOpType::CreateDraft, None));

        // Full write not allowed (only create_draft)
        assert!(!scope.is_allowed("owner/writable", ForgejoOpType::Write, None));

        // But can write to specific PR
        assert!(scope.is_allowed(
            "owner/writable",
            ForgejoOpType::WriteResource,
            Some("owner/writable#42")
        ));
        assert!(!scope.is_allowed(
            "owner/writable",
            ForgejoOpType::WriteResource,
            Some("owner/writable#99")
        ));
    }

    #[test]
    fn test_forgejo_scope_is_read_allowed() {
        let scope = ForgejoScope {
            host: "codeberg.org".into(),
            token: None,
            repos: [
                ("owner/*".into(), ForgejoRepoPermission::read_only()),
                ("other/repo".into(), ForgejoRepoPermission::read_only()),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
        };

        assert!(scope.is_read_allowed("owner/repo"));
        assert!(scope.is_read_allowed("owner/other"));
        assert!(scope.is_read_allowed("other/repo"));
        assert!(!scope.is_read_allowed("unknown/repo"));
    }

    #[test]
    fn test_forgejo_scope_pending_review_permission() {
        let scope = ForgejoScope {
            host: "codeberg.org".into(),
            token: None,
            repos: [
                ("owner/readonly".into(), ForgejoRepoPermission::read_only()),
                (
                    "owner/review".into(),
                    ForgejoRepoPermission::with_pending_review(),
                ),
                ("owner/full".into(), ForgejoRepoPermission::full_write()),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
        };

        // Read-only cannot manage pending reviews
        assert!(!scope.is_allowed("owner/readonly", ForgejoOpType::ManagePendingReview, None));

        // Review permission can manage pending reviews
        assert!(scope.is_allowed("owner/review", ForgejoOpType::ManagePendingReview, None));

        // Full write can manage pending reviews
        assert!(scope.is_allowed("owner/full", ForgejoOpType::ManagePendingReview, None));
    }

    #[test]
    fn test_forgejo_scope_issue_write_resource() {
        let scope = ForgejoScope {
            host: "codeberg.org".into(),
            token: None,
            repos: [("owner/repo".into(), ForgejoRepoPermission::read_only())].into(),
            prs: HashMap::new(),
            issues: [(
                "owner/repo#123".into(),
                ForgejoResourcePermission::read_write(),
            )]
            .into(),
        };

        // Can write to the specific issue
        assert!(scope.is_allowed(
            "owner/repo",
            ForgejoOpType::WriteResource,
            Some("owner/repo#123")
        ));

        // Cannot write to other issues
        assert!(!scope.is_allowed(
            "owner/repo",
            ForgejoOpType::WriteResource,
            Some("owner/repo#456")
        ));
    }

    #[test]
    fn test_forgejo_config_deserialization() {
        let toml = r#"
            [[forgejo]]
            host = "codeberg.org"

            [forgejo.repos]
            "owner/repo" = { read = true, create-draft = true }
            "owner/*" = { read = true }

            [forgejo.prs]
            "owner/repo#42" = { read = true, write = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();

        assert_eq!(config.forgejo.len(), 1);
        assert_eq!(config.forgejo[0].host, "codeberg.org");
        assert!(
            config.forgejo[0]
                .repos
                .get("owner/repo")
                .unwrap()
                .create_draft
        );
        assert!(config.forgejo[0].prs.get("owner/repo#42").unwrap().write);
    }

    #[test]
    fn test_forgejo_config_multiple_hosts() {
        let toml = r#"
            [[forgejo]]
            host = "codeberg.org"

            [forgejo.repos]
            "owner/repo" = { read = true }

            [[forgejo]]
            host = "git.example.com"

            [forgejo.repos]
            "myorg/myrepo" = { read = true, write = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();

        assert_eq!(config.forgejo.len(), 2);
        assert_eq!(config.forgejo[0].host, "codeberg.org");
        assert_eq!(config.forgejo[1].host, "git.example.com");
        assert!(config.forgejo[0].repos.get("owner/repo").unwrap().read);
        assert!(config.forgejo[1].repos.get("myorg/myrepo").unwrap().write);
    }

    #[test]
    fn test_forgejo_config_empty() {
        let toml = r#"
            [gh.repos]
            "owner/repo" = { read = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();
        assert!(config.forgejo.is_empty());
    }
}

// ============================================================================
// Kani Formal Verification Proofs
// ============================================================================

#[cfg(kani)]
mod verification {
    use super::*;

    /// Verify permission hierarchy invariants for all possible permission combinations
    /// This proof found a real bug in the original logic!
    #[kani::proof]
    fn verify_permission_hierarchy_invariants() {
        let read: bool = kani::any();
        let create_draft: bool = kani::any();
        let pending_review: bool = kani::any();
        let write: bool = kani::any();

        let perm = GhRepoPermission {
            read,
            create_draft,
            pending_review,
            write,
        };

        // Property 1: write permission implies all others
        if perm.write {
            assert!(perm.can_read(), "Write permission should imply read");
            assert!(
                perm.can_create_draft(),
                "Write permission should imply create_draft"
            );
            assert!(
                perm.can_manage_pending_review(),
                "Write permission should imply pending_review"
            );
        }

        // Property 2: any capability should imply read access
        if perm.can_create_draft() || perm.can_manage_pending_review() || perm.can_write() {
            assert!(perm.can_read(), "Any capability should imply read access");
        }

        // Property 3: verify the corrected can_read() logic
        assert_eq!(
            perm.can_read(),
            perm.read || perm.create_draft || perm.pending_review || perm.write,
            "can_read should match any capability"
        );
    }
}
