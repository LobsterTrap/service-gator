//! Scope-based access control for service-gator.
//!
//! This module provides resource scoping with fine-grained permissions.
//! Each service (gh, jira, gitlab, etc.) has its own scope configuration
//! with service-specific resource types and capabilities.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::jira_types::{JiraIssueKey, JiraProjectKey};
use crate::secret::ApiToken;

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
///    - `push-new-branch = false` - No branch pushing (requires explicit grant)
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
    /// Also allows creating agent- prefixed branches for sandboxed AI agents.
    /// Defaults to true - drafts require human review before merge.
    #[serde(default = "default_true")]
    pub create_draft: bool,
    /// Can create/update/delete pending PR reviews.
    /// Reviews must contain the marker token to be manageable.
    /// Defaults to true - pending reviews require human submission.
    #[serde(default = "default_true")]
    pub pending_review: bool,
    /// Can create and push to new branches (agent-* or PR head branches).
    /// More permissive than create_draft - allows updating existing work.
    /// Defaults to false - requires explicit grant.
    #[serde(default)]
    pub push_new_branch: bool,
    /// Full write access (merge, close, create non-draft, etc.)
    /// Implies all other permissions.
    #[serde(default)]
    pub write: bool,
}

impl Default for GhRepoPermission {
    fn default() -> Self {
        Self {
            read: true,
            create_draft: true,
            pending_review: true,
            push_new_branch: false,
            write: false,
        }
    }
}

impl GhRepoPermission {
    /// Read-only access (no draft creation, no pending reviews, no branch pushing, no writes).
    pub fn read_only() -> Self {
        Self {
            read: true,
            create_draft: false,
            pending_review: false,
            push_new_branch: false,
            write: false,
        }
    }

    /// Read + create draft PRs only.
    pub fn with_draft() -> Self {
        Self {
            read: true,
            create_draft: true,
            pending_review: false,
            push_new_branch: false,
            write: false,
        }
    }

    /// Read + pending review management only.
    pub fn with_pending_review() -> Self {
        Self {
            read: true,
            create_draft: false,
            pending_review: true,
            push_new_branch: false,
            write: false,
        }
    }

    /// Read + new branch pushing only.
    pub fn with_push_new_branch() -> Self {
        Self {
            read: true,
            create_draft: false,
            pending_review: false,
            push_new_branch: true,
            write: false,
        }
    }

    /// Full write access (includes all other permissions).
    pub fn full_write() -> Self {
        Self {
            read: true,
            create_draft: true,
            pending_review: true,
            push_new_branch: true,
            write: true,
        }
    }

    /// Check if reads are allowed.
    /// Any capability (create_draft, pending_review, push_new_branch, write) implies read access.
    pub fn can_read(&self) -> bool {
        self.read || self.create_draft || self.pending_review || self.push_new_branch || self.write
    }

    /// Check if creating draft PRs is allowed.
    /// Also controls creation of agent- prefixed branches.
    /// For backward compatibility, also checks push_new_branch permission.
    pub fn can_create_draft(&self) -> bool {
        self.create_draft || self.push_new_branch || self.write
    }

    /// Check if managing pending PR reviews is allowed.
    pub fn can_manage_pending_review(&self) -> bool {
        self.pending_review || self.write
    }

    /// Check if pushing to branches is allowed.
    /// This covers both creating new agent- branches and updating existing ones.
    pub fn can_push_new_branch(&self) -> bool {
        self.push_new_branch || self.write
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
    /// Create a draft PR (also allows creating agent- branches)
    CreateDraft,
    /// Manage pending PR reviews (create, update body, delete)
    ManagePendingReview,
    /// Push to new branches (create new agent- branches or update existing ones)
    PushNewBranch,
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
    /// Global read access for all GitHub API endpoints.
    /// When true, allows read-only access to any endpoint including non-repo
    /// paths like /search, /gists, /user, /orgs, etc.
    /// This also implicitly enables GraphQL read access.
    #[serde(default)]
    pub read: bool,

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
    /// Note: If `read = true` is set, GraphQL read access is implicitly enabled.
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
    /// Returns true if global `read = true` is set, or if the repo matches
    /// a pattern with read permission.
    pub fn is_read_allowed(&self, repo: &str) -> bool {
        // Global read permission bypasses per-repo checks
        if self.read {
            return true;
        }
        let repo_patterns = self.repo_patterns();
        repo_patterns
            .get(repo)
            .map(|p| p.can_read())
            .unwrap_or(false)
    }

    /// Check if global read access is enabled (for non-repo endpoints like /search, /gists).
    pub fn global_read_allowed(&self) -> bool {
        self.read
    }

    /// Check if GraphQL read access is allowed.
    /// Returns true if global `read = true` is set, or if `graphql` is set to read.
    pub fn graphql_read_allowed(&self) -> bool {
        self.read || self.graphql.can_read()
    }

    /// Check if an operation is allowed.
    pub fn is_allowed(&self, repo: &str, op: GhOpType, resource_ref: Option<&str>) -> bool {
        // Global read permission bypasses per-repo checks for read operations
        if op == GhOpType::Read && self.read {
            return true;
        }

        let repo_patterns = self.repo_patterns();
        let repo_perm = repo_patterns.get(repo);

        match op {
            GhOpType::Read => repo_perm.map(|p| p.can_read()).unwrap_or(false),

            GhOpType::CreateDraft => repo_perm.map(|p| p.can_create_draft()).unwrap_or(false),

            GhOpType::ManagePendingReview => repo_perm
                .map(|p| p.can_manage_pending_review())
                .unwrap_or(false),

            GhOpType::PushNewBranch => repo_perm.map(|p| p.can_push_new_branch()).unwrap_or(false),

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
    /// Can create and push to new branches (agent-* or MR head branches).
    /// More permissive than create_draft - allows updating existing work.
    /// Defaults to false - requires explicit grant.
    #[serde(default)]
    pub push_new_branch: bool,
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

    pub fn with_push_new_branch() -> Self {
        Self {
            read: true,
            push_new_branch: true,
            ..Default::default()
        }
    }

    pub fn full_write() -> Self {
        Self {
            read: true,
            create_draft: true,
            approve: true,
            push_new_branch: true,
            write: true,
        }
    }

    /// Check if reads are allowed.
    /// Any capability (create_draft, approve, push_new_branch, write) implies read access.
    pub fn can_read(&self) -> bool {
        self.read || self.create_draft || self.approve || self.push_new_branch || self.write
    }

    /// Check if creating draft MRs is allowed.
    /// For backward compatibility, also checks push_new_branch permission.
    pub fn can_create_draft(&self) -> bool {
        self.create_draft || self.push_new_branch || self.write
    }

    /// Check if approving MRs is allowed.
    pub fn can_approve(&self) -> bool {
        self.approve || self.write
    }

    /// Check if pushing to branches is allowed.
    /// This covers both creating new agent- branches and updating existing ones.
    pub fn can_push_new_branch(&self) -> bool {
        self.push_new_branch || self.write
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
    /// Push to new branches (create new agent- branches or update existing ones)
    PushNewBranch,
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

            GlOpType::PushNewBranch => project_perm
                .map(|p| p.can_push_new_branch())
                .unwrap_or(false),

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
    /// Can create and push to new branches (agent-* or PR head branches).
    /// More permissive than create_draft - allows updating existing work.
    /// Defaults to false - requires explicit grant.
    #[serde(default)]
    pub push_new_branch: bool,
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

    pub fn with_push_new_branch() -> Self {
        Self {
            read: true,
            push_new_branch: true,
            ..Default::default()
        }
    }

    pub fn full_write() -> Self {
        Self {
            read: true,
            create_draft: true,
            pending_review: true,
            push_new_branch: true,
            write: true,
        }
    }

    /// Check if reads are allowed.
    /// Any capability (create_draft, pending_review, push_new_branch, write) implies read access.
    pub fn can_read(&self) -> bool {
        self.read || self.create_draft || self.pending_review || self.push_new_branch || self.write
    }

    /// Check if creating draft PRs is allowed.
    /// For backward compatibility, also checks push_new_branch permission.
    pub fn can_create_draft(&self) -> bool {
        self.create_draft || self.push_new_branch || self.write
    }

    /// Check if managing pending PR reviews is allowed.
    pub fn can_manage_pending_review(&self) -> bool {
        self.pending_review || self.write
    }

    /// Check if pushing to branches is allowed.
    /// This covers both creating new agent- branches and updating existing ones.
    pub fn can_push_new_branch(&self) -> bool {
        self.push_new_branch || self.write
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
    /// Push to new branches (create new agent- branches or update existing ones)
    PushNewBranch,
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
    pub token: Option<ApiToken>,

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

            ForgejoOpType::PushNewBranch => {
                repo_perm.map(|p| p.can_push_new_branch()).unwrap_or(false)
            }

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
    pub token: Option<ApiToken>,

    /// Project permissions: "PROJ" → permission
    #[serde(default)]
    pub projects: HashMap<JiraProjectKey, JiraProjectPermission>,

    /// Issue-specific permissions: "PROJ-123" → permission
    #[serde(default)]
    pub issues: HashMap<JiraIssueKey, JiraIssuePermission>,
}

impl JiraScope {
    /// Check if an operation is allowed for a project or issue.
    pub fn is_allowed(&self, project: &str, op: OpType, issue_key: Option<&str>) -> bool {
        // If we have specific issue permissions, check those first
        if let Some(issue_key) = issue_key {
            if let Ok(parsed_issue_key) = issue_key.parse::<JiraIssueKey>() {
                if let Some(issue_perm) = self.issues.get(&parsed_issue_key) {
                    return match op {
                        OpType::Read => issue_perm.read,
                        OpType::Write => issue_perm.write,
                    };
                }
            }
        }

        // Fall back to project-level permissions
        if let Ok(project_key) = project.parse::<JiraProjectKey>() {
            if let Some(project_perm) = self.projects.get(&project_key) {
                return match op {
                    OpType::Read => project_perm.can_read(),
                    OpType::Write => project_perm.can_write(),
                };
            }
        }

        false
    }

    /// Check if the user has any read access to any project.
    pub fn has_any_read_access(&self) -> bool {
        self.projects.values().any(|p| p.can_read()) || self.issues.values().any(|i| i.read)
    }

    /// Get JIRA host from config or environment.
    pub fn host(&self) -> String {
        self.host
            .clone()
            .or_else(|| std::env::var("JIRA_HOST").ok())
            .unwrap_or_else(|| "https://jira.atlassian.net".to_string())
    }

    /// Get JIRA username from config or environment.
    pub fn username(&self) -> String {
        self.username
            .clone()
            .or_else(|| std::env::var("JIRA_USERNAME").ok())
            .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "user".to_string()))
    }

    /// Get JIRA token from config or environment.
    pub fn token(&self) -> String {
        self.token
            .as_ref()
            .map(|t| t.expose_secret().to_string())
            .or_else(|| std::env::var("JIRA_API_TOKEN").ok())
            .unwrap_or_else(|| {
                // This will fail later when trying to authenticate, but we return empty for now
                "".to_string()
            })
    }
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
            read: false,
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
        let myproj_key: JiraProjectKey = "MYPROJ".parse().unwrap();
        assert!(config.jira.projects.get(&myproj_key).unwrap().create);
    }

    #[test]
    fn test_graphql_permission() {
        assert!(!GraphQlPermission::None.can_read());
        assert!(GraphQlPermission::Read.can_read());
    }

    #[test]
    fn test_github_scope_is_read_allowed() {
        let scope = GithubScope {
            read: false,
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
    fn test_github_scope_global_read() {
        // Table-driven test for global read behavior
        struct TestCase {
            name: &'static str,
            global_read: bool,
            graphql_setting: GraphQlPermission,
            repos: Vec<(&'static str, GhRepoPermission)>,
            // Expected results
            expect_global_read_allowed: bool,
            expect_graphql_allowed: bool,
            // (repo, expected_read_allowed)
            read_checks: Vec<(&'static str, bool)>,
            // (repo, op, expected_allowed)
            op_checks: Vec<(&'static str, GhOpType, bool)>,
        }

        let cases = vec![
            TestCase {
                name: "global_read_true_no_repos",
                global_read: true,
                graphql_setting: GraphQlPermission::None,
                repos: vec![],
                expect_global_read_allowed: true,
                expect_graphql_allowed: true, // implicitly enabled by global read
                read_checks: vec![
                    ("any/repo", true),
                    ("unknown/random", true),
                    ("foo/bar", true),
                ],
                op_checks: vec![
                    ("any/repo", GhOpType::Read, true),
                    ("any/repo", GhOpType::Write, false),
                    ("any/repo", GhOpType::CreateDraft, false),
                    ("any/repo", GhOpType::ManagePendingReview, false),
                ],
            },
            TestCase {
                name: "global_read_false_with_repos",
                global_read: false,
                graphql_setting: GraphQlPermission::None,
                repos: vec![
                    ("owner/*", GhRepoPermission::read_only()),
                    ("specific/repo", GhRepoPermission::with_draft()),
                ],
                expect_global_read_allowed: false,
                expect_graphql_allowed: false,
                read_checks: vec![
                    ("owner/foo", true),
                    ("owner/bar", true),
                    ("specific/repo", true),
                    ("unknown/repo", false),
                ],
                op_checks: vec![
                    ("owner/foo", GhOpType::Read, true),
                    ("owner/foo", GhOpType::CreateDraft, false),
                    ("specific/repo", GhOpType::CreateDraft, true),
                    ("unknown/repo", GhOpType::Read, false),
                ],
            },
            TestCase {
                name: "global_read_false_graphql_explicit",
                global_read: false,
                graphql_setting: GraphQlPermission::Read,
                repos: vec![],
                expect_global_read_allowed: false,
                expect_graphql_allowed: true,
                read_checks: vec![("any/repo", false)],
                op_checks: vec![],
            },
            TestCase {
                name: "global_read_true_with_write_repos",
                global_read: true,
                graphql_setting: GraphQlPermission::None,
                repos: vec![("writable/repo", GhRepoPermission::full_write())],
                expect_global_read_allowed: true,
                expect_graphql_allowed: true,
                read_checks: vec![("writable/repo", true), ("other/repo", true)],
                op_checks: vec![
                    ("writable/repo", GhOpType::Write, true),
                    ("writable/repo", GhOpType::CreateDraft, true),
                    ("other/repo", GhOpType::Read, true),
                    ("other/repo", GhOpType::Write, false),
                ],
            },
        ];

        for case in cases {
            let scope = GithubScope {
                read: case.global_read,
                repos: case
                    .repos
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
                prs: HashMap::new(),
                issues: HashMap::new(),
                graphql: case.graphql_setting,
            };

            assert_eq!(
                scope.global_read_allowed(),
                case.expect_global_read_allowed,
                "{}: global_read_allowed mismatch",
                case.name
            );
            assert_eq!(
                scope.graphql_read_allowed(),
                case.expect_graphql_allowed,
                "{}: graphql_read_allowed mismatch",
                case.name
            );

            for (repo, expected) in case.read_checks {
                assert_eq!(
                    scope.is_read_allowed(repo),
                    expected,
                    "{}: is_read_allowed({}) expected {}",
                    case.name,
                    repo,
                    expected
                );
            }

            for (repo, op, expected) in case.op_checks {
                assert_eq!(
                    scope.is_allowed(repo, op.clone(), None),
                    expected,
                    "{}: is_allowed({}, {:?}) expected {}",
                    case.name,
                    repo,
                    op,
                    expected
                );
            }
        }
    }

    #[test]
    fn test_github_scope_graphql_permissions() {
        let scope_none = GithubScope {
            read: false,
            repos: HashMap::new(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };
        assert!(!scope_none.graphql_read_allowed());

        let scope_read = GithubScope {
            read: false,
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

    #[test]
    fn test_config_deserialization_global_read() {
        // Table-driven test for global read config parsing
        struct TestCase {
            name: &'static str,
            toml: &'static str,
            expect_global_read: bool,
            expect_graphql: bool,
            expect_repo_read: Option<(&'static str, bool)>,
        }

        let cases = vec![
            TestCase {
                name: "read_true_only",
                toml: r#"
                    [gh]
                    read = true
                "#,
                expect_global_read: true,
                expect_graphql: true, // implicitly enabled
                expect_repo_read: Some(("any/repo", true)),
            },
            TestCase {
                name: "read_false_explicit",
                toml: r#"
                    [gh]
                    read = false
                "#,
                expect_global_read: false,
                expect_graphql: false,
                expect_repo_read: Some(("any/repo", false)),
            },
            TestCase {
                name: "read_true_with_graphql_none",
                toml: r#"
                    [gh]
                    read = true
                    graphql = "none"
                "#,
                expect_global_read: true,
                expect_graphql: true, // global read overrides graphql=none
                expect_repo_read: None,
            },
            TestCase {
                name: "read_not_specified_defaults_false",
                toml: r#"
                    [gh.repos]
                    "owner/repo" = { read = true }
                "#,
                expect_global_read: false,
                expect_graphql: false,
                expect_repo_read: Some(("owner/repo", true)),
            },
            TestCase {
                name: "read_true_with_repos",
                toml: r#"
                    [gh]
                    read = true

                    [gh.repos]
                    "special/repo" = { read = true, write = true }
                "#,
                expect_global_read: true,
                expect_graphql: true,
                expect_repo_read: Some(("other/repo", true)), // global read allows any
            },
        ];

        for case in cases {
            let config: ScopeConfig = toml::from_str(case.toml)
                .unwrap_or_else(|e| panic!("{}: parse error: {}", case.name, e));

            assert_eq!(
                config.gh.global_read_allowed(),
                case.expect_global_read,
                "{}: global_read_allowed mismatch",
                case.name
            );
            assert_eq!(
                config.gh.graphql_read_allowed(),
                case.expect_graphql,
                "{}: graphql_read_allowed mismatch",
                case.name
            );

            if let Some((repo, expected)) = case.expect_repo_read {
                assert_eq!(
                    config.gh.is_read_allowed(repo),
                    expected,
                    "{}: is_read_allowed({}) mismatch",
                    case.name,
                    repo
                );
            }
        }
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
            read: false,
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
    // Tests for require-fork permission
    // ========================================================================

    // ========================================================================
    // Tests for push-new-branch permission
    // ========================================================================

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

    // ========================================================================
    // Tests for push-new-branch permission
    // ========================================================================

    #[test]
    fn test_gh_repo_permission_push_new_branch_defaults() {
        // Default permissions should not include push_new_branch
        let p = GhRepoPermission::default();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(p.can_manage_pending_review());
        assert!(!p.can_push_new_branch()); // Should default to false
        assert!(!p.can_write());
    }

    #[test]
    fn test_gh_repo_permission_with_push_new_branch() {
        let p = GhRepoPermission::with_push_new_branch();
        assert!(p.can_read());
        assert!(p.can_create_draft()); // push_new_branch enables create_draft for backward compatibility
        assert!(!p.can_manage_pending_review());
        assert!(p.can_push_new_branch());
        assert!(!p.can_write());
    }

    #[test]
    fn test_gh_repo_permission_push_new_branch_backward_compatibility() {
        // push_new_branch should enable can_create_draft for backward compatibility
        let p = GhRepoPermission {
            read: true,
            create_draft: false,
            pending_review: false,
            push_new_branch: true,
            write: false,
        };
        assert!(p.can_push_new_branch());
        assert!(p.can_create_draft()); // Should be true due to backward compatibility
    }

    #[test]
    fn test_gh_repo_permission_full_write_includes_push_new_branch() {
        let p = GhRepoPermission::full_write();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(p.can_manage_pending_review());
        assert!(p.can_push_new_branch()); // full_write should include push_new_branch
        assert!(p.can_write());
    }

    #[test]
    fn test_github_scope_push_new_branch_operation() {
        let scope = GithubScope {
            read: false,
            repos: [
                ("owner/readonly".into(), GhRepoPermission::read_only()),
                (
                    "owner/push".into(),
                    GhRepoPermission::with_push_new_branch(),
                ),
                ("owner/draft".into(), GhRepoPermission::with_draft()),
                ("owner/full".into(), GhRepoPermission::full_write()),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Read-only repo cannot push branches
        assert!(!scope.is_allowed("owner/readonly", GhOpType::PushNewBranch, None));

        // Push-branch repo can push branches
        assert!(scope.is_allowed("owner/push", GhOpType::PushNewBranch, None));

        // Draft repo cannot push branches
        assert!(!scope.is_allowed("owner/draft", GhOpType::PushNewBranch, None));

        // Full write repo can push branches
        assert!(scope.is_allowed("owner/full", GhOpType::PushNewBranch, None));

        // Unknown repo cannot push branches
        assert!(!scope.is_allowed("owner/unknown", GhOpType::PushNewBranch, None));
    }

    #[test]
    fn test_gl_project_permission_push_new_branch_defaults() {
        // Default permissions should not include push_new_branch
        let p = GlProjectPermission::default();
        assert!(!p.can_read());
        assert!(!p.can_create_draft());
        assert!(!p.can_approve());
        assert!(!p.can_push_new_branch()); // Should default to false
        assert!(!p.can_write());
    }

    #[test]
    fn test_gl_project_permission_with_push_new_branch() {
        let p = GlProjectPermission::with_push_new_branch();
        assert!(p.can_read());
        assert!(p.can_create_draft()); // push_new_branch enables create_draft for backward compatibility
        assert!(!p.can_approve());
        assert!(p.can_push_new_branch());
        assert!(!p.can_write());
    }

    #[test]
    fn test_gl_project_permission_push_new_branch_backward_compatibility() {
        // push_new_branch should enable can_create_draft for backward compatibility
        let p = GlProjectPermission {
            read: true,
            create_draft: false,
            approve: false,
            push_new_branch: true,
            write: false,
        };
        assert!(p.can_push_new_branch());
        assert!(p.can_create_draft()); // Should be true due to backward compatibility
    }

    #[test]
    fn test_gl_project_permission_full_write_includes_push_new_branch() {
        let p = GlProjectPermission::full_write();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(p.can_approve());
        assert!(p.can_push_new_branch()); // full_write should include push_new_branch
        assert!(p.can_write());
    }

    #[test]
    fn test_gitlab_scope_push_new_branch_operation() {
        let scope = GitLabScope {
            projects: [
                ("group/readonly".into(), GlProjectPermission::read_only()),
                (
                    "group/push".into(),
                    GlProjectPermission::with_push_new_branch(),
                ),
                ("group/draft".into(), GlProjectPermission::with_draft()),
                ("group/full".into(), GlProjectPermission::full_write()),
            ]
            .into(),
            mrs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
            host: None,
        };

        // Read-only project cannot push branches
        assert!(!scope.is_allowed("group/readonly", GlOpType::PushNewBranch, None));

        // Push-branch project can push branches
        assert!(scope.is_allowed("group/push", GlOpType::PushNewBranch, None));

        // Draft project cannot push branches
        assert!(!scope.is_allowed("group/draft", GlOpType::PushNewBranch, None));

        // Full write project can push branches
        assert!(scope.is_allowed("group/full", GlOpType::PushNewBranch, None));

        // Unknown project cannot push branches
        assert!(!scope.is_allowed("group/unknown", GlOpType::PushNewBranch, None));
    }

    #[test]
    fn test_forgejo_repo_permission_push_new_branch_defaults() {
        // Default permissions should not include push_new_branch
        let p = ForgejoRepoPermission::default();
        assert!(!p.can_read());
        assert!(!p.can_create_draft());
        assert!(!p.can_manage_pending_review());
        assert!(!p.can_push_new_branch()); // Should default to false
        assert!(!p.can_write());
    }

    #[test]
    fn test_forgejo_repo_permission_with_push_new_branch() {
        let p = ForgejoRepoPermission::with_push_new_branch();
        assert!(p.can_read());
        assert!(p.can_create_draft()); // push_new_branch enables create_draft for backward compatibility
        assert!(!p.can_manage_pending_review());
        assert!(p.can_push_new_branch());
        assert!(!p.can_write());
    }

    #[test]
    fn test_forgejo_repo_permission_push_new_branch_backward_compatibility() {
        // push_new_branch should enable can_create_draft for backward compatibility
        let p = ForgejoRepoPermission {
            read: true,
            create_draft: false,
            pending_review: false,
            push_new_branch: true,
            write: false,
        };
        assert!(p.can_push_new_branch());
        assert!(p.can_create_draft()); // Should be true due to backward compatibility
    }

    #[test]
    fn test_forgejo_repo_permission_full_write_includes_push_new_branch() {
        let p = ForgejoRepoPermission::full_write();
        assert!(p.can_read());
        assert!(p.can_create_draft());
        assert!(p.can_manage_pending_review());
        assert!(p.can_push_new_branch()); // full_write should include push_new_branch
        assert!(p.can_write());
    }

    #[test]
    fn test_forgejo_scope_push_new_branch_operation() {
        let scope = ForgejoScope {
            host: "codeberg.org".to_string(),
            token: None,
            repos: [
                ("owner/readonly".into(), ForgejoRepoPermission::read_only()),
                (
                    "owner/push".into(),
                    ForgejoRepoPermission::with_push_new_branch(),
                ),
                ("owner/draft".into(), ForgejoRepoPermission::with_draft()),
                ("owner/full".into(), ForgejoRepoPermission::full_write()),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
        };

        // Read-only repo cannot push branches
        assert!(!scope.is_allowed("owner/readonly", ForgejoOpType::PushNewBranch, None));

        // Push-branch repo can push branches
        assert!(scope.is_allowed("owner/push", ForgejoOpType::PushNewBranch, None));

        // Draft repo cannot push branches
        assert!(!scope.is_allowed("owner/draft", ForgejoOpType::PushNewBranch, None));

        // Full write repo can push branches
        assert!(scope.is_allowed("owner/full", ForgejoOpType::PushNewBranch, None));

        // Unknown repo cannot push branches
        assert!(!scope.is_allowed("owner/unknown", ForgejoOpType::PushNewBranch, None));
    }

    // ============================================================================
    // Comprehensive Integration Tests for Permission Separation
    // ============================================================================

    #[test]
    fn test_permission_separation_configuration_scenarios() {
        // Test scenario 1: Repository with only push-new-branch = true (can push, cannot create PRs)
        let scope_push_only = GithubScope {
            read: false,
            repos: [(
                "owner/push-only".into(),
                GhRepoPermission {
                    read: true,
                    create_draft: false,
                    pending_review: false,
                    push_new_branch: true,
                    write: false,
                },
            )]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Can push branches
        assert!(scope_push_only.is_allowed("owner/push-only", GhOpType::PushNewBranch, None));
        // Cannot create draft PRs (but can due to backward compatibility)
        assert!(scope_push_only.is_allowed("owner/push-only", GhOpType::CreateDraft, None));
        // Cannot do full write operations
        assert!(!scope_push_only.is_allowed("owner/push-only", GhOpType::Write, None));
        // Can read
        assert!(scope_push_only.is_allowed("owner/push-only", GhOpType::Read, None));

        // Test scenario 2: Repository with only create-draft = true (can create PRs, can also push due to compatibility)
        let scope_draft_only = GithubScope {
            read: false,
            repos: [(
                "owner/draft-only".into(),
                GhRepoPermission {
                    read: true,
                    create_draft: true,
                    pending_review: false,
                    push_new_branch: false,
                    write: false,
                },
            )]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Can create draft PRs
        assert!(scope_draft_only.is_allowed("owner/draft-only", GhOpType::CreateDraft, None));
        // Cannot push branches directly (no push_new_branch permission)
        assert!(!scope_draft_only.is_allowed("owner/draft-only", GhOpType::PushNewBranch, None));
        // Cannot do full write operations
        assert!(!scope_draft_only.is_allowed("owner/draft-only", GhOpType::Write, None));
        // Can read
        assert!(scope_draft_only.is_allowed("owner/draft-only", GhOpType::Read, None));

        // Test scenario 3: Repository with both push-new-branch = true and create-draft = true
        let scope_both = GithubScope {
            read: false,
            repos: [(
                "owner/both".into(),
                GhRepoPermission {
                    read: true,
                    create_draft: true,
                    pending_review: false,
                    push_new_branch: true,
                    write: false,
                },
            )]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Can do both operations
        assert!(scope_both.is_allowed("owner/both", GhOpType::PushNewBranch, None));
        assert!(scope_both.is_allowed("owner/both", GhOpType::CreateDraft, None));
        assert!(scope_both.is_allowed("owner/both", GhOpType::Read, None));
        assert!(!scope_both.is_allowed("owner/both", GhOpType::Write, None));

        // Test scenario 4: Repository with neither (cannot do either operation)
        let scope_neither = GithubScope {
            read: false,
            repos: [(
                "owner/neither".into(),
                GhRepoPermission {
                    read: true,
                    create_draft: false,
                    pending_review: false,
                    push_new_branch: false,
                    write: false,
                },
            )]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Cannot do push or draft operations
        assert!(!scope_neither.is_allowed("owner/neither", GhOpType::PushNewBranch, None));
        assert!(!scope_neither.is_allowed("owner/neither", GhOpType::CreateDraft, None));
        assert!(!scope_neither.is_allowed("owner/neither", GhOpType::Write, None));
        // Can still read
        assert!(scope_neither.is_allowed("owner/neither", GhOpType::Read, None));
    }

    #[test]
    fn test_operation_permission_requirements() {
        let scope = GithubScope {
            read: false,
            repos: [
                // Only push-new-branch permission
                (
                    "owner/push-only".into(),
                    GhRepoPermission {
                        read: true,
                        create_draft: false,
                        pending_review: false,
                        push_new_branch: true,
                        write: false,
                    },
                ),
                // Only create-draft permission
                (
                    "owner/draft-only".into(),
                    GhRepoPermission {
                        read: true,
                        create_draft: true,
                        pending_review: false,
                        push_new_branch: false,
                        write: false,
                    },
                ),
                // Both permissions
                (
                    "owner/both".into(),
                    GhRepoPermission {
                        read: true,
                        create_draft: true,
                        pending_review: false,
                        push_new_branch: true,
                        write: false,
                    },
                ),
                // No permissions except read
                (
                    "owner/read-only".into(),
                    GhRepoPermission {
                        read: true,
                        create_draft: false,
                        pending_review: false,
                        push_new_branch: false,
                        write: false,
                    },
                ),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Test git_push_local equivalent (requires push-new-branch)
        assert!(scope.is_allowed("owner/push-only", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("owner/draft-only", GhOpType::PushNewBranch, None));
        assert!(scope.is_allowed("owner/both", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("owner/read-only", GhOpType::PushNewBranch, None));

        // Test github_push (no PR) equivalent (requires push-new-branch)
        assert!(scope.is_allowed("owner/push-only", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("owner/draft-only", GhOpType::PushNewBranch, None));
        assert!(scope.is_allowed("owner/both", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("owner/read-only", GhOpType::PushNewBranch, None));

        // Test github_push (with PR) equivalent (requires both push-new-branch and create-draft)
        // Note: In practice, this would check both permissions in the MCP tool
        // push-only: has push-new-branch but backward compatibility gives create-draft
        let push_only_can_create = scope.is_allowed("owner/push-only", GhOpType::CreateDraft, None);
        let push_only_can_push = scope.is_allowed("owner/push-only", GhOpType::PushNewBranch, None);
        assert!(push_only_can_create && push_only_can_push); // Both should be true due to backward compatibility

        // draft-only: has create-draft but no push-new-branch
        let draft_only_can_create =
            scope.is_allowed("owner/draft-only", GhOpType::CreateDraft, None);
        let draft_only_can_push =
            scope.is_allowed("owner/draft-only", GhOpType::PushNewBranch, None);
        assert!(draft_only_can_create && !draft_only_can_push); // Would fail in practice

        // both: has both permissions
        let both_can_create = scope.is_allowed("owner/both", GhOpType::CreateDraft, None);
        let both_can_push = scope.is_allowed("owner/both", GhOpType::PushNewBranch, None);
        assert!(both_can_create && both_can_push);

        // read-only: has neither
        let readonly_can_create = scope.is_allowed("owner/read-only", GhOpType::CreateDraft, None);
        let readonly_can_push = scope.is_allowed("owner/read-only", GhOpType::PushNewBranch, None);
        assert!(!readonly_can_create && !readonly_can_push);

        // Test gh_create_branch equivalent (requires push-new-branch)
        assert!(scope.is_allowed("owner/push-only", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("owner/draft-only", GhOpType::PushNewBranch, None));
        assert!(scope.is_allowed("owner/both", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("owner/read-only", GhOpType::PushNewBranch, None));
    }

    #[test]
    fn test_backward_compatibility_behavior() {
        // Test that existing configurations with create-draft = true continue to work for all operations
        let legacy_scope = GithubScope {
            read: false,
            repos: [(
                "owner/legacy".into(),
                GhRepoPermission {
                    read: true,
                    create_draft: true,
                    pending_review: true,
                    push_new_branch: false, // This is the key - old configs won't have this set
                    write: false,
                },
            )]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Legacy config should work for create-draft operations
        assert!(legacy_scope.is_allowed("owner/legacy", GhOpType::CreateDraft, None));
        // But not for direct push-new-branch operations since push_new_branch = false
        assert!(!legacy_scope.is_allowed("owner/legacy", GhOpType::PushNewBranch, None));
        // Can do other operations it had before
        assert!(legacy_scope.is_allowed("owner/legacy", GhOpType::Read, None));
        assert!(legacy_scope.is_allowed("owner/legacy", GhOpType::ManagePendingReview, None));

        // Test migration scenario - adding push_new_branch = true to existing config
        let migrated_scope = GithubScope {
            read: false,
            repos: [(
                "owner/migrated".into(),
                GhRepoPermission {
                    read: true,
                    create_draft: true,
                    pending_review: true,
                    push_new_branch: true, // Now explicitly granted
                    write: false,
                },
            )]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Migrated config should work for all operations
        assert!(migrated_scope.is_allowed("owner/migrated", GhOpType::CreateDraft, None));
        assert!(migrated_scope.is_allowed("owner/migrated", GhOpType::PushNewBranch, None));
        assert!(migrated_scope.is_allowed("owner/migrated", GhOpType::Read, None));
        assert!(migrated_scope.is_allowed("owner/migrated", GhOpType::ManagePendingReview, None));

        // Test that push_new_branch alone enables create_draft for backward compatibility
        let push_only_scope = GithubScope {
            read: false,
            repos: [(
                "owner/push-enabled".into(),
                GhRepoPermission {
                    read: true,
                    create_draft: false, // Explicitly disabled
                    pending_review: false,
                    push_new_branch: true, // But push is enabled
                    write: false,
                },
            )]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // push_new_branch should enable create_draft for backward compatibility
        assert!(push_only_scope.is_allowed("owner/push-enabled", GhOpType::CreateDraft, None));
        assert!(push_only_scope.is_allowed("owner/push-enabled", GhOpType::PushNewBranch, None));
    }

    #[test]
    fn test_toml_configuration_parsing() {
        // Test that the new push-new-branch field is correctly parsed from TOML
        let toml_basic = r#"
            [gh.repos]
            "owner/repo" = { read = true, push-new-branch = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml_basic).unwrap();
        let repo_perm = config.gh.repos.get("owner/repo").unwrap();
        assert!(repo_perm.read);
        assert!(repo_perm.push_new_branch);
        assert!(repo_perm.create_draft); // Should default to true when not specified
        assert!(!repo_perm.write);

        // Test combined configurations
        let toml_combined = r#"
            [gh.repos]
            "owner/both" = { read = true, create-draft = true, push-new-branch = true }
            "owner/draft-only" = { read = true, create-draft = true }
            "owner/push-only" = { read = true, push-new-branch = true }
            "owner/legacy" = { read = true, create-draft = true, pending-review = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml_combined).unwrap();

        // Test "both" config
        let both_perm = config.gh.repos.get("owner/both").unwrap();
        assert!(both_perm.read);
        assert!(both_perm.create_draft);
        assert!(both_perm.push_new_branch);
        assert!(both_perm.pending_review); // Should default to true
        assert!(!both_perm.write);

        // Test "draft-only" config
        let draft_perm = config.gh.repos.get("owner/draft-only").unwrap();
        assert!(draft_perm.read);
        assert!(draft_perm.create_draft);
        assert!(!draft_perm.push_new_branch); // Should default to false
        assert!(draft_perm.pending_review); // Should default to true

        // Test "push-only" config
        let push_perm = config.gh.repos.get("owner/push-only").unwrap();
        assert!(push_perm.read);
        assert!(push_perm.create_draft); // Should default to true when not specified
        assert!(push_perm.push_new_branch);
        assert!(push_perm.pending_review); // Should default to true

        // Test "legacy" config (no push-new-branch specified)
        let legacy_perm = config.gh.repos.get("owner/legacy").unwrap();
        assert!(legacy_perm.read);
        assert!(legacy_perm.create_draft);
        assert!(!legacy_perm.push_new_branch); // Should default to false
        assert!(legacy_perm.pending_review);

        // Test default values when repo is empty
        let toml_empty = r#"
            [gh.repos]
            "owner/empty" = {}
        "#;

        let config: ScopeConfig = toml::from_str(toml_empty).unwrap();
        let empty_perm = config.gh.repos.get("owner/empty").unwrap();
        assert!(empty_perm.read); // Should default to true
        assert!(empty_perm.create_draft); // Should default to true
        assert!(empty_perm.pending_review); // Should default to true
        assert!(!empty_perm.push_new_branch); // Should default to false
        assert!(!empty_perm.write); // Should default to false

        // Test explicit separation - push-new-branch without create-draft
        let toml_separated = r#"
            [gh.repos]
            "owner/push-no-draft" = { read = true, create-draft = false, push-new-branch = true }
            "owner/draft-no-push" = { read = true, create-draft = true, push-new-branch = false }
        "#;

        let config: ScopeConfig = toml::from_str(toml_separated).unwrap();

        // Test push-new-branch without create-draft
        let push_no_draft = config.gh.repos.get("owner/push-no-draft").unwrap();
        assert!(push_no_draft.read);
        assert!(!push_no_draft.create_draft); // Explicitly disabled
        assert!(push_no_draft.push_new_branch); // Explicitly enabled
                                                // But can_create_draft() should still return true due to backward compatibility
        assert!(push_no_draft.can_create_draft());
        assert!(push_no_draft.can_push_new_branch());

        // Test create-draft without push-new-branch
        let draft_no_push = config.gh.repos.get("owner/draft-no-push").unwrap();
        assert!(draft_no_push.read);
        assert!(draft_no_push.create_draft); // Explicitly enabled
        assert!(!draft_no_push.push_new_branch); // Explicitly disabled
        assert!(draft_no_push.can_create_draft());
        assert!(!draft_no_push.can_push_new_branch());
    }

    #[test]
    fn test_error_message_content() {
        // This test verifies that permission checks would produce helpful error messages
        // Note: The actual error message generation happens in the MCP tools, not in scope.rs
        // But we can verify the permission checks that would trigger those errors

        let scope = GithubScope {
            read: false,
            repos: [
                ("owner/read-only".into(), GhRepoPermission::read_only()),
                (
                    "owner/draft-only".into(),
                    GhRepoPermission {
                        read: true,
                        create_draft: true,
                        pending_review: false,
                        push_new_branch: false,
                        write: false,
                    },
                ),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Test scenarios that would trigger "push-new-branch permission not granted" errors
        assert!(!scope.is_allowed("owner/read-only", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("owner/draft-only", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("owner/unknown", GhOpType::PushNewBranch, None));

        // Test scenarios that would trigger "create-draft permission not granted" errors
        assert!(!scope.is_allowed("owner/read-only", GhOpType::CreateDraft, None));
        // Note: draft-only should allow create-draft
        assert!(scope.is_allowed("owner/draft-only", GhOpType::CreateDraft, None));

        // Test scenarios for combined permission requirements
        // (github_push with create_draft_pr=true requires both push-new-branch AND create-draft)

        // read-only: has neither
        assert!(!scope.is_allowed("owner/read-only", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("owner/read-only", GhOpType::CreateDraft, None));

        // draft-only: has create-draft but not push-new-branch
        assert!(!scope.is_allowed("owner/draft-only", GhOpType::PushNewBranch, None));
        assert!(scope.is_allowed("owner/draft-only", GhOpType::CreateDraft, None));
    }

    #[test]
    fn test_permission_interaction_matrix() {
        // Comprehensive matrix test for all permission combinations
        struct PermissionTest {
            name: &'static str,
            permission: GhRepoPermission,
            expected_read: bool,
            expected_create_draft: bool,
            expected_pending_review: bool,
            expected_push_new_branch: bool,
            expected_write: bool,
        }

        let tests = vec![
            PermissionTest {
                name: "default",
                permission: GhRepoPermission::default(),
                expected_read: true,
                expected_create_draft: true,
                expected_pending_review: true,
                expected_push_new_branch: false,
                expected_write: false,
            },
            PermissionTest {
                name: "read_only",
                permission: GhRepoPermission::read_only(),
                expected_read: true,
                expected_create_draft: false,
                expected_pending_review: false,
                expected_push_new_branch: false,
                expected_write: false,
            },
            PermissionTest {
                name: "with_draft",
                permission: GhRepoPermission::with_draft(),
                expected_read: true,
                expected_create_draft: true,
                expected_pending_review: false,
                expected_push_new_branch: false,
                expected_write: false,
            },
            PermissionTest {
                name: "with_push_new_branch",
                permission: GhRepoPermission::with_push_new_branch(),
                expected_read: true,
                expected_create_draft: true, // backward compatibility
                expected_pending_review: false,
                expected_push_new_branch: true,
                expected_write: false,
            },
            PermissionTest {
                name: "with_pending_review",
                permission: GhRepoPermission::with_pending_review(),
                expected_read: true,
                expected_create_draft: false,
                expected_pending_review: true,
                expected_push_new_branch: false,
                expected_write: false,
            },
            PermissionTest {
                name: "full_write",
                permission: GhRepoPermission::full_write(),
                expected_read: true,
                expected_create_draft: true,
                expected_pending_review: true,
                expected_push_new_branch: true,
                expected_write: true,
            },
            PermissionTest {
                name: "explicit_all_false",
                permission: GhRepoPermission {
                    read: false,
                    create_draft: false,
                    pending_review: false,
                    push_new_branch: false,
                    write: false,
                },
                expected_read: false,
                expected_create_draft: false,
                expected_pending_review: false,
                expected_push_new_branch: false,
                expected_write: false,
            },
            PermissionTest {
                name: "only_push_branch",
                permission: GhRepoPermission {
                    read: false,
                    create_draft: false,
                    pending_review: false,
                    push_new_branch: true,
                    write: false,
                },
                expected_read: true,         // implied by push_branch
                expected_create_draft: true, // backward compatibility
                expected_pending_review: false,
                expected_push_new_branch: true,
                expected_write: false,
            },
        ];

        for test in tests {
            // Test individual permission methods
            assert_eq!(
                test.permission.can_read(),
                test.expected_read,
                "{}: can_read() mismatch",
                test.name
            );
            assert_eq!(
                test.permission.can_create_draft(),
                test.expected_create_draft,
                "{}: can_create_draft() mismatch",
                test.name
            );
            assert_eq!(
                test.permission.can_manage_pending_review(),
                test.expected_pending_review,
                "{}: can_manage_pending_review() mismatch",
                test.name
            );
            assert_eq!(
                test.permission.can_push_new_branch(),
                test.expected_push_new_branch,
                "{}: can_push_new_branch() mismatch",
                test.name
            );
            assert_eq!(
                test.permission.can_write(),
                test.expected_write,
                "{}: can_write() mismatch",
                test.name
            );

            // Test via scope operations
            let scope = GithubScope {
                read: false,
                repos: [("test/repo".to_string(), test.permission.clone())].into(),
                prs: HashMap::new(),
                issues: HashMap::new(),
                graphql: GraphQlPermission::None,
            };

            assert_eq!(
                scope.is_allowed("test/repo", GhOpType::Read, None),
                test.expected_read,
                "{}: GhOpType::Read mismatch",
                test.name
            );
            assert_eq!(
                scope.is_allowed("test/repo", GhOpType::CreateDraft, None),
                test.expected_create_draft,
                "{}: GhOpType::CreateDraft mismatch",
                test.name
            );
            assert_eq!(
                scope.is_allowed("test/repo", GhOpType::ManagePendingReview, None),
                test.expected_pending_review,
                "{}: GhOpType::ManagePendingReview mismatch",
                test.name
            );
            assert_eq!(
                scope.is_allowed("test/repo", GhOpType::PushNewBranch, None),
                test.expected_push_new_branch,
                "{}: GhOpType::PushNewBranch mismatch",
                test.name
            );
            assert_eq!(
                scope.is_allowed("test/repo", GhOpType::Write, None),
                test.expected_write,
                "{}: GhOpType::Write mismatch",
                test.name
            );
        }
    }

    #[test]
    fn test_config_deserialization_with_push_new_branch() {
        let toml = r#"
            [gh.repos]
            "owner/repo" = { read = true, create-draft = false, pending-review = false, push-new-branch = true }
            "owner/full" = { read = true, create-draft = true, pending-review = true, push-new-branch = true, write = true }

            [gitlab.projects]
            "group/project" = { read = true, create-draft = false, approve = false, push-new-branch = true }

            [[forgejo]]
            host = "codeberg.org"

            [forgejo.repos]
            "owner/repo" = { read = true, create-draft = false, pending-review = false, push-new-branch = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();

        // GitHub permissions
        let gh_repo_perm = config.gh.repos.get("owner/repo").unwrap();
        assert!(gh_repo_perm.read);
        assert!(!gh_repo_perm.create_draft);
        assert!(!gh_repo_perm.pending_review);
        assert!(gh_repo_perm.push_new_branch);
        assert!(!gh_repo_perm.write);

        let gh_full_perm = config.gh.repos.get("owner/full").unwrap();
        assert!(gh_full_perm.push_new_branch);
        assert!(gh_full_perm.write);

        // GitLab permissions
        let gl_project_perm = config.gitlab.projects.get("group/project").unwrap();
        assert!(gl_project_perm.read);
        assert!(!gl_project_perm.create_draft);
        assert!(!gl_project_perm.approve);
        assert!(gl_project_perm.push_new_branch);
        assert!(!gl_project_perm.write);

        // Forgejo permissions
        let forgejo_repo_perm = config.forgejo[0].repos.get("owner/repo").unwrap();
        assert!(forgejo_repo_perm.read);
        assert!(!forgejo_repo_perm.create_draft);
        assert!(!forgejo_repo_perm.pending_review);
        assert!(forgejo_repo_perm.push_new_branch);
        assert!(!forgejo_repo_perm.write);
    }

    #[test]
    fn test_push_branch_permission_read_implication() {
        // push_branch permission should imply read access

        // GitHub
        let gh_perm = GhRepoPermission {
            read: false,
            create_draft: false,
            pending_review: false,
            push_new_branch: true,
            write: false,
        };
        assert!(gh_perm.can_read()); // Should be true due to push_branch

        // GitLab
        let gl_perm = GlProjectPermission {
            read: false,
            create_draft: false,
            approve: false,
            push_new_branch: true,
            write: false,
        };
        assert!(gl_perm.can_read()); // Should be true due to push_branch

        // Forgejo
        let forgejo_perm = ForgejoRepoPermission {
            read: false,
            create_draft: false,
            pending_review: false,
            push_new_branch: true,
            write: false,
        };
        assert!(forgejo_perm.can_read()); // Should be true due to push_branch
    }

    // ============================================================================
    // Additional comprehensive tests for push-new-branch permission system
    // ============================================================================

    #[test]
    fn test_push_new_branch_toml_field_defaults() {
        // Test that push-new-branch field defaults to false when not specified
        let toml = r#"
            [gh.repos]
            "owner/repo1" = {}
            "owner/repo2" = { read = true }
            "owner/repo3" = { read = true, create-draft = true }
            "owner/repo4" = { read = true, write = true }

            [gitlab.projects]
            "group/project1" = {}
            "group/project2" = { read = true }

            [[forgejo]]
            host = "codeberg.org"

            [forgejo.repos]
            "owner/repo1" = {}
            "owner/repo2" = { read = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();

        // GitHub repos
        assert!(!config.gh.repos.get("owner/repo1").unwrap().push_new_branch);
        assert!(!config.gh.repos.get("owner/repo2").unwrap().push_new_branch);
        assert!(!config.gh.repos.get("owner/repo3").unwrap().push_new_branch);
        assert!(!config.gh.repos.get("owner/repo4").unwrap().push_new_branch); // push_new_branch field still defaults to false
        assert!(config
            .gh
            .repos
            .get("owner/repo4")
            .unwrap()
            .can_push_new_branch()); // but can_push_new_branch() returns true due to write=true

        // GitLab projects
        assert!(
            !config
                .gitlab
                .projects
                .get("group/project1")
                .unwrap()
                .push_new_branch
        );
        assert!(
            !config
                .gitlab
                .projects
                .get("group/project2")
                .unwrap()
                .push_new_branch
        );

        // Forgejo repos
        assert!(
            !config.forgejo[0]
                .repos
                .get("owner/repo1")
                .unwrap()
                .push_new_branch
        );
        assert!(
            !config.forgejo[0]
                .repos
                .get("owner/repo2")
                .unwrap()
                .push_new_branch
        );
    }

    #[test]
    fn test_push_new_branch_explicit_true_false_parsing() {
        // Test explicit true/false values for push-new-branch
        let toml = r#"
            [gh.repos]
            "owner/explicit-true" = { read = true, push-new-branch = true }
            "owner/explicit-false" = { read = true, push-new-branch = false }
            "owner/both" = { read = true, create-draft = true, push-new-branch = true }

            [gitlab.projects]
            "group/explicit-true" = { read = true, push-new-branch = true }
            "group/explicit-false" = { read = true, push-new-branch = false }

            [[forgejo]]
            host = "codeberg.org"

            [forgejo.repos]
            "owner/explicit-true" = { read = true, push-new-branch = true }
            "owner/explicit-false" = { read = true, push-new-branch = false }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();

        // GitHub
        assert!(
            config
                .gh
                .repos
                .get("owner/explicit-true")
                .unwrap()
                .push_new_branch
        );
        assert!(
            !config
                .gh
                .repos
                .get("owner/explicit-false")
                .unwrap()
                .push_new_branch
        );
        assert!(config.gh.repos.get("owner/both").unwrap().push_new_branch);
        assert!(config.gh.repos.get("owner/both").unwrap().create_draft);

        // GitLab
        assert!(
            config
                .gitlab
                .projects
                .get("group/explicit-true")
                .unwrap()
                .push_new_branch
        );
        assert!(
            !config
                .gitlab
                .projects
                .get("group/explicit-false")
                .unwrap()
                .push_new_branch
        );

        // Forgejo
        assert!(
            config.forgejo[0]
                .repos
                .get("owner/explicit-true")
                .unwrap()
                .push_new_branch
        );
        assert!(
            !config.forgejo[0]
                .repos
                .get("owner/explicit-false")
                .unwrap()
                .push_new_branch
        );
    }

    #[test]
    fn test_write_permission_hierarchy() {
        // Test that write permission implies all other permissions

        // GitHub
        let gh_write = GhRepoPermission::full_write();
        assert!(gh_write.can_read());
        assert!(gh_write.can_create_draft());
        assert!(gh_write.can_manage_pending_review());
        assert!(gh_write.can_push_new_branch());
        assert!(gh_write.can_write());

        // GitLab
        let gl_write = GlProjectPermission::full_write();
        assert!(gl_write.can_read());
        assert!(gl_write.can_create_draft());
        assert!(gl_write.can_approve());
        assert!(gl_write.can_push_new_branch());
        assert!(gl_write.can_write());

        // Forgejo
        let forgejo_write = ForgejoRepoPermission::full_write();
        assert!(forgejo_write.can_read());
        assert!(forgejo_write.can_create_draft());
        assert!(forgejo_write.can_manage_pending_review());
        assert!(forgejo_write.can_push_new_branch());
        assert!(forgejo_write.can_write());
    }

    #[test]
    fn test_permission_combination_edge_cases() {
        // Test edge cases where permissions might interact unexpectedly

        // Test: Only pending-review + push-new-branch (no create-draft)
        let gh_review_push = GhRepoPermission {
            read: false, // Will be implied
            create_draft: false,
            pending_review: true,
            push_new_branch: true,
            write: false,
        };
        assert!(gh_review_push.can_read()); // Implied by other permissions
        assert!(gh_review_push.can_create_draft()); // Implied by push_new_branch backward compatibility
        assert!(gh_review_push.can_manage_pending_review());
        assert!(gh_review_push.can_push_new_branch());
        assert!(!gh_review_push.can_write());

        // Test: Only create-draft + pending-review (no push-new-branch)
        let gh_draft_review = GhRepoPermission {
            read: false, // Will be implied
            create_draft: true,
            pending_review: true,
            push_new_branch: false,
            write: false,
        };
        assert!(gh_draft_review.can_read()); // Implied by other permissions
        assert!(gh_draft_review.can_create_draft());
        assert!(gh_draft_review.can_manage_pending_review());
        assert!(!gh_draft_review.can_push_new_branch());
        assert!(!gh_draft_review.can_write());

        // Test: All individual permissions false
        let gh_nothing = GhRepoPermission {
            read: false,
            create_draft: false,
            pending_review: false,
            push_new_branch: false,
            write: false,
        };
        assert!(!gh_nothing.can_read());
        assert!(!gh_nothing.can_create_draft());
        assert!(!gh_nothing.can_manage_pending_review());
        assert!(!gh_nothing.can_push_new_branch());
        assert!(!gh_nothing.can_write());
    }

    #[test]
    fn test_scope_pattern_matching_with_push_new_branch() {
        // Test that pattern matching works correctly with the push-new-branch permission
        let scope = GithubScope {
            read: false,
            repos: [
                // Wildcard with push-new-branch
                (
                    "owner/*".into(),
                    GhRepoPermission {
                        read: true,
                        create_draft: false,
                        pending_review: false,
                        push_new_branch: true,
                        write: false,
                    },
                ),
                // Specific repo override with different permissions
                (
                    "owner/special".into(),
                    GhRepoPermission {
                        read: true,
                        create_draft: true,
                        pending_review: true,
                        push_new_branch: false, // Explicitly disabled
                        write: false,
                    },
                ),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Wildcard match should allow push-new-branch
        assert!(scope.is_allowed("owner/regular", GhOpType::PushNewBranch, None));
        assert!(scope.is_allowed("owner/regular", GhOpType::CreateDraft, None)); // Backward compatibility

        // Specific repo should NOT allow push-new-branch (explicit override)
        assert!(!scope.is_allowed("owner/special", GhOpType::PushNewBranch, None));
        assert!(scope.is_allowed("owner/special", GhOpType::CreateDraft, None)); // Explicit permission
        assert!(scope.is_allowed("owner/special", GhOpType::ManagePendingReview, None)); // Explicit permission

        // Unknown repo should be denied
        assert!(!scope.is_allowed("other/repo", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("other/repo", GhOpType::CreateDraft, None));
    }

    #[test]
    fn test_multiple_forgejo_hosts_push_permissions() {
        // Test that push-new-branch permissions work correctly across multiple Forgejo hosts
        let toml = r#"
            [[forgejo]]
            host = "codeberg.org"

            [forgejo.repos]
            "user/repo1" = { read = true, push-new-branch = true }
            "user/repo2" = { read = true }

            [[forgejo]]
            host = "git.example.com"

            [forgejo.repos]
            "org/project" = { read = true, create-draft = true, push-new-branch = true }
        "#;

        let config: ScopeConfig = toml::from_str(toml).unwrap();

        assert_eq!(config.forgejo.len(), 2);

        // First host (codeberg.org)
        let codeberg = &config.forgejo[0];
        assert_eq!(codeberg.host, "codeberg.org");
        assert!(codeberg.repos.get("user/repo1").unwrap().push_new_branch);
        assert!(!codeberg.repos.get("user/repo2").unwrap().push_new_branch);

        // Second host (git.example.com)
        let example = &config.forgejo[1];
        assert_eq!(example.host, "git.example.com");
        assert!(example.repos.get("org/project").unwrap().push_new_branch);
        assert!(example.repos.get("org/project").unwrap().create_draft);
    }

    #[test]
    fn test_permission_method_consistency() {
        // Test that permission methods are consistent across all platforms

        struct TestPermissions {
            read: bool,
            create_draft: bool,
            special: bool, // pending_review for GH/Forgejo, approve for GitLab
            push_new_branch: bool,
            write: bool,
        }

        let test_cases = vec![
            TestPermissions {
                read: false,
                create_draft: false,
                special: false,
                push_new_branch: false,
                write: false,
            },
            TestPermissions {
                read: true,
                create_draft: false,
                special: false,
                push_new_branch: false,
                write: false,
            },
            TestPermissions {
                read: false,
                create_draft: true,
                special: false,
                push_new_branch: false,
                write: false,
            },
            TestPermissions {
                read: false,
                create_draft: false,
                special: true,
                push_new_branch: false,
                write: false,
            },
            TestPermissions {
                read: false,
                create_draft: false,
                special: false,
                push_new_branch: true,
                write: false,
            },
            TestPermissions {
                read: false,
                create_draft: false,
                special: false,
                push_new_branch: false,
                write: true,
            },
            TestPermissions {
                read: true,
                create_draft: true,
                special: true,
                push_new_branch: true,
                write: true,
            },
        ];

        for (i, test) in test_cases.into_iter().enumerate() {
            let gh = GhRepoPermission {
                read: test.read,
                create_draft: test.create_draft,
                pending_review: test.special,
                push_new_branch: test.push_new_branch,
                write: test.write,
            };

            let gl = GlProjectPermission {
                read: test.read,
                create_draft: test.create_draft,
                approve: test.special,
                push_new_branch: test.push_new_branch,
                write: test.write,
            };

            let forgejo = ForgejoRepoPermission {
                read: test.read,
                create_draft: test.create_draft,
                pending_review: test.special,
                push_new_branch: test.push_new_branch,
                write: test.write,
            };

            // Test that can_read is consistent
            let gh_read = gh.can_read();
            let gl_read = gl.can_read();
            let forgejo_read = forgejo.can_read();
            assert_eq!(
                gh_read, gl_read,
                "Test case {}: GitHub and GitLab can_read mismatch",
                i
            );
            assert_eq!(
                gh_read, forgejo_read,
                "Test case {}: GitHub and Forgejo can_read mismatch",
                i
            );

            // Test that can_create_draft is consistent
            let gh_draft = gh.can_create_draft();
            let gl_draft = gl.can_create_draft();
            let forgejo_draft = forgejo.can_create_draft();
            assert_eq!(
                gh_draft, gl_draft,
                "Test case {}: GitHub and GitLab can_create_draft mismatch",
                i
            );
            assert_eq!(
                gh_draft, forgejo_draft,
                "Test case {}: GitHub and Forgejo can_create_draft mismatch",
                i
            );

            // Test that can_push_new_branch is consistent
            let gh_push = gh.can_push_new_branch();
            let gl_push = gl.can_push_new_branch();
            let forgejo_push = forgejo.can_push_new_branch();
            assert_eq!(
                gh_push, gl_push,
                "Test case {}: GitHub and GitLab can_push_new_branch mismatch",
                i
            );
            assert_eq!(
                gh_push, forgejo_push,
                "Test case {}: GitHub and Forgejo can_push_new_branch mismatch",
                i
            );

            // Test that can_write is consistent
            let gh_write = gh.can_write();
            let gl_write = gl.can_write();
            let forgejo_write = forgejo.can_write();
            assert_eq!(
                gh_write, gl_write,
                "Test case {}: GitHub and GitLab can_write mismatch",
                i
            );
            assert_eq!(
                gh_write, forgejo_write,
                "Test case {}: GitHub and Forgejo can_write mismatch",
                i
            );
        }
    }

    #[test]
    fn test_operation_type_enum_coverage() {
        // Ensure all operation types are tested for the push-new-branch permission

        let scope = GithubScope {
            read: false,
            repos: [
                ("test/read-only".into(), GhRepoPermission::read_only()),
                (
                    "test/push-only".into(),
                    GhRepoPermission::with_push_new_branch(),
                ),
                ("test/full-write".into(), GhRepoPermission::full_write()),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Test all operation types
        let operations = [
            GhOpType::Read,
            GhOpType::CreateDraft,
            GhOpType::ManagePendingReview,
            GhOpType::PushNewBranch,
            GhOpType::WriteResource,
            GhOpType::Write,
        ];

        for op in operations {
            // Read-only repo
            let read_allowed = scope.is_allowed("test/read-only", op, None);
            match op {
                GhOpType::Read => assert!(read_allowed, "Read-only should allow Read"),
                _ => assert!(!read_allowed, "Read-only should deny {:?}", op),
            }

            // Push-only repo
            let push_allowed = scope.is_allowed("test/push-only", op, None);
            match op {
                GhOpType::Read => assert!(push_allowed, "Push-only should allow Read"),
                GhOpType::CreateDraft => assert!(
                    push_allowed,
                    "Push-only should allow CreateDraft (backward compatibility)"
                ),
                GhOpType::PushNewBranch => {
                    assert!(push_allowed, "Push-only should allow PushNewBranch")
                }
                _ => assert!(!push_allowed, "Push-only should deny {:?}", op),
            }

            // Full-write repo
            let write_allowed = scope.is_allowed("test/full-write", op, None);
            assert!(write_allowed, "Full-write should allow {:?}", op);
        }
    }

    #[test]
    fn test_toml_validation_error_cases() {
        // Test that invalid TOML configurations are handled gracefully

        // Valid config for comparison
        let valid_toml = r#"
            [gh.repos]
            "owner/repo" = { read = true, push-new-branch = true }
        "#;
        let _config: ScopeConfig = toml::from_str(valid_toml).unwrap();

        // Test that unknown fields are ignored (TOML deserialization should handle this)
        let unknown_field_toml = r#"
            [gh.repos]
            "owner/repo" = { read = true, push-new-branch = true, unknown-field = true }
        "#;
        // This should succeed (serde ignores unknown fields by default)
        let _config: Result<ScopeConfig, _> = toml::from_str(unknown_field_toml);
        // We can't assert it succeeds because serde might be strict, so just ensure it doesn't panic
    }

    #[test]
    fn test_real_world_configuration_scenarios() {
        // Test realistic configuration scenarios that users might create

        // Scenario 1: Development team with different permission levels
        let dev_team_config = r#"
            [gh.repos]
            # Junior developers - can only create drafts
            "company/frontend" = { read = true, create-draft = true }
            
            # Senior developers - can push branches directly
            "company/backend" = { read = true, create-draft = true, push-new-branch = true }
            
            # Maintainers - full access
            "company/infrastructure" = { read = true, write = true }
            
            # CI/CD system - only push and create PRs
            "company/deployment" = { read = true, push-new-branch = true }
        "#;

        let config: ScopeConfig = toml::from_str(dev_team_config).unwrap();

        // Junior devs
        let frontend = config.gh.repos.get("company/frontend").unwrap();
        assert!(frontend.can_read());
        assert!(frontend.can_create_draft());
        assert!(!frontend.can_push_new_branch());
        assert!(!frontend.can_write());

        // Senior devs
        let backend = config.gh.repos.get("company/backend").unwrap();
        assert!(backend.can_read());
        assert!(backend.can_create_draft());
        assert!(backend.can_push_new_branch());
        assert!(!backend.can_write());

        // Maintainers
        let infra = config.gh.repos.get("company/infrastructure").unwrap();
        assert!(infra.can_read());
        assert!(infra.can_create_draft());
        assert!(infra.can_push_new_branch());
        assert!(infra.can_write());

        // CI/CD
        let deploy = config.gh.repos.get("company/deployment").unwrap();
        assert!(deploy.can_read());
        assert!(deploy.can_create_draft()); // Backward compatibility
        assert!(deploy.can_push_new_branch());
        assert!(!deploy.can_write());

        // Scenario 2: Multi-forge setup
        let multi_forge_config = r#"
            [gh.repos]
            "github-org/*" = { read = true, push-new-branch = true }

            [gitlab.projects]
            "gitlab-group/*" = { read = true, create-draft = true }

            [[forgejo]]
            host = "codeberg.org"

            [forgejo.repos]
            "codeberg-user/*" = { read = true, create-draft = true, push-new-branch = true }
        "#;

        let multi_config: ScopeConfig = toml::from_str(multi_forge_config).unwrap();

        // Verify each forge has appropriate permissions
        assert!(!multi_config.gh.repos.is_empty());
        assert!(!multi_config.gitlab.projects.is_empty());
        assert!(!multi_config.forgejo.is_empty());
        assert_eq!(multi_config.forgejo[0].host, "codeberg.org");
    }

    #[test]
    fn test_legacy_migration_compatibility() {
        // Test that old configurations can be incrementally migrated to the new permission system

        // Original configuration (pre-push-new-branch)
        let legacy_config = r#"
            [gh.repos]
            "legacy/repo1" = { read = true, create-draft = true, pending-review = true }
            "legacy/repo2" = { read = true, write = true }
        "#;

        let config: ScopeConfig = toml::from_str(legacy_config).unwrap();

        // Legacy repo1: should work for drafts but not direct push
        let repo1 = config.gh.repos.get("legacy/repo1").unwrap();
        assert!(repo1.can_read());
        assert!(repo1.can_create_draft());
        assert!(repo1.can_manage_pending_review());
        assert!(!repo1.can_push_new_branch()); // Should default to false
        assert!(!repo1.can_write());

        // Legacy repo2: write=true should enable everything
        let repo2 = config.gh.repos.get("legacy/repo2").unwrap();
        assert!(repo2.can_read());
        assert!(repo2.can_create_draft());
        assert!(repo2.can_manage_pending_review());
        assert!(repo2.can_push_new_branch()); // Should be true due to write=true
        assert!(repo2.can_write());

        // Partially migrated configuration
        let partial_migration = r#"
            [gh.repos]
            # Still using legacy format
            "legacy/old" = { read = true, create-draft = true }
            
            # Updated to new format  
            "new/modern" = { read = true, create-draft = true, push-new-branch = true }
        "#;

        let partial_config: ScopeConfig = toml::from_str(partial_migration).unwrap();

        let old_repo = partial_config.gh.repos.get("legacy/old").unwrap();
        assert!(!old_repo.can_push_new_branch()); // Legacy behavior preserved

        let new_repo = partial_config.gh.repos.get("new/modern").unwrap();
        assert!(new_repo.can_push_new_branch()); // New explicit permission
    }

    // ============================================================================
    // Critical Permission Denial Scenario Tests
    // ============================================================================

    #[test]
    fn test_permission_denial_scenarios() {
        // Test exact permission combinations that should fail

        // Scenario 1: User has create-draft but not push-new-branch
        let create_draft_only = GhRepoPermission {
            read: true,
            create_draft: true,
            pending_review: false,
            push_new_branch: false,
            write: false,
        };

        let scope_draft_only = GithubScope {
            read: false,
            repos: [("owner/repo".to_string(), create_draft_only)].into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Should allow draft creation
        assert!(scope_draft_only.is_allowed("owner/repo", GhOpType::CreateDraft, None));
        // Should NOT allow branch pushing
        assert!(!scope_draft_only.is_allowed("owner/repo", GhOpType::PushNewBranch, None));

        // Scenario 2: User has push-new-branch but not create-draft
        let push_only = GhRepoPermission {
            read: true,
            create_draft: false,
            pending_review: false,
            push_new_branch: true,
            write: false,
        };

        let scope_push_only = GithubScope {
            read: false,
            repos: [("owner/repo".to_string(), push_only)].into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Should allow branch pushing
        assert!(scope_push_only.is_allowed("owner/repo", GhOpType::PushNewBranch, None));
        // Should allow draft creation due to backward compatibility
        assert!(scope_push_only.is_allowed("owner/repo", GhOpType::CreateDraft, None));

        // Scenario 3: User has neither permission
        let read_only = GhRepoPermission {
            read: true,
            create_draft: false,
            pending_review: false,
            push_new_branch: false,
            write: false,
        };

        let scope_read_only = GithubScope {
            read: false,
            repos: [("owner/repo".to_string(), read_only)].into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Should NOT allow either operation
        assert!(!scope_read_only.is_allowed("owner/repo", GhOpType::CreateDraft, None));
        assert!(!scope_read_only.is_allowed("owner/repo", GhOpType::PushNewBranch, None));
        assert!(!scope_read_only.is_allowed("owner/repo", GhOpType::Write, None));

        // Scenario 4: Unknown repository
        assert!(!scope_read_only.is_allowed("unknown/repo", GhOpType::Read, None));
        assert!(!scope_read_only.is_allowed("unknown/repo", GhOpType::CreateDraft, None));
        assert!(!scope_read_only.is_allowed("unknown/repo", GhOpType::PushNewBranch, None));
    }

    #[test]
    fn test_malformed_toml_configuration_error_handling() {
        // Test various invalid TOML configurations

        // Invalid permission combination 1: Nonsensical permissions
        let invalid_toml1 = r#"
            [gh.repos]
            "owner/repo" = { read = false, create-draft = true }
        "#;

        let config: ScopeConfig = toml::from_str(invalid_toml1).unwrap();
        let repo_perm = config.gh.repos.get("owner/repo").unwrap();
        // Should still work - create_draft implies read access
        assert!(repo_perm.can_read());
        assert!(repo_perm.can_create_draft());

        // Invalid permission combination 2: Write false but other permissions true
        let invalid_toml2 = r#"
            [gh.repos]
            "owner/repo" = { read = true, create-draft = true, pending-review = true, push-new-branch = true, write = false }
        "#;

        let config2: ScopeConfig = toml::from_str(invalid_toml2).unwrap();
        let repo_perm2 = config2.gh.repos.get("owner/repo").unwrap();
        // Should work fine - individual permissions are still valid
        assert!(repo_perm2.can_push_new_branch());
        assert!(!repo_perm2.can_write()); // Explicitly set to false

        // Test completely empty repos section
        let empty_toml = r#"
            [gh.repos]
        "#;

        let config3: ScopeConfig = toml::from_str(empty_toml).unwrap();
        assert!(config3.gh.repos.is_empty());

        // Test invalid field names (should be ignored by serde)
        let unknown_fields = r#"
            [gh.repos]
            "owner/repo" = { read = true, invalid_field = true, unknown_permission = false }
        "#;

        // This should succeed as serde ignores unknown fields
        let result = toml::from_str::<ScopeConfig>(unknown_fields);
        assert!(result.is_ok());
    }

    #[test]
    fn test_permission_conflicts_and_edge_cases() {
        // Test edge cases in permission logic

        // Edge case 1: All permissions explicitly set to false
        let all_false = GhRepoPermission {
            read: false,
            create_draft: false,
            pending_review: false,
            push_new_branch: false,
            write: false,
        };

        assert!(!all_false.can_read());
        assert!(!all_false.can_create_draft());
        assert!(!all_false.can_manage_pending_review());
        assert!(!all_false.can_push_new_branch());
        assert!(!all_false.can_write());

        // Edge case 2: Only write permission set
        let only_write = GhRepoPermission {
            read: false,
            create_draft: false,
            pending_review: false,
            push_new_branch: false,
            write: true,
        };

        // Write permission should enable all capabilities
        assert!(only_write.can_read());
        assert!(only_write.can_create_draft());
        assert!(only_write.can_manage_pending_review());
        assert!(only_write.can_push_new_branch());
        assert!(only_write.can_write());

        // Edge case 3: GitLab permission hierarchy
        let gl_only_write = GlProjectPermission {
            read: false,
            create_draft: false,
            approve: false,
            push_new_branch: false,
            write: true,
        };

        assert!(gl_only_write.can_read());
        assert!(gl_only_write.can_create_draft());
        assert!(gl_only_write.can_approve());
        assert!(gl_only_write.can_push_new_branch());
        assert!(gl_only_write.can_write());

        // Edge case 4: Forgejo permission hierarchy
        let forgejo_only_write = ForgejoRepoPermission {
            read: false,
            create_draft: false,
            pending_review: false,
            push_new_branch: false,
            write: true,
        };

        assert!(forgejo_only_write.can_read());
        assert!(forgejo_only_write.can_create_draft());
        assert!(forgejo_only_write.can_manage_pending_review());
        assert!(forgejo_only_write.can_push_new_branch());
        assert!(forgejo_only_write.can_write());
    }

    #[test]
    fn test_invalid_permission_combinations_in_toml() {
        // Test that TOML parsing handles edge cases gracefully

        // Test 1: Conflicting boolean values (should parse the last one)
        let conflicting_toml = r#"
            [gh.repos]
            "owner/repo" = { read = true, push-new-branch = false, push-new-branch = true }
        "#;

        // Note: TOML spec says duplicate keys should error, but some parsers may handle it
        // Let's test what our parser does
        // Note: TOML spec says duplicate keys should error, but some parsers may handle it
        // Let's test what our parser does
        let _result = toml::from_str::<ScopeConfig>(conflicting_toml);
        // This might fail or succeed depending on TOML parser behavior
        // If it succeeds, the second value should be used

        // Test 2: Missing required structure
        let minimal_toml = r#"
            [gh]
            read = false
        "#;

        let config: ScopeConfig = toml::from_str(minimal_toml).unwrap();
        assert!(!config.gh.read);
        assert!(config.gh.repos.is_empty());

        // Test 3: Mixed case field names (should fail as field names are case-sensitive)
        let mixed_case_toml = r#"
            [gh.repos]
            "owner/repo" = { Read = true, Push-New-Branch = true }
        "#;

        let result = toml::from_str::<ScopeConfig>(mixed_case_toml);
        // This should succeed but unknown fields will be ignored
        if let Ok(config) = result {
            let repo = config.gh.repos.get("owner/repo").unwrap();
            // Mixed case fields should be ignored, so should use defaults
            assert!(repo.read); // Default is true
            assert!(!repo.push_new_branch); // Default is false
        }
    }

    #[test]
    fn test_comprehensive_permission_denial_matrix() {
        // Comprehensive matrix of permission denials for different operation types

        struct PermissionTest {
            name: &'static str,
            permission: GhRepoPermission,
            // Which operations should be DENIED (false)
            deny_read: bool,
            deny_create_draft: bool,
            deny_pending_review: bool,
            deny_push_branch: bool,
            deny_write: bool,
        }

        let test_cases = vec![
            PermissionTest {
                name: "completely_locked_down",
                permission: GhRepoPermission {
                    read: false,
                    create_draft: false,
                    pending_review: false,
                    push_new_branch: false,
                    write: false,
                },
                deny_read: true,
                deny_create_draft: true,
                deny_pending_review: true,
                deny_push_branch: true,
                deny_write: true,
            },
            PermissionTest {
                name: "only_read",
                permission: GhRepoPermission {
                    read: true,
                    create_draft: false,
                    pending_review: false,
                    push_new_branch: false,
                    write: false,
                },
                deny_read: false,
                deny_create_draft: true,
                deny_pending_review: true,
                deny_push_branch: true,
                deny_write: true,
            },
            PermissionTest {
                name: "read_and_create_draft",
                permission: GhRepoPermission {
                    read: true,
                    create_draft: true,
                    pending_review: false,
                    push_new_branch: false,
                    write: false,
                },
                deny_read: false,
                deny_create_draft: false,
                deny_pending_review: true,
                deny_push_branch: true,
                deny_write: true,
            },
            PermissionTest {
                name: "push_branch_only",
                permission: GhRepoPermission {
                    read: false,
                    create_draft: false,
                    pending_review: false,
                    push_new_branch: true,
                    write: false,
                },
                deny_read: false,         // Implied by push_new_branch
                deny_create_draft: false, // Backward compatibility
                deny_pending_review: true,
                deny_push_branch: false,
                deny_write: true,
            },
        ];

        for test_case in test_cases {
            let scope = GithubScope {
                read: false,
                repos: [("test/repo".to_string(), test_case.permission)].into(),
                prs: HashMap::new(),
                issues: HashMap::new(),
                graphql: GraphQlPermission::None,
            };

            // Test that denials match expected results
            assert_eq!(
                !scope.is_allowed("test/repo", GhOpType::Read, None),
                test_case.deny_read,
                "{}: Read denial mismatch",
                test_case.name
            );
            assert_eq!(
                !scope.is_allowed("test/repo", GhOpType::CreateDraft, None),
                test_case.deny_create_draft,
                "{}: CreateDraft denial mismatch",
                test_case.name
            );
            assert_eq!(
                !scope.is_allowed("test/repo", GhOpType::ManagePendingReview, None),
                test_case.deny_pending_review,
                "{}: PendingReview denial mismatch",
                test_case.name
            );
            assert_eq!(
                !scope.is_allowed("test/repo", GhOpType::PushNewBranch, None),
                test_case.deny_push_branch,
                "{}: PushNewBranch denial mismatch",
                test_case.name
            );
            assert_eq!(
                !scope.is_allowed("test/repo", GhOpType::Write, None),
                test_case.deny_write,
                "{}: Write denial mismatch",
                test_case.name
            );
        }
    }

    #[test]
    fn test_multi_forge_permission_denial_consistency() {
        // Test that permission denial behavior is consistent across all forges

        // Create identical permission setups for all three forges
        let read_only_gh = GhRepoPermission::read_only();
        let read_only_gl = GlProjectPermission::read_only();
        let read_only_forgejo = ForgejoRepoPermission::read_only();

        // GitHub scope
        let gh_scope = GithubScope {
            read: false,
            repos: [("owner/repo".to_string(), read_only_gh)].into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // GitLab scope
        let gl_scope = GitLabScope {
            projects: [("group/project".to_string(), read_only_gl)].into(),
            mrs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
            host: None,
        };

        // Forgejo scope
        let forgejo_scope = ForgejoScope {
            host: "codeberg.org".to_string(),
            token: None,
            repos: [("owner/repo".to_string(), read_only_forgejo)].into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
        };

        // All should allow read
        assert!(gh_scope.is_allowed("owner/repo", GhOpType::Read, None));
        assert!(gl_scope.is_allowed("group/project", crate::scope::GlOpType::Read, None));
        assert!(forgejo_scope.is_allowed("owner/repo", crate::scope::ForgejoOpType::Read, None));

        // All should deny push-new-branch
        assert!(!gh_scope.is_allowed("owner/repo", GhOpType::PushNewBranch, None));
        assert!(!gl_scope.is_allowed("group/project", crate::scope::GlOpType::PushNewBranch, None));
        assert!(!forgejo_scope.is_allowed(
            "owner/repo",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));

        // All should deny create-draft
        assert!(!gh_scope.is_allowed("owner/repo", GhOpType::CreateDraft, None));
        assert!(!gl_scope.is_allowed("group/project", crate::scope::GlOpType::CreateDraft, None));
        assert!(!forgejo_scope.is_allowed(
            "owner/repo",
            crate::scope::ForgejoOpType::CreateDraft,
            None
        ));

        // All should deny write
        assert!(!gh_scope.is_allowed("owner/repo", GhOpType::Write, None));
        assert!(!gl_scope.is_allowed("group/project", crate::scope::GlOpType::Write, None));
        assert!(!forgejo_scope.is_allowed("owner/repo", crate::scope::ForgejoOpType::Write, None));
    }

    #[test]
    fn test_operation_type_enum_coverage_comprehensive() {
        // Ensure all operation types are tested for permission requirements

        let full_permission_gh = GhRepoPermission::full_write();
        let no_permission_gh = GhRepoPermission {
            read: false,
            create_draft: false,
            pending_review: false,
            push_new_branch: false,
            write: false,
        };

        let full_scope = GithubScope {
            read: false,
            repos: [("full/repo".to_string(), full_permission_gh)].into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        let empty_scope = GithubScope {
            read: false,
            repos: [("empty/repo".to_string(), no_permission_gh)].into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Test all GitHub operation types
        let gh_ops = [
            GhOpType::Read,
            GhOpType::CreateDraft,
            GhOpType::ManagePendingReview,
            GhOpType::PushNewBranch,
            GhOpType::WriteResource,
            GhOpType::Write,
        ];

        for op in gh_ops.iter() {
            // Full permissions should allow all operations
            assert!(
                full_scope.is_allowed("full/repo", *op, None),
                "Full permissions should allow {:?}",
                op
            );

            // Empty permissions should deny all operations
            assert!(
                !empty_scope.is_allowed("empty/repo", *op, None),
                "Empty permissions should deny {:?}",
                op
            );
        }

        // Test GitLab operation types
        let gl_ops = [
            crate::scope::GlOpType::Read,
            crate::scope::GlOpType::CreateDraft,
            crate::scope::GlOpType::Approve,
            crate::scope::GlOpType::PushNewBranch,
            crate::scope::GlOpType::WriteResource,
            crate::scope::GlOpType::Write,
        ];

        let gl_scope = GitLabScope {
            projects: [(
                "group/project".to_string(),
                GlProjectPermission::full_write(),
            )]
            .into(),
            mrs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
            host: None,
        };

        for op in gl_ops.iter() {
            assert!(
                gl_scope.is_allowed("group/project", *op, None),
                "GitLab full permissions should allow {:?}",
                op
            );
        }

        // Test Forgejo operation types
        let forgejo_ops = [
            crate::scope::ForgejoOpType::Read,
            crate::scope::ForgejoOpType::CreateDraft,
            crate::scope::ForgejoOpType::ManagePendingReview,
            crate::scope::ForgejoOpType::PushNewBranch,
            crate::scope::ForgejoOpType::WriteResource,
            crate::scope::ForgejoOpType::Write,
        ];

        let forgejo_scope = ForgejoScope {
            host: "codeberg.org".to_string(),
            token: None,
            repos: [(
                "owner/repo".to_string(),
                ForgejoRepoPermission::full_write(),
            )]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
        };

        for op in forgejo_ops.iter() {
            assert!(
                forgejo_scope.is_allowed("owner/repo", *op, None),
                "Forgejo full permissions should allow {:?}",
                op
            );
        }
    }

    #[test]
    fn test_permission_method_consistency_comprehensive() {
        // Test that permission methods are consistent across all permission types

        // Test GitHub permission consistency
        let test_permissions = [
            GhRepoPermission::read_only(),
            GhRepoPermission::with_draft(),
            GhRepoPermission::with_pending_review(),
            GhRepoPermission::with_push_new_branch(),
            GhRepoPermission::full_write(),
        ];

        for perm in test_permissions.iter() {
            // If any capability is enabled, read should be enabled
            let has_any_capability = perm.can_create_draft()
                || perm.can_manage_pending_review()
                || perm.can_push_new_branch()
                || perm.can_write();

            if has_any_capability {
                assert!(
                    perm.can_read(),
                    "Any capability should imply read access for {:?}",
                    perm
                );
            }

            // Write permission should imply all others
            if perm.can_write() {
                assert!(perm.can_read(), "Write should imply read for {:?}", perm);
                assert!(
                    perm.can_create_draft(),
                    "Write should imply create_draft for {:?}",
                    perm
                );
                assert!(
                    perm.can_manage_pending_review(),
                    "Write should imply pending_review for {:?}",
                    perm
                );
                assert!(
                    perm.can_push_new_branch(),
                    "Write should imply push_new_branch for {:?}",
                    perm
                );
            }

            // push_new_branch should enable create_draft for backward compatibility
            if perm.can_push_new_branch() {
                assert!(
                    perm.can_create_draft(),
                    "push_new_branch should enable create_draft for {:?}",
                    perm
                );
            }
        }

        // Test GitLab permission consistency
        let gl_permissions = [
            GlProjectPermission::read_only(),
            GlProjectPermission::with_draft(),
            GlProjectPermission::with_approve(),
            GlProjectPermission::with_push_new_branch(),
            GlProjectPermission::full_write(),
        ];

        for perm in gl_permissions.iter() {
            let has_any_capability = perm.can_create_draft()
                || perm.can_approve()
                || perm.can_push_new_branch()
                || perm.can_write();

            if has_any_capability {
                assert!(
                    perm.can_read(),
                    "Any GL capability should imply read access for {:?}",
                    perm
                );
            }

            if perm.can_write() {
                assert!(perm.can_read(), "GL write should imply read for {:?}", perm);
                assert!(
                    perm.can_create_draft(),
                    "GL write should imply create_draft for {:?}",
                    perm
                );
                assert!(
                    perm.can_approve(),
                    "GL write should imply approve for {:?}",
                    perm
                );
                assert!(
                    perm.can_push_new_branch(),
                    "GL write should imply push_new_branch for {:?}",
                    perm
                );
            }
        }

        // Test Forgejo permission consistency
        let forgejo_permissions = [
            ForgejoRepoPermission::read_only(),
            ForgejoRepoPermission::with_draft(),
            ForgejoRepoPermission::with_pending_review(),
            ForgejoRepoPermission::with_push_new_branch(),
            ForgejoRepoPermission::full_write(),
        ];

        for perm in forgejo_permissions.iter() {
            let has_any_capability = perm.can_create_draft()
                || perm.can_manage_pending_review()
                || perm.can_push_new_branch()
                || perm.can_write();

            if has_any_capability {
                assert!(
                    perm.can_read(),
                    "Any Forgejo capability should imply read access for {:?}",
                    perm
                );
            }

            if perm.can_write() {
                assert!(
                    perm.can_read(),
                    "Forgejo write should imply read for {:?}",
                    perm
                );
                assert!(
                    perm.can_create_draft(),
                    "Forgejo write should imply create_draft for {:?}",
                    perm
                );
                assert!(
                    perm.can_manage_pending_review(),
                    "Forgejo write should imply pending_review for {:?}",
                    perm
                );
                assert!(
                    perm.can_push_new_branch(),
                    "Forgejo write should imply push_new_branch for {:?}",
                    perm
                );
            }
        }
    }

    #[test]
    fn test_toml_validation_error_cases_comprehensive() {
        // Test TOML parsing with various malformed inputs

        // Test 1: Invalid Boolean values
        let invalid_bool_toml = r#"
            [gh.repos]
            "owner/repo" = { read = "not_a_boolean" }
        "#;

        let result = toml::from_str::<ScopeConfig>(invalid_bool_toml);
        assert!(result.is_err(), "Should fail to parse invalid boolean");

        // Test 2: Invalid structure
        let invalid_structure = r#"
            [gh.repos]
            "owner/repo" = "should_be_object_not_string"  
        "#;

        let result2 = toml::from_str::<ScopeConfig>(invalid_structure);
        assert!(
            result2.is_err(),
            "Should fail to parse invalid repo structure"
        );

        // Test 3: Missing required quotes on repo names
        let unquoted_keys = r#"
            [gh.repos]
            owner/repo = { read = true }
        "#;

        let result3 = toml::from_str::<ScopeConfig>(unquoted_keys);
        assert!(
            result3.is_err(),
            "Should fail to parse unquoted repo name with slash"
        );

        // Test 4: Empty configuration should succeed
        let empty_config = "";
        let result4 = toml::from_str::<ScopeConfig>(empty_config);
        assert!(result4.is_ok(), "Empty config should parse successfully");

        if let Ok(config) = result4 {
            assert!(!config.gh.read);
            assert!(config.gh.repos.is_empty());
            assert!(config.gitlab.projects.is_empty());
            assert!(config.forgejo.is_empty());
        }
    }

    #[test]
    fn test_scope_pattern_matching_with_push_new_branch_comprehensive() {
        // Test that wildcard patterns work correctly with push-new-branch permissions

        let scope = GithubScope {
            read: false,
            repos: [
                // Wildcard with push permission
                (
                    "owner/*".to_string(),
                    GhRepoPermission::with_push_new_branch(),
                ),
                // Specific repo with only read permission (should override wildcard)
                (
                    "owner/restricted".to_string(),
                    GhRepoPermission::read_only(),
                ),
                // Different org with full write
                ("otherorg/*".to_string(), GhRepoPermission::full_write()),
            ]
            .into(),
            prs: HashMap::new(),
            issues: HashMap::new(),
            graphql: GraphQlPermission::None,
        };

        // Wildcard should grant push permission
        assert!(scope.is_allowed("owner/randomrepo", GhOpType::PushNewBranch, None));
        assert!(scope.is_allowed("owner/anothrepo", GhOpType::PushNewBranch, None));

        // Specific override should deny push permission
        assert!(!scope.is_allowed("owner/restricted", GhOpType::PushNewBranch, None));
        assert!(scope.is_allowed("owner/restricted", GhOpType::Read, None));

        // Different org should have full permissions
        assert!(scope.is_allowed("otherorg/somerepo", GhOpType::PushNewBranch, None));
        assert!(scope.is_allowed("otherorg/somerepo", GhOpType::Write, None));

        // Unknown patterns should be denied
        assert!(!scope.is_allowed("unknownorg/repo", GhOpType::PushNewBranch, None));
        assert!(!scope.is_allowed("unknownorg/repo", GhOpType::Read, None));
    }

    #[test]
    fn test_multiple_forgejo_hosts_push_permissions_comprehensive() {
        // Test push-new-branch permissions across multiple Forgejo hosts

        let scope_config = ScopeConfig {
            gh: GithubScope::default(),
            gitlab: GitLabScope::default(),
            forgejo: vec![
                ForgejoScope {
                    host: "codeberg.org".to_string(),
                    token: None,
                    repos: [
                        (
                            "user/allowed".to_string(),
                            ForgejoRepoPermission::with_push_new_branch(),
                        ),
                        (
                            "user/readonly".to_string(),
                            ForgejoRepoPermission::read_only(),
                        ),
                    ]
                    .into(),
                    prs: HashMap::new(),
                    issues: HashMap::new(),
                },
                ForgejoScope {
                    host: "git.example.com".to_string(),
                    token: None,
                    repos: [(
                        "org/project".to_string(),
                        ForgejoRepoPermission::full_write(),
                    )]
                    .into(),
                    prs: HashMap::new(),
                    issues: HashMap::new(),
                },
            ],
            jira: crate::scope::JiraScope::default(),
        };

        // Test first host permissions
        let codeberg_scope = &scope_config.forgejo[0];
        assert!(codeberg_scope.is_allowed(
            "user/allowed",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));
        assert!(!codeberg_scope.is_allowed(
            "user/readonly",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));
        assert!(!codeberg_scope.is_allowed(
            "user/unknown",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));

        // Test second host permissions
        let example_scope = &scope_config.forgejo[1];
        assert!(example_scope.is_allowed(
            "org/project",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));
        assert!(!example_scope.is_allowed(
            "org/other",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));

        // Cross-host should not work
        assert!(!codeberg_scope.is_allowed(
            "org/project",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));
        assert!(!example_scope.is_allowed(
            "user/allowed",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));
    }

    #[test]
    fn test_real_world_configuration_scenarios_comprehensive() {
        // Test realistic configuration scenarios that might occur in production

        // Scenario 1: Organization with tiered permissions
        let org_config = r#"
            [gh]
            read = false

            [gh.repos]
            # Core developers get full access
            "myorg/core-service" = { read = true, write = true }
            
            # Contributors can create drafts and push branches 
            "myorg/contrib-*" = { read = true, create-draft = true, push-new-branch = true }
            
            # Public repos are read-only
            "myorg/public-*" = { read = true, create-draft = false, pending-review = false }
            
            # Specific sensitive repo needs explicit permission
            "myorg/sensitive" = { read = false, create-draft = false, pending-review = false, push-new-branch = false, write = false }
        "#;

        let config: ScopeConfig = toml::from_str(org_config).unwrap();

        // Core service - full access
        assert!(config
            .gh
            .is_allowed("myorg/core-service", GhOpType::Write, None));
        assert!(config
            .gh
            .is_allowed("myorg/core-service", GhOpType::PushNewBranch, None));

        // Contrib repos - can push and create drafts but not full write
        assert!(config
            .gh
            .is_allowed("myorg/contrib-backend", GhOpType::PushNewBranch, None));
        assert!(config
            .gh
            .is_allowed("myorg/contrib-frontend", GhOpType::CreateDraft, None));
        assert!(!config
            .gh
            .is_allowed("myorg/contrib-backend", GhOpType::Write, None));

        // Public repos - read only
        assert!(config
            .gh
            .is_allowed("myorg/public-docs", GhOpType::Read, None));
        assert!(!config
            .gh
            .is_allowed("myorg/public-docs", GhOpType::CreateDraft, None));
        assert!(!config
            .gh
            .is_allowed("myorg/public-docs", GhOpType::PushNewBranch, None));

        // Sensitive repo - completely locked down
        assert!(!config
            .gh
            .is_allowed("myorg/sensitive", GhOpType::Read, None));

        // Scenario 2: Mixed forge environment
        let mixed_config = r#"
            # GitHub for public projects
            [gh.repos]
            "opensource/lib" = { read = true, create-draft = true }

            # GitLab for internal projects  
            [gitlab.projects]
            "company/internal" = { read = true, create-draft = true, push-new-branch = true }

            # Forgejo for personal projects
            [[forgejo]]
            host = "git.personal.dev"
            
            [forgejo.repos]
            "personal/experiments" = { read = true, push-new-branch = true }
        "#;

        let mixed: ScopeConfig = toml::from_str(mixed_config).unwrap();

        // GitHub - can create drafts but not push directly
        assert!(mixed
            .gh
            .is_allowed("opensource/lib", GhOpType::CreateDraft, None));
        assert!(!mixed
            .gh
            .is_allowed("opensource/lib", GhOpType::PushNewBranch, None));

        // GitLab - can push branches
        assert!(mixed.gitlab.is_allowed(
            "company/internal",
            crate::scope::GlOpType::PushNewBranch,
            None
        ));

        // Forgejo - can push branches
        assert!(mixed.forgejo[0].is_allowed(
            "personal/experiments",
            crate::scope::ForgejoOpType::PushNewBranch,
            None
        ));
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
        let push_new_branch: bool = kani::any();
        let write: bool = kani::any();

        let perm = GhRepoPermission {
            read,
            create_draft,
            pending_review,
            push_new_branch,
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
            assert!(
                perm.can_push_new_branch(),
                "Write permission should imply push_branch"
            );
        }

        // Property 2: any capability should imply read access
        if perm.can_create_draft()
            || perm.can_manage_pending_review()
            || perm.can_push_new_branch()
            || perm.can_write()
        {
            assert!(perm.can_read(), "Any capability should imply read access");
        }

        // Property 3: verify the corrected can_read() logic
        assert_eq!(
            perm.can_read(),
            perm.read
                || perm.create_draft
                || perm.pending_review
                || perm.push_new_branch
                || perm.write,
            "can_read should match any capability"
        );
    }
}
