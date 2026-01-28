//! JWT-based authentication for the MCP server.
//!
//! This module provides token-based authentication where scopes are embedded
//! in signed JWTs. This allows a single service-gator instance to serve multiple
//! sandboxed agents, each with their own scope-restricted access.
//!
//! # Flow
//!
//! 1. Admin/human calls POST /admin/mint-token with desired scopes
//! 2. Server returns a signed JWT containing those scopes
//! 3. Agent includes `Authorization: Bearer <token>` on MCP requests
//! 4. Server validates signature, extracts scopes, applies them to requests
//!
//! # Token Rotation
//!
//! Tokens can self-rotate (refresh) by calling POST /token/rotate with a new
//! expiration time. The new token has identical scopes. This is bounded by
//! `max_exp_delta` to prevent infinite token lifetimes.
//!
//! # Secret/Token File Support
//!
//! Secrets can be read from files for container deployments:
//! - Set `SERVICE_GATOR_SECRET_FILE` or `SERVICE_GATOR_ADMIN_KEY_FILE` to a path
//! - Compatible with `podman run --secret` and Kubernetes secrets
//! - Files are read and trimmed of whitespace

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::scope::ScopeConfig;

/// JWT claims for service-gator tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Issued-at timestamp (Unix seconds).
    pub iat: u64,
    /// Expiration timestamp (Unix seconds).
    pub exp: u64,
    /// The scopes this token grants.
    pub scopes: ScopeConfig,
    /// Optional subject identifier (for logging/audit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Whether this token can call /token/rotate.
    #[serde(default = "default_can_rotate")]
    pub can_rotate: bool,
    /// Maximum lifetime: rotated tokens can't expire later than original_iat + max_exp_delta.
    /// If None, no limit (beyond the requested expiration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_exp_delta: Option<u64>,
    /// Original issued-at timestamp (preserved across rotations).
    /// Used for max_exp_delta enforcement. If None, uses iat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_iat: Option<u64>,
}

fn default_can_rotate() -> bool {
    true
}

/// Authentication mode for the server.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// All MCP requests require a valid Bearer token.
    Required,
    /// Allow both authenticated and unauthenticated requests.
    /// Unauthenticated requests use fallback config (if any).
    Optional,
    /// No token authentication (current/legacy behavior).
    #[default]
    None,
}

/// Server authentication configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerAuthConfig {
    /// Secret key for JWT signing (HMAC-SHA256).
    /// Can also be set via SERVER_SECRET environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

    /// Admin key for /admin/* endpoints.
    /// Can also be set via ADMIN_KEY environment variable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_key: Option<String>,

    /// Authentication mode.
    #[serde(default)]
    pub mode: AuthMode,

    /// Default rotation settings for minted tokens.
    #[serde(default)]
    pub rotation: RotationConfig,
}

/// Configuration for token rotation defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RotationConfig {
    /// Whether newly minted tokens can rotate by default.
    #[serde(default = "default_can_rotate")]
    pub enabled: bool,

    /// Default max lifetime in seconds for minted tokens.
    /// Rotated tokens can't expire later than original_iat + max_lifetime.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lifetime: Option<u64>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_lifetime: None,
        }
    }
}

/// Token signing and validation.
pub struct TokenAuthority {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl TokenAuthority {
    /// Create a new token authority with the given secret.
    pub fn new(secret: &str) -> Self {
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        // Explicitly specify HS256 algorithm for defense in depth
        // (prevents any potential "alg: none" attacks, though jsonwebtoken v9 is not vulnerable)
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        validation.required_spec_claims.clear();
        validation.required_spec_claims.insert("exp".to_string());

        Self {
            encoding_key,
            decoding_key,
            validation,
        }
    }

    /// Sign a new token with the given claims.
    pub fn sign(&self, claims: &TokenClaims) -> Result<String, TokenError> {
        encode(&Header::default(), claims, &self.encoding_key).map_err(TokenError::Signing)
    }

    /// Validate and decode a token.
    pub fn validate(&self, token: &str) -> Result<TokenClaims, TokenError> {
        let token_data = decode::<TokenClaims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => TokenError::Expired,
                jsonwebtoken::errors::ErrorKind::InvalidSignature => TokenError::InvalidSignature,
                _ => TokenError::Validation(e),
            })?;
        Ok(token_data.claims)
    }
}

/// Errors from token operations.
#[derive(Debug)]
pub enum TokenError {
    /// Token signature is invalid.
    InvalidSignature,
    /// Token has expired.
    Expired,
    /// Token signing failed.
    Signing(jsonwebtoken::errors::Error),
    /// Token validation failed.
    Validation(jsonwebtoken::errors::Error),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::InvalidSignature => write!(f, "invalid token signature"),
            TokenError::Expired => write!(f, "token has expired"),
            TokenError::Signing(e) => write!(f, "failed to sign token: {e}"),
            TokenError::Validation(e) => write!(f, "token validation failed: {e}"),
        }
    }
}

impl std::error::Error for TokenError {}

/// Minimum token lifetime: 1 minute.
pub const MIN_EXPIRES_IN: u64 = 60;

/// Maximum token lifetime: 1 year.
pub const MAX_EXPIRES_IN: u64 = 365 * 24 * 3600;

/// Errors from token minting.
#[derive(Debug)]
pub enum MintError {
    /// Token lifetime is too short.
    ExpiresTooShort { min: u64 },
    /// Token lifetime is too long.
    ExpiresTooLong { max: u64 },
    /// Token signing failed.
    Signing(TokenError),
}

impl std::fmt::Display for MintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MintError::ExpiresTooShort { min } => {
                write!(f, "expires_in must be at least {min} seconds")
            }
            MintError::ExpiresTooLong { max } => {
                write!(f, "expires_in must be at most {max} seconds")
            }
            MintError::Signing(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for MintError {}

/// Get current Unix timestamp.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

/// Request to mint a new token.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MintRequest {
    /// Scopes to embed in the token.
    pub scopes: ScopeConfig,
    /// Token lifetime in seconds.
    pub expires_in: u64,
    /// Optional subject identifier.
    #[serde(default)]
    pub sub: Option<String>,
    /// Override default can_rotate setting.
    #[serde(default)]
    pub can_rotate: Option<bool>,
    /// Override default max_exp_delta.
    #[serde(default)]
    pub max_exp_delta: Option<u64>,
}

/// Response from minting a token.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MintResponse {
    /// The signed JWT.
    pub token: String,
    /// When the token expires (Unix timestamp).
    pub expires_at: u64,
}

/// Request to rotate a token.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RotateRequest {
    /// New token lifetime in seconds from now.
    pub expires_in: u64,
}

/// Response from rotating a token.
#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RotateResponse {
    /// The new signed JWT.
    pub token: String,
    /// When the new token expires (Unix timestamp).
    pub expires_at: u64,
}

/// Error response for auth endpoints.
#[derive(Debug, Serialize)]
pub struct AuthError {
    pub error: String,
}

impl AuthError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { error: msg.into() }
    }
}

/// Complete server configuration including auth and default scopes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerConfig {
    /// Server authentication configuration.
    #[serde(default)]
    pub server: ServerAuthConfig,

    /// Default scope configuration (used as fallback or for unauthenticated requests).
    #[serde(flatten)]
    pub scopes: ScopeConfig,
}

/// Read a secret from a file, trimming whitespace.
///
/// Used for container secret mounts (podman --secret, k8s secrets).
fn read_secret_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Get a value from env var, or from a file specified by `{VAR}_FILE`.
///
/// This supports container secret patterns:
/// - `podman run --secret gh_token,target=/run/secrets/gh_token`
/// - Kubernetes secret volume mounts
fn env_or_file(var_name: &str) -> Option<String> {
    // First check direct env var
    if let Ok(val) = std::env::var(var_name) {
        if !val.is_empty() {
            return Some(val);
        }
    }

    // Then check {VAR}_FILE for a path to read from
    let file_var = format!("{}_FILE", var_name);
    if let Ok(path) = std::env::var(&file_var) {
        return read_secret_file(Path::new(&path));
    }

    None
}

impl ServerConfig {
    /// Create a ServerConfig with just scopes (no auth), for backward compatibility.
    pub fn from_scopes(scopes: ScopeConfig) -> Self {
        Self {
            server: ServerAuthConfig::default(),
            scopes,
        }
    }

    /// Check if token authentication is enabled.
    pub fn auth_enabled(&self) -> bool {
        self.server.secret.is_some() && self.server.mode != AuthMode::None
    }

    /// Get the effective secret, checking environment variable and file as fallback.
    ///
    /// Order of precedence:
    /// 1. Config file `server.secret`
    /// 2. `SERVICE_GATOR_SECRET` environment variable
    /// 3. File path from `SERVICE_GATOR_SECRET_FILE` environment variable
    pub fn effective_secret(&self) -> Option<String> {
        self.server
            .secret
            .clone()
            .or_else(|| env_or_file("SERVICE_GATOR_SECRET"))
    }

    /// Get the effective admin key, checking environment variable and file as fallback.
    ///
    /// Order of precedence:
    /// 1. Config file `server.admin-key`
    /// 2. `SERVICE_GATOR_ADMIN_KEY` environment variable
    /// 3. File path from `SERVICE_GATOR_ADMIN_KEY_FILE` environment variable
    pub fn effective_admin_key(&self) -> Option<String> {
        self.server
            .admin_key
            .clone()
            .or_else(|| env_or_file("SERVICE_GATOR_ADMIN_KEY"))
    }
}

impl TokenAuthority {
    /// Mint a new token from a mint request.
    pub fn mint(
        &self,
        req: &MintRequest,
        defaults: &RotationConfig,
    ) -> Result<MintResponse, MintError> {
        // Validate expires_in bounds
        if req.expires_in < MIN_EXPIRES_IN {
            return Err(MintError::ExpiresTooShort {
                min: MIN_EXPIRES_IN,
            });
        }
        if req.expires_in > MAX_EXPIRES_IN {
            return Err(MintError::ExpiresTooLong {
                max: MAX_EXPIRES_IN,
            });
        }

        let now = now_unix();
        let exp = now + req.expires_in;

        let claims = TokenClaims {
            iat: now,
            exp,
            scopes: req.scopes.clone(),
            sub: req.sub.clone(),
            can_rotate: req.can_rotate.unwrap_or(defaults.enabled),
            max_exp_delta: req.max_exp_delta.or(defaults.max_lifetime),
            // For freshly minted tokens, original_iat is None (iat is used)
            original_iat: None,
        };

        let token = self.sign(&claims).map_err(MintError::Signing)?;
        Ok(MintResponse {
            token,
            expires_at: exp,
        })
    }

    /// Rotate an existing token.
    pub fn rotate(
        &self,
        current: &TokenClaims,
        req: &RotateRequest,
    ) -> Result<RotateResponse, RotateError> {
        if !current.can_rotate {
            return Err(RotateError::RotationDisabled);
        }

        let now = now_unix();
        let new_exp = now + req.expires_in;

        // Get the original issuance time (preserved across rotations)
        let original_iat = current.original_iat.unwrap_or(current.iat);

        // Check max lifetime constraint against original issuance time
        if let Some(max_delta) = current.max_exp_delta {
            let max_allowed_exp = original_iat + max_delta;
            if new_exp > max_allowed_exp {
                return Err(RotateError::ExceedsMaxLifetime {
                    requested: new_exp,
                    max_allowed: max_allowed_exp,
                });
            }
        }

        let new_claims = TokenClaims {
            iat: now,
            exp: new_exp,
            scopes: current.scopes.clone(),
            sub: current.sub.clone(),
            can_rotate: current.can_rotate,
            max_exp_delta: current.max_exp_delta,
            // Preserve the original issuance time across rotations
            original_iat: Some(original_iat),
        };

        let token = self.sign(&new_claims).map_err(RotateError::Signing)?;
        Ok(RotateResponse {
            token,
            expires_at: new_exp,
        })
    }
}

/// Errors from token rotation.
#[derive(Debug)]
pub enum RotateError {
    /// Token rotation is disabled for this token.
    RotationDisabled,
    /// Requested expiration exceeds max allowed lifetime.
    ExceedsMaxLifetime { requested: u64, max_allowed: u64 },
    /// Token signing failed.
    Signing(TokenError),
}

impl std::fmt::Display for RotateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotateError::RotationDisabled => write!(f, "token rotation is disabled for this token"),
            RotateError::ExceedsMaxLifetime {
                requested,
                max_allowed,
            } => {
                write!(
                    f,
                    "requested expiration {} exceeds maximum allowed {}",
                    requested, max_allowed
                )
            }
            RotateError::Signing(e) => write!(f, "failed to sign rotated token: {e}"),
        }
    }
}

impl std::error::Error for RotateError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_validate() {
        let authority = TokenAuthority::new("test-secret-key-for-testing");

        let claims = TokenClaims {
            iat: now_unix(),
            exp: now_unix() + 3600,
            scopes: ScopeConfig::default(),
            sub: Some("test-agent".into()),
            can_rotate: true,
            max_exp_delta: Some(86400),
            original_iat: None,
        };

        let token = authority.sign(&claims).expect("signing should succeed");
        let decoded = authority
            .validate(&token)
            .expect("validation should succeed");

        assert_eq!(decoded.sub, Some("test-agent".into()));
        assert!(decoded.can_rotate);
        assert_eq!(decoded.max_exp_delta, Some(86400));
    }

    #[test]
    fn test_expired_token() {
        let authority = TokenAuthority::new("test-secret-key-for-testing");

        let claims = TokenClaims {
            iat: now_unix() - 7200,
            exp: now_unix() - 3600, // expired 1 hour ago
            scopes: ScopeConfig::default(),
            sub: None,
            can_rotate: true,
            max_exp_delta: None,
            original_iat: None,
        };

        let token = authority.sign(&claims).expect("signing should succeed");
        let result = authority.validate(&token);

        assert!(matches!(result, Err(TokenError::Expired)));
    }

    #[test]
    fn test_invalid_signature() {
        let authority1 = TokenAuthority::new("secret-one");
        let authority2 = TokenAuthority::new("secret-two");

        let claims = TokenClaims {
            iat: now_unix(),
            exp: now_unix() + 3600,
            scopes: ScopeConfig::default(),
            sub: None,
            can_rotate: true,
            max_exp_delta: None,
            original_iat: None,
        };

        let token = authority1.sign(&claims).expect("signing should succeed");
        let result = authority2.validate(&token);

        assert!(matches!(result, Err(TokenError::InvalidSignature)));
    }

    #[test]
    fn test_default_can_rotate() {
        // Verify default deserialization
        let json = r#"{"iat": 0, "exp": 1, "scopes": {}}"#;
        let claims: TokenClaims = serde_json::from_str(json).unwrap();
        assert!(claims.can_rotate);
    }

    #[test]
    fn test_auth_mode_deserialization() {
        assert_eq!(
            serde_json::from_str::<AuthMode>(r#""required""#).unwrap(),
            AuthMode::Required
        );
        assert_eq!(
            serde_json::from_str::<AuthMode>(r#""optional""#).unwrap(),
            AuthMode::Optional
        );
        assert_eq!(
            serde_json::from_str::<AuthMode>(r#""none""#).unwrap(),
            AuthMode::None
        );
    }

    #[test]
    fn test_mint_token() {
        let authority = TokenAuthority::new("test-secret");
        let defaults = RotationConfig::default();

        let req = MintRequest {
            scopes: ScopeConfig::default(),
            expires_in: 3600,
            sub: Some("agent-1".into()),
            can_rotate: None, // use default
            max_exp_delta: None,
        };

        let response = authority
            .mint(&req, &defaults)
            .expect("minting should succeed");
        assert!(response.expires_at > now_unix());

        // Validate the minted token
        let claims = authority
            .validate(&response.token)
            .expect("validation should succeed");
        assert_eq!(claims.sub, Some("agent-1".into()));
        assert!(claims.can_rotate); // default is true
    }

    #[test]
    fn test_mint_token_with_overrides() {
        let authority = TokenAuthority::new("test-secret");
        let defaults = RotationConfig {
            enabled: true,
            max_lifetime: Some(86400),
        };

        let req = MintRequest {
            scopes: ScopeConfig::default(),
            expires_in: 3600,
            sub: None,
            can_rotate: Some(false),   // override
            max_exp_delta: Some(7200), // override
        };

        let response = authority
            .mint(&req, &defaults)
            .expect("minting should succeed");
        let claims = authority
            .validate(&response.token)
            .expect("validation should succeed");

        assert!(!claims.can_rotate);
        assert_eq!(claims.max_exp_delta, Some(7200));
    }

    #[test]
    fn test_mint_token_expires_too_short() {
        let authority = TokenAuthority::new("test-secret");
        let defaults = RotationConfig::default();

        let req = MintRequest {
            scopes: ScopeConfig::default(),
            expires_in: 30, // too short
            sub: None,
            can_rotate: None,
            max_exp_delta: None,
        };

        let result = authority.mint(&req, &defaults);
        assert!(matches!(result, Err(MintError::ExpiresTooShort { .. })));
    }

    #[test]
    fn test_mint_token_expires_too_long() {
        let authority = TokenAuthority::new("test-secret");
        let defaults = RotationConfig::default();

        let req = MintRequest {
            scopes: ScopeConfig::default(),
            expires_in: MAX_EXPIRES_IN + 1, // too long
            sub: None,
            can_rotate: None,
            max_exp_delta: None,
        };

        let result = authority.mint(&req, &defaults);
        assert!(matches!(result, Err(MintError::ExpiresTooLong { .. })));
    }

    #[test]
    fn test_rotate_token() {
        let authority = TokenAuthority::new("test-secret");

        let original_claims = TokenClaims {
            iat: now_unix(),
            exp: now_unix() + 3600,
            scopes: ScopeConfig::default(),
            sub: Some("agent-1".into()),
            can_rotate: true,
            max_exp_delta: None,
            original_iat: None,
        };

        let req = RotateRequest { expires_in: 7200 };
        let response = authority
            .rotate(&original_claims, &req)
            .expect("rotation should succeed");

        // New token should be valid
        let new_claims = authority
            .validate(&response.token)
            .expect("new token should be valid");
        assert_eq!(new_claims.sub, Some("agent-1".into()));
        assert!(new_claims.can_rotate);
        // original_iat should be preserved
        assert_eq!(new_claims.original_iat, Some(original_claims.iat));
    }

    #[test]
    fn test_rotate_disabled() {
        let authority = TokenAuthority::new("test-secret");

        let claims = TokenClaims {
            iat: now_unix(),
            exp: now_unix() + 3600,
            scopes: ScopeConfig::default(),
            sub: None,
            can_rotate: false, // rotation disabled
            max_exp_delta: None,
            original_iat: None,
        };

        let req = RotateRequest { expires_in: 3600 };
        let result = authority.rotate(&claims, &req);

        assert!(matches!(result, Err(RotateError::RotationDisabled)));
    }

    #[test]
    fn test_rotate_exceeds_max_lifetime() {
        let authority = TokenAuthority::new("test-secret");

        let iat = now_unix();
        let claims = TokenClaims {
            iat,
            exp: iat + 3600,
            scopes: ScopeConfig::default(),
            sub: None,
            can_rotate: true,
            max_exp_delta: Some(7200), // max 2 hours from original iat
            original_iat: None,
        };

        // Try to rotate with expiration beyond max
        let req = RotateRequest { expires_in: 10000 }; // would exceed iat + 7200
        let result = authority.rotate(&claims, &req);

        assert!(matches!(
            result,
            Err(RotateError::ExceedsMaxLifetime { .. })
        ));
    }

    #[test]
    fn test_rotate_within_max_lifetime() {
        let authority = TokenAuthority::new("test-secret");

        let iat = now_unix();
        let claims = TokenClaims {
            iat,
            exp: iat + 3600,
            scopes: ScopeConfig::default(),
            sub: None,
            can_rotate: true,
            max_exp_delta: Some(86400), // max 24 hours from original iat
            original_iat: None,
        };

        // Rotate with expiration within max
        let req = RotateRequest { expires_in: 3600 }; // 1 hour from now, well within 24h limit
        let response = authority
            .rotate(&claims, &req)
            .expect("rotation should succeed");

        assert!(response.expires_at <= iat + 86400);
    }

    #[test]
    fn test_rotate_preserves_original_iat_across_multiple_rotations() {
        let authority = TokenAuthority::new("test-secret");

        let original_iat = now_unix() - 1000; // original token minted 1000s ago
        let claims = TokenClaims {
            iat: now_unix() - 500, // this token was rotated 500s ago
            exp: now_unix() + 3600,
            scopes: ScopeConfig::default(),
            sub: None,
            can_rotate: true,
            max_exp_delta: Some(7200), // max 2 hours from ORIGINAL iat
            original_iat: Some(original_iat), // track original
        };

        // We're now at original_iat + 1000, with max at original_iat + 7200
        // So we have 6200s left of max lifetime
        let req = RotateRequest { expires_in: 5000 }; // within limit
        let response = authority
            .rotate(&claims, &req)
            .expect("rotation should succeed");

        let new_claims = authority
            .validate(&response.token)
            .expect("new token should be valid");

        // original_iat should still be preserved as the original value
        assert_eq!(new_claims.original_iat, Some(original_iat));

        // Now try to exceed the original max lifetime
        let req_too_long = RotateRequest { expires_in: 10000 }; // would exceed original_iat + 7200
        let result = authority.rotate(&new_claims, &req_too_long);
        assert!(matches!(
            result,
            Err(RotateError::ExceedsMaxLifetime { .. })
        ));
    }

    #[test]
    fn test_server_config_from_scopes() {
        let scopes = ScopeConfig::default();
        let config = ServerConfig::from_scopes(scopes);

        assert!(!config.auth_enabled());
        assert_eq!(config.server.mode, AuthMode::None);
    }

    #[test]
    fn test_server_config_toml_parsing() {
        let toml = r#"
            [server]
            secret = "my-secret"
            admin-key = "my-admin-key"
            mode = "required"

            [server.rotation]
            enabled = true
            max-lifetime = 86400

            [gh.repos]
            "owner/repo" = { read = true }
        "#;

        let config: ServerConfig = toml::from_str(toml).expect("parsing should succeed");

        assert_eq!(config.server.secret, Some("my-secret".into()));
        assert_eq!(config.server.admin_key, Some("my-admin-key".into()));
        assert_eq!(config.server.mode, AuthMode::Required);
        assert!(config.server.rotation.enabled);
        assert_eq!(config.server.rotation.max_lifetime, Some(86400));
        assert!(config.scopes.gh.repos.contains_key("owner/repo"));
    }
}
