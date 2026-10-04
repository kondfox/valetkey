//! The interface every secret source implements (§5, §6.11). Implementations live in
//! `valetkey-secrets`; core only defines the contract.

use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use secrecy::SecretString;

use crate::paths::ValetkeyRoot;
use crate::secret_ref::SecretRef;
use crate::user_config::UserConfig;

/// What a source may use while fetching.
#[derive(Debug)]
pub struct FetchCx<'a> {
    /// The canonical project root (for `env-file://`).
    pub project_root: &'a Path,
    pub root: &'a ValetkeyRoot,
    /// Human-approved tool paths and their environment (`valetkey setup`).
    pub user: &'a UserConfig,
}

/// Paths the fence must protect for a source (used by the fence profile in M4).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FenceRules {
    pub deny_read: Vec<PathBuf>,
}

/// A failed fetch. [`fmt::Display`] is the **public** message, safe for the agent: fixed text
/// that never contains file content, command output or the secret. [`SourceError::detail`] is for
/// the broker's log.
#[derive(Debug)]
pub struct SourceError {
    public: String,
    detail: String,
}

impl SourceError {
    pub fn new(public: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            public: public.into(),
            detail: detail.into(),
        }
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.public)
    }
}

impl std::error::Error for SourceError {}

/// The future a fetch returns. Boxed, because `async fn` in traits isn't dyn-compatible.
pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<SecretString, SourceError>> + Send + 'a>>;

/// One `<scheme>://` source.
pub trait SecretSource: Send + Sync {
    fn scheme(&self) -> &'static str;

    /// Fetches the secret. Errors carry a public message and a log-only detail.
    fn fetch<'a>(&'a self, reference: &'a SecretRef, cx: &'a FetchCx<'a>) -> FetchFuture<'a>;

    /// Paths the fence must deny the agent, given the human's tool config.
    fn fence(&self, user: &UserConfig) -> FenceRules;
}
