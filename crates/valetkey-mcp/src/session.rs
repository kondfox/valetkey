//! Step 1 of every call: who is asking, for which project, and is its config approved (§6.1).

use std::path::{Path, PathBuf};
use std::time::Duration;

use rmcp::{Peer, RoleServer};
use valetkey_core::NormalizeCx;
use valetkey_core::config::CONFIG_FILE_NAME;
use valetkey_core::project::{self, Project, ProjectError};
use valetkey_core::safe_read::{MAX_CONFIG_LEN, read_untrusted};
use valetkey_core::snapshot::{self, ApprovalState, Snapshot};

use crate::{BrokerConfig, ProjectReport};

/// What step 1 found.
#[derive(Debug)]
pub struct Session {
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub fence_profile: Option<&'static str>,
    /// Whether `CLAUDE_PROJECT_DIR` matched the client's first MCP root.
    pub dir_verified: bool,
    pub project: Option<Project>,
    /// The approved snapshot, only when it matches the working config.
    pub snapshot: Option<Box<Snapshot>>,
    approval: &'static str,
    message: Message,
}

#[derive(Debug)]
enum Message {
    NoProjectDir,
    Discovery(&'static str),
    NotApproved,
    Stale(String),
    RootMismatch,
    Approved,
}

impl Session {
    pub(crate) fn project_report(&self, config: &BrokerConfig) -> ProjectReport {
        let allow_hint = format!(
            "ask a human to run `{} allow` in a normal terminal (not inside the agent's session)",
            config.self_path.display()
        );
        let message = match &self.message {
            Message::NoProjectDir => {
                "the client gave no project directory (no CLAUDE_PROJECT_DIR, no MCP roots)".to_owned()
            }
            Message::Discovery(why) => format!("no usable {CONFIG_FILE_NAME} for this project: {why}"),
            Message::NotApproved => format!("{CONFIG_FILE_NAME} isn't approved yet; {allow_hint}"),
            Message::Stale(reason) => format!("{reason}; nothing is served until {allow_hint}"),
            Message::RootMismatch => format!("the stored approval belongs to another path; {allow_hint}"),
            Message::Approved => "the approved configuration is in effect".to_owned(),
        };
        ProjectReport {
            root: self.project.as_ref().map(|p| p.root.clone()),
            dir_verified: self.dir_verified,
            approval: self.approval,
            message,
        }
    }

    /// The reason nothing can be used, if the session itself rules everything out.
    pub(crate) fn unusable_reason(&self, config: &BrokerConfig) -> Option<String> {
        match self.message {
            Message::Approved => None,
            _ => Some(self.project_report(config).message),
        }
    }
}

/// Resolves the session for one call.
pub async fn resolve(config: &BrokerConfig, peer: &Peer<RoleServer>) -> Session {
    let info = peer.peer_info();
    let client_name = info.as_ref().map(|i| i.client_info.name.clone());
    let client_version = info.as_ref().map(|i| i.client_info.version.clone());
    let fence_profile = match client_name.as_deref() {
        Some("claude-code") => Some("claude-code"),
        _ => None,
    };
    let root_dir = first_root(peer, config.roots_timeout).await;
    let env_dir = config.env_project_dir.clone();
    let dir_verified = match (&env_dir, &root_dir) {
        (Some(env), Some(root)) => same_dir(env, root),
        _ => false,
    };
    let mut s = Session {
        client_name,
        client_version,
        fence_profile,
        dir_verified,
        project: None,
        snapshot: None,
        approval: "no_project",
        message: Message::NoProjectDir,
    };
    let Some(start) = env_dir.or(root_dir) else { return s };
    let project = match project::discover(&start) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "project discovery failed");
            s.message = Message::Discovery(discovery_summary(&e));
            return s;
        }
    };
    match approval_state(config, &project) {
        ApprovalState::Approved(snap) => {
            s.approval = "approved";
            s.message = Message::Approved;
            s.snapshot = Some(snap);
        }
        ApprovalState::NotApproved => {
            s.approval = "not_approved";
            s.message = Message::NotApproved;
        }
        ApprovalState::Stale { reason, .. } => {
            s.approval = "stale";
            s.message = Message::Stale(reason);
        }
        ApprovalState::RootMismatch { .. } => {
            s.approval = "root_mismatch";
            s.message = Message::RootMismatch;
        }
    }
    s.project = Some(project);
    s
}

/// The approval state of the working config. The file sits in an agent-writable directory, so
/// it's read without following links (§6.2.1), and read or parse errors, which can quote file
/// content, go to the log only.
fn approval_state(config: &BrokerConfig, project: &Project) -> ApprovalState {
    let cx = NormalizeCx {
        root: &config.root,
        platform: config.platform,
    };
    let current = match read_untrusted(&project.config_path, MAX_CONFIG_LEN) {
        Ok(text) => config.registry.parse(&text, &cx).map_err(|problems| {
            tracing::warn!(?problems, "valetkey.toml doesn't validate");
        }),
        Err(e) => {
            tracing::warn!(error = %e, "can't read valetkey.toml");
            Err(())
        }
    };
    let stored = match snapshot::load(&config.root, project) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "can't use the stored snapshot");
            None
        }
    };
    ApprovalState::evaluate(stored, project, current.as_ref().map_err(|_| ()))
}

/// A short, content-free description of why discovery failed, for the agent.
fn discovery_summary(e: &ProjectError) -> &'static str {
    match e {
        ProjectError::NotFound(_) => "none found in the project directory or its parents",
        ProjectError::ConfigIsSymlink(_) => "it's a symlink",
        ProjectError::SymlinkOnPath(_) => "a directory on the way to it is a symlink",
        ProjectError::NotAbsolute(_) | ProjectError::NotNormalized(_) => {
            "the client's project directory isn't a normalized absolute path"
        }
        ProjectError::Io { .. } => "it can't be inspected",
    }
}

/// The client's first MCP root as a local path, if it supports roots and answers in time.
///
/// Roots are deprecated in the newest MCP spec (SEP-2577), but Claude Code sends them (M0). If a
/// client stops sending them, the cross-check fails closed: protected targets are refused.
#[allow(deprecated)]
async fn first_root(peer: &Peer<RoleServer>, timeout: Duration) -> Option<PathBuf> {
    let supports_roots = peer.peer_info().is_some_and(|i| i.capabilities.roots.is_some());
    if !supports_roots {
        return None;
    }
    let roots = match tokio::time::timeout(timeout, peer.list_roots()).await {
        Ok(Ok(r)) => r.roots,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "roots/list failed");
            return None;
        }
        Err(_) => {
            tracing::warn!("roots/list timed out");
            return None;
        }
    };
    let uri = &roots.first()?.uri;
    url::Url::parse(uri)
        .ok()
        .filter(|u| u.scheme() == "file")
        .and_then(|u| u.to_file_path().ok())
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
