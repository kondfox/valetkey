//! The broker: valetkey's MCP stdio server (§1, §6.7).
//!
//! M1 serves one tool, `valetkey_targets`: the approved targets of the client's project and why
//! each is or isn't usable. It already applies the rules every later tool depends on:
//! - only an **approved snapshot** is served, and only while the working `valetkey.toml` still
//!   matches it (§6.1)
//! - the client-supplied project dir is **cross-checked**: `CLAUDE_PROJECT_DIR` must equal the
//!   client's first MCP root, or protected targets are refused (§6.1)
//!
//! Nothing here writes to stdout except the MCP transport.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData as McpError, Peer, RoleServer, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use serde::Serialize;
use valetkey_core::config::CONFIG_FILE_NAME;
use valetkey_core::project::{self, Project};
use valetkey_core::snapshot::{self, ApprovalState};
use valetkey_core::{Exposure, NormalizeCx, Platform, Registry, ValetkeyRoot};

/// How long the broker waits for the client's `roots/list` answer.
const ROOTS_TIMEOUT: Duration = Duration::from_secs(5);

/// Everything the broker needs, fixed at startup.
#[derive(Debug)]
pub struct BrokerConfig {
    pub root: ValetkeyRoot,
    pub registry: Registry,
    pub platform: Platform,
    /// `CLAUDE_PROJECT_DIR` as inherited at startup. Untrusted until cross-checked.
    pub env_project_dir: Option<PathBuf>,
    /// The absolute path humans should run for `allow` etc. (§6.3: hints use absolute paths).
    pub self_path: PathBuf,
}

/// The MCP server.
#[derive(Clone, Debug)]
pub struct Broker {
    config: Arc<BrokerConfig>,
    tool_router: ToolRouter<Self>,
}

impl Broker {
    pub fn new(config: BrokerConfig) -> Self {
        Self {
            config: Arc::new(config),
            tool_router: Self::tool_router(),
        }
    }

    /// Serves MCP over stdin/stdout until the client disconnects.
    pub async fn serve_stdio(self) -> anyhow::Result<()> {
        let service = self.serve(rmcp::transport::stdio()).await?;
        service.waiting().await?;
        Ok(())
    }
}

#[tool_router]
impl Broker {
    #[tool(
        name = "valetkey_targets",
        description = "List the credentialed targets valetkey can broker for this project (databases, APIs), \
                       whether each is usable now, and if not, why. Secrets are never shown."
    )]
    async fn valetkey_targets(&self, peer: Peer<RoleServer>) -> Result<CallToolResult, McpError> {
        let report = self.targets_report(&peer).await;
        tracing::info!(
            approval = report.project.approval,
            targets = report.targets.len(),
            "valetkey_targets"
        );
        Ok(CallToolResult::success(vec![ContentBlock::json(report)?]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Broker {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("valetkey", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "valetkey brokers access to credentialed resources without revealing the credentials. \
                 Start with valetkey_targets.",
            )
    }
}

#[derive(Debug, Serialize)]
struct TargetsReport {
    project: ProjectReport,
    client: ClientReport,
    targets: Vec<TargetReport>,
}

#[derive(Debug, Serialize)]
struct ProjectReport {
    root: Option<PathBuf>,
    /// Whether `CLAUDE_PROJECT_DIR` matched the client's first MCP root.
    dir_verified: bool,
    /// `approved`, `not_approved`, `stale`, `root_mismatch` or `no_project`.
    approval: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct ClientReport {
    name: Option<String>,
    version: Option<String>,
    /// The fence profile that will apply to this client (fence detection arrives in M4).
    fence_profile: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct TargetReport {
    id: String,
    kind: String,
    writable: bool,
    secret_exposure: Option<Exposure>,
    available: bool,
    reason: String,
}

impl Broker {
    async fn targets_report(&self, peer: &Peer<RoleServer>) -> TargetsReport {
        let client = client_report(peer);
        let root_dir = first_root(peer).await;
        let env_dir = self.config.env_project_dir.clone();
        let dir_verified = match (&env_dir, &root_dir) {
            (Some(env), Some(root)) => same_dir(env, root),
            _ => false,
        };
        let empty = |approval, root, message: String| TargetsReport {
            project: ProjectReport {
                root,
                dir_verified,
                approval,
                message,
            },
            client: client_report(peer),
            targets: Vec::new(),
        };

        let Some(start) = env_dir.or(root_dir) else {
            return empty(
                "no_project",
                None,
                "the client gave no project directory (no CLAUDE_PROJECT_DIR, no MCP roots)".into(),
            );
        };
        let project = match project::discover(&start) {
            Ok(p) => p,
            Err(e) => return empty("no_project", None, e.to_string()),
        };
        let state = self.approval_state(&project);
        let allow_hint = format!(
            "ask a human to run `{} allow` in a normal terminal (not inside the agent's session)",
            self.config.self_path.display()
        );
        let (approval, message, snapshot) = match state {
            ApprovalState::Approved(s) => ("approved", "the approved configuration is in effect".to_owned(), s),
            ApprovalState::NotApproved => {
                return empty(
                    "not_approved",
                    Some(project.root),
                    format!("{CONFIG_FILE_NAME} isn't approved yet; {allow_hint}"),
                );
            }
            ApprovalState::Stale { reason, .. } => {
                return empty(
                    "stale",
                    Some(project.root),
                    format!("{reason}; nothing is served until {allow_hint}"),
                );
            }
            ApprovalState::RootMismatch { .. } => {
                return empty(
                    "root_mismatch",
                    Some(project.root),
                    format!("the stored approval belongs to another path; {allow_hint}"),
                );
            }
        };

        let targets = snapshot
            .config
            .targets
            .iter()
            .map(|(id, t)| {
                let reason = if t.exposure == Some(Exposure::Protected) && !dir_verified {
                    "refused: the project directory couldn't be verified against the client's MCP roots, so a protected secret won't be used".to_owned()
                } else {
                    format!("valetkey {} has no tools for `{}` targets yet (they arrive in M2)", env!("CARGO_PKG_VERSION"), t.kind)
                };
                TargetReport {
                    id: id.to_string(),
                    kind: t.kind.clone(),
                    writable: t.writable,
                    secret_exposure: t.exposure,
                    available: false,
                    reason,
                }
            })
            .collect();

        TargetsReport {
            project: ProjectReport {
                root: Some(project.root),
                dir_verified,
                approval,
                message,
            },
            client,
            targets,
        }
    }

    fn approval_state(&self, project: &Project) -> ApprovalState {
        let cx = NormalizeCx {
            root: &self.config.root,
            platform: self.config.platform,
        };
        let current = std::fs::read_to_string(&project.config_path)
            .map_err(|e| format!("can't read {}: {e}", project.config_path.display()))
            .and_then(|text| {
                self.config
                    .registry
                    .parse(&text, &cx)
                    .map_err(|ps| ps.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))
            });
        let stored = match snapshot::load(&self.config.root, project) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "can't load snapshot");
                None
            }
        };
        ApprovalState::evaluate(stored, project, current.as_ref().map_err(Clone::clone))
    }
}

fn client_report(peer: &Peer<RoleServer>) -> ClientReport {
    let info = peer.peer_info();
    let name = info.as_ref().map(|i| i.client_info.name.clone());
    let fence_profile = match name.as_deref() {
        Some("claude-code") => Some("claude-code"),
        _ => None,
    };
    ClientReport {
        version: info.as_ref().map(|i| i.client_info.version.clone()),
        name,
        fence_profile,
    }
}

/// The client's first MCP root as a local path, if it supports roots and answers in time.
///
/// Roots are deprecated in the newest MCP spec (SEP-2577), but Claude Code sends them (M0). If a
/// client stops sending them, the cross-check fails closed: protected targets are refused.
#[allow(deprecated)]
async fn first_root(peer: &Peer<RoleServer>) -> Option<PathBuf> {
    let supports_roots = peer.peer_info().is_some_and(|i| i.capabilities.roots.is_some());
    if !supports_roots {
        return None;
    }
    let result = tokio::time::timeout(ROOTS_TIMEOUT, peer.list_roots()).await;
    let roots = match result {
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
