//! The broker: valetkey's MCP stdio server (§1, §6.7).
//!
//! Tools: `valetkey_targets`, `sql_query`, `sql_describe`. Every tool goes through the same steps
//! (§6.7), and a later step never runs if an earlier one refuses:
//! 1. **session** ([`session`]): the client's project dir, cross-checked against its MCP roots;
//!    the project; its approved snapshot, served only while the working `valetkey.toml` matches
//! 2. **policy** ([`policy`]): the target exists in the snapshot with the right kind; exposure is
//!    recomputed; protected targets need a verified project dir, a private valetkey root and a
//!    fence (none before M4, so only with `require_fence = false`)
//! 3. **secret**: only now, through the single-flight cache (policy always runs first, so a cache
//!    hit can't skip it)
//! 4. **adapter**: the Postgres read path ([`valetkey_postgres::read`])
//!
//! Nothing here writes to stdout except the MCP transport. The log (agent-readable) never gets
//! statement text, parameters or secrets.

pub mod policy;
pub mod session;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{
    ErrorData as McpError, Peer, RoleServer, ServerHandler, ServiceExt, schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use valetkey_core::user_config::UserConfig;
use valetkey_core::{Exposure, Platform, Registry, ValetkeyRoot};
use valetkey_postgres::read::{ReadRequest, read};
use valetkey_secrets::cache::{CacheKey, SecretCache};

use crate::policy::{Usable, evaluate};
use crate::session::{Session, resolve};

/// The broker's log filter. `rmcp` logs whole requests, tool arguments included, at DEBUG; the
/// log is agent-readable and must never contain statement text or parameters, so `rmcp` is held
/// at WARN. The binary and the log-content tests both use this constant.
pub const LOG_FILTER: &str = "info,rmcp=warn";

/// How long the broker waits for the client's `roots/list` answer, by default.
pub const DEFAULT_ROOTS_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// How long to wait for the client's `roots/list` answer before treating the project dir as
    /// unverified.
    pub roots_timeout: Duration,
}

/// The MCP server.
#[derive(Clone, Debug)]
pub struct Broker {
    config: Arc<BrokerConfig>,
    cache: Arc<SecretCache>,
    tool_router: ToolRouter<Self>,
}

impl Broker {
    pub fn new(config: BrokerConfig) -> Self {
        Self {
            config: Arc::new(config),
            cache: Arc::new(SecretCache::default()),
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

/// Arguments of `sql_query`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SqlQueryArgs {
    /// The target id, as listed by `valetkey_targets`.
    pub target: String,
    /// Exactly one SQL statement. It runs in a read-only transaction that is always rolled back.
    pub sql: String,
    /// Values for `$1`, `$2`, …: strings, numbers, booleans or null. They're sent as data, never
    /// as SQL.
    #[serde(default)]
    pub params: Vec<Value>,
}

/// Arguments of `sql_describe`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SqlDescribeArgs {
    /// The target id, as listed by `valetkey_targets`.
    pub target: String,
    /// A table (`name` or `schema.name`) to list the columns of. Omit to list tables and views.
    pub table: Option<String>,
}

#[tool_router]
impl Broker {
    #[tool(
        name = "valetkey_targets",
        description = "List the credentialed targets valetkey can broker for this project (databases, APIs), \
                       whether each is usable now and with which tools, and if not, why. Secrets are never shown."
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

    #[tool(
        name = "sql_query",
        description = "Run one read-only SQL statement on a Postgres target and return its rows. The transaction is \
                       read-only and always rolled back; rows, bytes and time are limited per target. Use $1, $2, … \
                       placeholders with `params` for values."
    )]
    async fn sql_query(
        &self,
        Parameters(args): Parameters<SqlQueryArgs>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        Ok(self
            .run_sql(&peer, &args.target, &args.sql, &args.params, "sql_query")
            .await)
    }

    #[tool(
        name = "sql_describe",
        description = "Describe a Postgres target: without `table`, list the tables and views the role can see; with \
                       `table` (`name` or `schema.name`), list its columns."
    )]
    async fn sql_describe(
        &self,
        Parameters(args): Parameters<SqlDescribeArgs>,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (sql, params) = describe_query(args.table.as_deref());
        Ok(self.run_sql(&peer, &args.target, sql, &params, "sql_describe").await)
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

/// The fixed queries behind `sql_describe`; the table name is always a parameter.
fn describe_query(table: Option<&str>) -> (&'static str, Vec<Value>) {
    match table {
        None => (
            "SELECT table_schema, table_name, table_type FROM information_schema.tables \
             WHERE table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY 1, 2",
            vec![],
        ),
        Some(t) => {
            let (schema, name) = match t.split_once('.') {
                Some((s, n)) => (json!(s), json!(n)),
                None => (Value::Null, json!(t)),
            };
            (
                "SELECT table_schema, column_name, data_type, is_nullable, column_default \
                 FROM information_schema.columns \
                 WHERE table_name = $1 AND ($2::text IS NULL OR table_schema = $2) \
                 ORDER BY table_schema, ordinal_position",
                vec![name, schema],
            )
        }
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
    /// The tools that work on this target now.
    tools: Vec<&'static str>,
    reason: String,
    /// The fence state that applies, for protected targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    fence: Option<&'static str>,
}

impl Broker {
    async fn targets_report(&self, peer: &Peer<RoleServer>) -> TargetsReport {
        let s = resolve(&self.config, peer).await;
        let client = ClientReport {
            name: s.client_name.clone(),
            version: s.client_version.clone(),
            fence_profile: s.fence_profile,
        };
        let Some(snapshot) = s.snapshot.as_ref() else {
            return TargetsReport {
                project: s.project_report(&self.config),
                client,
                targets: Vec::new(),
            };
        };
        let targets = snapshot
            .config
            .targets
            .keys()
            .map(|id| {
                let t = &snapshot.config.targets[id];
                let exposure = t.secret.as_ref().map(|r| r.exposure(self.config.platform));
                match evaluate(&self.config, &s, id.as_str()) {
                    Ok(u) => TargetReport {
                        id: id.to_string(),
                        kind: t.kind.clone(),
                        writable: t.writable,
                        secret_exposure: exposure,
                        available: true,
                        tools: vec!["sql_query", "sql_describe"],
                        reason: "usable".into(),
                        fence: u.fence,
                    },
                    Err(reason) => TargetReport {
                        id: id.to_string(),
                        kind: t.kind.clone(),
                        writable: t.writable,
                        secret_exposure: exposure,
                        available: false,
                        tools: vec![],
                        reason,
                        fence: None,
                    },
                }
            })
            .collect();
        TargetsReport {
            project: s.project_report(&self.config),
            client,
            targets,
        }
    }

    /// Steps 1–4 for one SQL call. Refusals and failures are tool errors with fixed or
    /// server-provided text; never secrets.
    async fn run_sql(
        &self,
        peer: &Peer<RoleServer>,
        target: &str,
        sql: &str,
        params: &[Value],
        tool: &str,
    ) -> CallToolResult {
        let started = std::time::Instant::now();
        let statement_hash = blake3::hash(sql.as_bytes()).to_hex()[..16].to_owned();
        let s = resolve(&self.config, peer).await;
        let usable = match evaluate(&self.config, &s, target) {
            Ok(u) => u,
            Err(reason) => {
                tracing::info!(tool, target = %sanitize(target), outcome = "refused", "sql call");
                return tool_error(reason);
            }
        };
        let result = self.execute(&s, &usable, sql, params).await;
        let ms = started.elapsed().as_millis();
        match result {
            Ok(mut out) => {
                tracing::info!(
                    tool,
                    target,
                    statement_hash,
                    rows = out["row_count"].as_u64(),
                    ms,
                    outcome = "ok",
                    "sql call"
                );
                if let Some(fence) = usable.fence {
                    out["fence"] = json!(fence);
                }
                out["target"] = json!(target);
                match ContentBlock::json(out) {
                    Ok(block) => CallToolResult::success(vec![block]),
                    Err(_) => tool_error("internal error: the result couldn't be encoded".into()),
                }
            }
            Err((public, detail)) => {
                tracing::warn!(tool, target, statement_hash, ms, outcome = "error", detail = %detail, "sql call");
                tool_error(public)
            }
        }
    }

    async fn execute(&self, s: &Session, u: &Usable, sql: &str, params: &[Value]) -> Result<Value, (String, String)> {
        let user = UserConfig::load(&self.config.root).map_err(|e| {
            (
                "valetkey's user config can't be read; ask a human to run `valetkey doctor`".to_owned(),
                e.to_string(),
            )
        })?;
        let project = s.project.as_ref().expect("policy passed, so there is a project");
        let snapshot = s.snapshot.as_ref().expect("policy passed, so there is a snapshot");
        let reference = u
            .target
            .secret
            .as_ref()
            .ok_or(("internal error: the target has no secret".to_owned(), String::new()))?;
        let key = CacheKey {
            project_key: project.key.to_string(),
            config_hash: snapshot.config_hash.to_string(),
            target: u.id.clone(),
            reference: reference.to_string(),
        };
        let cx = valetkey_core::secret_source::FetchCx {
            project_root: &project.root,
            root: &self.config.root,
            user: &user,
        };
        let password = self
            .cache
            .get_or_fetch(key.clone(), || valetkey_secrets::fetch(reference, &cx))
            .await
            .map_err(|e| (e.to_string(), e.detail().to_owned()))?;

        let endpoint = u
            .spec
            .endpoint()
            .map_err(|e| ("internal error: the target's endpoint is malformed".to_owned(), e))?;
        let request = ReadRequest {
            endpoint,
            database: &u.spec.database,
            user: &u.spec.user,
            password: &password,
            // The checks run for protected targets and for every socket target: the agent can't
            // reach a socket itself, so the read path is its only route (M2b review N1). Exposed
            // TCP targets skip them: tech debt until M4 knows which targets the agent can reach.
            run_checks: u.protected || u.spec.socket.is_some(),
            allow_prepared_transactions: u.spec.allow_prepared_transactions,
            extra_extensions: &u.spec.allow_extensions,
            allow_grant_drift: u.spec.allow_grant_drift,
            sql,
            params,
            limits: u.spec.limits(),
        };
        match read(request).await {
            Ok(result) => serde_json::to_value(result).map_err(|e| ("internal error".to_owned(), e.to_string())),
            Err(e) => {
                if e.is_auth_failure() {
                    self.cache.invalidate(&key);
                }
                Err((e.to_string(), e.detail()))
            }
        }
    }
}

fn tool_error(message: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message)])
}

fn sanitize(s: &str) -> String {
    valetkey_core::sanitize::for_display(s)
}
