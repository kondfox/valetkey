//! `sql_execute`: writes with out-of-band human approval (§6.10).
//!
//! 1. **Reserve** the target's slot, synchronously, before anything awaits: one outstanding write
//!    per target per broker (= per client session), so concurrent calls can't slip past it.
//! 2. Session and policy (the target must be `writable`), the secret, then the pre-approval
//!    connection ([`prepare_write`]): identity, checks, `prepare`. Nothing is written.
//! 3. **Publish** the request (`~/.valetkey/pending/<id>.json`) and keep it in memory. Only the
//!    in-memory copy is ever executed.
//! 4. **Wait** for `~/.valetkey/write-approvals/<id>.json`. The wait ends on a decision, on the
//!    client cancelling the call (`notifications/cancelled` only fires a token in rmcp; the handler
//!    isn't dropped), on broker shutdown, or at the deadline. Every exit but an approval withdraws
//!    the request. Progress notifications keep the client's idle timer from expiring, and one
//!    elicitation shows the human the command to run; its answer is ignored.
//! 5. **Check** the decision (approve, this request's hash, an unused nonce, before the deadline),
//!    then session and policy **again** (the human may have run `allow` meanwhile): same approved
//!    config, same project, still writable, same exposure.
//! 6. Write the `approved` audit record (no record, no write), then execute in a task on the
//!    broker's tracker, which ignores cancellation and is awaited at shutdown, so an approved write
//!    always ends with an outcome record.
//!
//! Before M4 the approval store isn't fenced from the agent; see the M3 decision page.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::model::{CallToolResult, ContentBlock, ProgressNotificationParam};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, schemars};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};
use valetkey_core::audit::{ApprovalRef, Outcome};
use valetkey_core::write_request::{self, DEFAULT_APPROVAL_TIMEOUT, Param, REQUEST_FORMAT, SessionInfo, WriteRequest};
use valetkey_core::write_store::{self, Decision, Verdict};
use valetkey_postgres::write::{Prepared, WriteTarget, execute_write, prepare_write};

use crate::audit::Draft;
use crate::policy::{Usable, evaluate};
use crate::session::{Session, resolve};
use crate::{Broker, check_input, tool_error};

/// How often the broker looks for a decision.
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// How often it sends progress while waiting (the client's idle timer resets on progress).
const PROGRESS_INTERVAL: Duration = Duration::from_secs(15);

/// Arguments of `sql_execute`.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SqlExecuteArgs {
    /// The target id, as listed by `valetkey_targets`. It must be writable.
    pub target: String,
    /// Exactly one SQL statement. A human sees it in full and approves it in a terminal before it
    /// runs; it then commits as a whole or not at all.
    pub sql: String,
    /// Values for `$1`, `$2`, …: strings, numbers, booleans or null. They're sent as data, never
    /// as SQL, and the human sees them with their types.
    #[serde(default)]
    pub params: Vec<Value>,
    /// Must be `true`: confirms that this call writes.
    pub allow_write: bool,
}

/// Default for `BrokerConfig::approval_timeout`.
pub const APPROVAL_TIMEOUT: Duration = DEFAULT_APPROVAL_TIMEOUT;

/// Per-broker write state.
#[derive(Debug, Default)]
pub(crate) struct WriteState {
    /// Target id → the pending request id, once published.
    slots: Mutex<HashMap<String, Option<String>>>,
    consumed_nonces: Mutex<HashSet<String>>,
}

/// One target's slot; released on drop.
#[derive(Debug)]
pub(crate) struct Slot {
    state: Arc<WriteState>,
    target: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.state.slots.lock().expect("slots lock").remove(&self.target);
    }
}

impl WriteState {
    /// Takes the target's slot, or returns the id already waiting (`None` while it's being prepared).
    fn reserve(self: &Arc<Self>, target: &str) -> Result<Slot, Option<String>> {
        let mut slots = self.slots.lock().expect("slots lock");
        if let Some(existing) = slots.get(target) {
            return Err(existing.clone());
        }
        slots.insert(target.to_owned(), None);
        Ok(Slot {
            state: self.clone(),
            target: target.to_owned(),
        })
    }

    fn set_id(&self, target: &str, id: &str) {
        if let Some(slot) = self.slots.lock().expect("slots lock").get_mut(target) {
            *slot = Some(id.to_owned());
        }
    }

    /// `true` the first time a nonce is seen.
    fn consume(&self, nonce: &str) -> bool {
        self.consumed_nonces
            .lock()
            .expect("nonce lock")
            .insert(nonce.to_owned())
    }
}

/// An empty form: the elicitation only displays the instruction.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct Acknowledge {}
rmcp::elicit_safe!(Acknowledge);

/// How a call ended before execution: outcome, text for the agent, detail for the log.
struct Exit {
    outcome: Outcome,
    public: String,
    detail: String,
}

enum TaskError {
    Exit(Exit),
    Db(valetkey_postgres::read::ReadError),
}

impl Exit {
    fn new(outcome: Outcome, public: impl Into<String>) -> Self {
        let public = public.into();
        Self {
            outcome,
            detail: public.clone(),
            public,
        }
    }
}

impl Broker {
    pub(crate) async fn execute_with_approval(
        &self,
        args: SqlExecuteArgs,
        ctx: RequestContext<RoleServer>,
    ) -> CallToolResult {
        // Tracked, so shutdown waits for withdrawals and outcomes to be audited.
        let this = self.clone();
        self.tracker.track_future(this.execute_flow(args, ctx)).await
    }

    async fn execute_flow(self, args: SqlExecuteArgs, ctx: RequestContext<RoleServer>) -> CallToolResult {
        let mut draft = self.draft("sql_execute", &args.target, &args.sql, &args.params);
        let statement_hash = draft.record.statement_hash.clone().unwrap_or_default();
        let short_hash = statement_hash.get(..16).unwrap_or_default().to_owned();
        let end = |draft: &Draft, exit: Exit| {
            self.audit(draft, exit.outcome, Some(&exit.public));
            tracing::info!(tool = "sql_execute", target = %crate::sanitize(&args.target), statement_hash = %short_hash, outcome = ?exit.outcome, detail = %exit.detail, "sql call");
            tool_error(exit.public)
        };

        if !args.allow_write {
            return end(
                &draft,
                Exit::new(
                    Outcome::Refused,
                    "refused: sql_execute writes; set allow_write = true to confirm",
                ),
            );
        }
        if let Err(m) = check_input(&args.sql, &args.params) {
            return end(&draft, Exit::new(Outcome::Refused, m));
        }
        // Synchronous, before the first await (M3 review B7).
        let slot = match self.writes.reserve(&args.target) {
            Ok(slot) => slot,
            Err(Some(id)) => {
                return end(
                    &draft,
                    Exit::new(
                        Outcome::Refused,
                        format!(
                            "refused: write request {id} for this target is still waiting for a human (`{} approve {id}`); one at a time per target",
                            self.config.self_path.display()
                        ),
                    ),
                );
            }
            Err(None) => {
                return end(
                    &draft,
                    Exit::new(
                        Outcome::Refused,
                        "refused: another write for this target is being prepared; one at a time per target",
                    ),
                );
            }
        };

        let s = resolve(&self.config, &ctx.peer).await;
        draft.session(&s);
        let usable = match evaluate(&self.config, &s, &args.target) {
            Ok(u) => u,
            Err(reason) => return end(&draft, Exit::new(Outcome::Refused, reason)),
        };
        if !usable.target.writable {
            return end(
                &draft,
                Exit::new(
                    Outcome::Refused,
                    format!(
                        "refused: `{}` isn't writable; a human can set writable = true in valetkey.toml and run `{} allow`",
                        args.target,
                        self.config.self_path.display()
                    ),
                ),
            );
        }
        let password = match self.fetch_secret(&s, &usable).await {
            Ok((p, _)) => p,
            Err((public, detail)) => {
                return end(
                    &draft,
                    Exit {
                        outcome: Outcome::Error,
                        public,
                        detail,
                    },
                );
            }
        };
        let prepared = {
            let target = match write_target(&usable, &password) {
                Ok(t) => t,
                Err(exit) => return end(&draft, exit),
            };
            match prepare_write(&target, &args.sql, &args.params).await {
                Ok(p) => p,
                Err(e) => {
                    if e.is_auth_failure() {
                        self.invalidate_secret(&s, &usable);
                    }
                    let outcome = match e {
                        valetkey_postgres::read::ReadError::Refused(_)
                        | valetkey_postgres::read::ReadError::Guard(_)
                        | valetkey_postgres::read::ReadError::Identity { .. } => Outcome::Refused,
                        _ => Outcome::Error,
                    };
                    return end(
                        &draft,
                        Exit {
                            outcome,
                            public: e.to_string(),
                            detail: e.detail(),
                        },
                    );
                }
            }
        };
        drop(password);

        let (request, published) = match self.publish(&s, &usable, &args, &prepared) {
            Ok(x) => x,
            Err(detail) => {
                return end(
                    &draft,
                    Exit {
                        outcome: Outcome::Error,
                        public: "the write request couldn't be stored; ask a human to run `valetkey doctor`".into(),
                        detail,
                    },
                );
            }
        };
        let id = request.id.clone();
        self.writes.set_id(&args.target, &id);
        tracing::info!(id = %id, target = %args.target, statement_hash = %short_hash, "write waiting for approval");

        let decision = match self.wait(&ctx, &id).await {
            Ok(d) => d,
            Err(exit) => {
                published.withdraw();
                return end(&draft, exit);
            }
        };
        // The decision is read; neither file can authorize anything again.
        published.withdraw();
        drop(published);
        if let Err(exit) = self.check_decision(&request, &decision) {
            return end(&draft, exit);
        }
        draft.approval(ApprovalRef {
            id: id.clone(),
            request_hash: decision.request_hash.clone(),
            decided_at: decision.at.clone(),
            tty: decision.tty.clone(),
        });

        // The human may have run `allow` while we waited (M3 review B6).
        let s2 = resolve(&self.config, &ctx.peer).await;
        let usable2 = match self.recheck(&s2, &usable, &request) {
            Ok(u) => u,
            Err(exit) => return end(&draft, exit),
        };
        let password = match self.fetch_secret(&s2, &usable2).await {
            Ok((p, _)) => p,
            Err((public, detail)) => {
                return end(
                    &draft,
                    Exit {
                        outcome: Outcome::Error,
                        public,
                        detail,
                    },
                );
            }
        };
        if !self.audit(&draft, Outcome::Approved, None) {
            return end(
                &draft,
                Exit::new(
                    Outcome::Error,
                    "the audit log can't be written, so the approved write was not executed; ask a human to run `valetkey doctor`",
                ),
            );
        }

        // Detached and tracked: cancellation can't cut it off, and shutdown waits for it.
        let sql = args.sql.clone();
        let params = args.params.clone();
        let target_id = args.target.clone();
        let handle = self.tracker.spawn(async move {
            let _slot = slot;
            let target = match write_target(&usable2, &password) {
                Ok(t) => t,
                Err(exit) => return (Err(TaskError::Exit(exit)), draft),
            };
            let result = execute_write(&target, &sql, &params, &prepared).await;
            (result.map_err(TaskError::Db), draft)
        });
        let (result, mut draft) = match handle.await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "the write task failed");
                return tool_error(
                    "internal error: the write task failed; its outcome is unknown, check the data".into(),
                );
            }
        };
        match result {
            Ok(out) => {
                draft.record.rows = Some(out.row_count as u64);
                draft.record.rows_affected = out.rows_affected;
                draft.record.truncated = Some(out.truncated);
                self.audit(&draft, Outcome::Ok, None);
                tracing::info!(tool = "sql_execute", target = %target_id, statement_hash = %short_hash, id = %id, rows_affected = out.rows_affected, outcome = "ok", "sql call");
                let mut value = match serde_json::to_value(&out) {
                    Ok(v) => v,
                    Err(_) => return tool_error("committed, but the result couldn't be encoded".into()),
                };
                value["target"] = json!(target_id);
                value["approval"] = json!({ "id": id });
                if let Some(fence) = usable.fence {
                    value["fence"] = json!(fence);
                }
                match ContentBlock::json(value) {
                    Ok(block) => CallToolResult::success(vec![block]),
                    Err(_) => tool_error("committed, but the result couldn't be encoded".into()),
                }
            }
            Err(TaskError::Exit(exit)) => end(&draft, exit),
            Err(TaskError::Db(e)) => {
                let outcome = match e {
                    valetkey_postgres::read::ReadError::CommitUnknown(_) => Outcome::Unknown,
                    valetkey_postgres::read::ReadError::Changed(_)
                    | valetkey_postgres::read::ReadError::Identity { .. } => Outcome::Denied,
                    _ => Outcome::Error,
                };
                end(
                    &draft,
                    Exit {
                        outcome,
                        public: e.to_string(),
                        detail: e.detail(),
                    },
                )
            }
        }
    }

    fn publish(
        &self,
        s: &Session,
        u: &Usable,
        args: &SqlExecuteArgs,
        prepared: &Prepared,
    ) -> Result<(WriteRequest, write_store::Published), String> {
        let project = s.project.as_ref().ok_or("no project")?;
        let snapshot = s.snapshot.as_ref().ok_or("no snapshot")?;
        let created = chrono::Utc::now();
        let expires = created + chrono::Duration::from_std(self.config.approval_timeout).unwrap_or_default();
        let fmt = |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let nonce = write_request::random_hex(16);
        write_store::sweep(&self.config.root);
        write_store::publish(&self.config.root, |id| WriteRequest {
            format: REQUEST_FORMAT,
            id: id.to_owned(),
            created_at: fmt(created),
            expires_at: fmt(expires),
            project_key: project.key.as_str().to_owned(),
            project_root: project.root.display().to_string(),
            config_hash: snapshot.config_hash.to_string(),
            target: u.id.clone(),
            identity: prepared.identity.clone(),
            statement: args.sql.clone(),
            statement_hash: write_request::statement_hash(&args.sql),
            params: prepared
                .params
                .iter()
                .map(|p| Param {
                    type_name: p.type_name.clone(),
                    type_oid: p.type_oid,
                    text: p.text.clone(),
                })
                .collect(),
            nonce: nonce.clone(),
            session: SessionInfo {
                client_name: s.client_name.clone(),
                client_version: s.client_version.clone(),
                broker_pid: std::process::id(),
                session_id: self.session_id.clone(),
            },
        })
        .map_err(|e| e.to_string())
    }

    /// Waits for a decision on `id`. See the module docs for what ends the wait.
    async fn wait(&self, ctx: &RequestContext<RoleServer>, id: &str) -> Result<Decision, Exit> {
        let timeout = self.config.approval_timeout;
        let deadline = tokio::time::Instant::now() + timeout;
        let instruction = format!(
            "Approval needed: run `{} approve {id}` in a normal terminal (not inside the agent's session). The request expires in {} seconds.",
            self.config.self_path.display(),
            timeout.as_secs()
        );
        let progress_token = ctx.meta.get_progress_token();
        let peer = ctx.peer.clone();
        // Display only: never awaited for the decision, and its answer is ignored (§6.10).
        let shows_form = peer
            .supported_elicitation_modes()
            .contains(&rmcp::service::ElicitationMode::Form);
        let elicitation = peer.elicit::<Acknowledge>(instruction.clone());
        tokio::pin!(elicitation);
        let mut elicitation_open = shows_form;
        let mut poll = tokio::time::interval(POLL_INTERVAL);
        let mut progress = tokio::time::interval(PROGRESS_INTERVAL);
        let started = tokio::time::Instant::now();
        loop {
            tokio::select! {
                () = ctx.ct.cancelled() => {
                    return Err(Exit::new(Outcome::Cancelled, format!("cancelled by the client; write request {id} was withdrawn")));
                }
                () = self.shutdown.cancelled() => {
                    return Err(Exit::new(Outcome::Cancelled, format!("the broker is shutting down; write request {id} was withdrawn")));
                }
                () = tokio::time::sleep_until(deadline) => {
                    return Err(Exit::new(Outcome::Timeout, format!("no human approved write request {id} within {} seconds; nothing was written", timeout.as_secs())));
                }
                _ = &mut elicitation, if elicitation_open => {
                    elicitation_open = false;
                }
                _ = progress.tick() => {
                    if let Some(token) = progress_token.clone() {
                        let mut p = ProgressNotificationParam::new(token, started.elapsed().as_secs_f64());
                        p.total = Some(timeout.as_secs_f64());
                        p.message = Some(instruction.clone());
                        let _ = peer.notify_progress(p).await;
                    }
                }
                _ = poll.tick() => {
                    match write_store::read_decision(&self.config.root, id) {
                        Ok(Some(d)) => return Ok(d),
                        Ok(None) => {}
                        Err(e) => {
                            return Err(Exit { outcome: Outcome::Denied, public: format!("write request {id} was denied: its approval file is unusable"), detail: e.to_string() });
                        }
                    }
                }
            }
        }
    }

    fn check_decision(&self, request: &WriteRequest, d: &Decision) -> Result<(), Exit> {
        let id = &request.id;
        if d.verdict == Verdict::Deny {
            return Err(Exit::new(
                Outcome::Denied,
                format!("a human denied write request {id}; nothing was written"),
            ));
        }
        if d.id != *id || d.request_hash != request.hash() {
            return Err(Exit::new(
                Outcome::Denied,
                format!("write request {id} was denied: the approval doesn't match this request"),
            ));
        }
        if !self.writes.consume(&request.nonce) {
            return Err(Exit::new(
                Outcome::Denied,
                format!("write request {id} was denied: its nonce was already used"),
            ));
        }
        Ok(())
    }

    /// Session and policy again, after the wait. Anything the approval depended on must be the same.
    fn recheck(&self, s: &Session, before: &Usable, request: &WriteRequest) -> Result<Usable, Exit> {
        let changed = |what: &str| {
            Exit::new(
                Outcome::Denied,
                format!(
                    "write request {} was denied: {what} changed while it waited for approval; nothing was written",
                    request.id
                ),
            )
        };
        let usable = evaluate(&self.config, s, &before.id).map_err(|reason| changed(&format!("policy ({reason})")))?;
        let snapshot = s
            .snapshot
            .as_ref()
            .ok_or_else(|| changed("the approved configuration"))?;
        let project = s.project.as_ref().ok_or_else(|| changed("the project"))?;
        if snapshot.config_hash.to_string() != request.config_hash {
            return Err(changed("the approved configuration"));
        }
        if project.key.as_str() != request.project_key || project.root.display().to_string() != request.project_root {
            return Err(changed("the project"));
        }
        if !usable.target.writable {
            return Err(changed("the target's writable flag"));
        }
        if usable.protected != before.protected || usable.spec != before.spec {
            return Err(changed("the target"));
        }
        Ok(usable)
    }
}

fn write_target<'a>(u: &'a Usable, password: &'a SecretString) -> Result<WriteTarget<'a>, Exit> {
    let endpoint = u
        .spec
        .endpoint()
        .map_err(|_| Exit::new(Outcome::Error, "internal error: the target's endpoint is malformed"))?;
    Ok(WriteTarget {
        endpoint,
        database: &u.spec.database,
        user: &u.spec.user,
        password,
        // The same rules as reads (see `Broker::execute`).
        run_checks: u.protected || u.spec.socket.is_some(),
        allow_prepared_transactions: u.spec.allow_prepared_transactions && !u.protected,
        extra_extensions: &u.spec.allow_extensions,
        allow_grant_drift: u.spec.allow_grant_drift,
        limits: u.spec.limits(),
    })
}
