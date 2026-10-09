//! Audit records for the SQL tools (§6.7 step 7), built here and written by
//! [`valetkey_core::audit`].
//!
//! Reads that can't be audited still run (a full or broken disk shouldn't stop the read path), with
//! a warning in `mcp.log`; writes can't run without their `approved` record.

use std::time::Instant;

use serde_json::Value;
use valetkey_core::audit::{self, ApprovalRef, AuditRecord, Outcome};
use valetkey_postgres::values::TextParam;

use crate::Broker;
use crate::session::Session;

/// A record being filled in during one call.
#[derive(Debug)]
pub(crate) struct Draft {
    pub record: AuditRecord,
    started: Instant,
}

impl Draft {
    pub fn session(&mut self, s: &Session) {
        self.record.client_name.clone_from(&s.client_name);
        self.record.client_version.clone_from(&s.client_version);
        if let Some(p) = &s.project {
            self.record.project_key = Some(p.key.as_str().to_owned());
            self.record.project_root = Some(p.root.display().to_string());
        }
    }

    pub fn approval(&mut self, approval: ApprovalRef) {
        self.record.approval = Some(approval);
    }
}

impl Broker {
    pub(crate) fn draft(&self, tool: &str, target: &str, sql: &str, params: &[Value]) -> Draft {
        Draft {
            record: AuditRecord {
                time: String::new(),
                tool: tool.to_owned(),
                outcome: Outcome::Ok,
                target: Some(target.to_owned()),
                project_key: None,
                project_root: None,
                client_name: None,
                client_version: None,
                broker_pid: std::process::id(),
                session_id: self.session_id.clone(),
                statement: Some(sql.to_owned()),
                statement_hash: Some(valetkey_core::write_request::statement_hash(sql)),
                params: params.iter().map(param_text).collect(),
                rows: None,
                rows_affected: None,
                truncated: None,
                reason: None,
                approval: None,
                duration_ms: None,
            },
            started: Instant::now(),
        }
    }

    /// Writes the record with `outcome`. `false` (and a warning in `mcp.log`) when it can't be
    /// written.
    pub(crate) fn audit(&self, draft: &Draft, outcome: Outcome, reason: Option<&str>) -> bool {
        let mut record = draft.record.clone();
        record.time = now();
        record.outcome = outcome;
        if reason.is_some() {
            record.reason = reason.map(str::to_owned);
        }
        record.duration_ms = Some(u64::try_from(draft.started.elapsed().as_millis()).unwrap_or(u64::MAX));
        match audit::append(&self.config.root, &record) {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, tool = %record.tool, "AUDIT LOG NOT WRITTEN");
                false
            }
        }
    }
}

/// RFC 3339, UTC, seconds.
pub(crate) fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A parameter as it's sent; values that can't be sent are recorded as their JSON.
fn param_text(v: &Value) -> Option<String> {
    match TextParam::from_json(v) {
        Ok(p) => p.0,
        Err(_) => Some(v.to_string()),
    }
}
