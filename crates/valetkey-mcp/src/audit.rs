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

/// A target id longer than this is cut in the record (ids in an approved config are short; a
/// longer one is the agent's free text).
const MAX_TARGET_CHARS: usize = 128;
/// What a record keeps of a statement that was refused for its size.
const REFUSED_HEAD_BYTES: usize = 1024;

impl Broker {
    /// A record of a call whose input passed [`crate::check_input`], so it's bounded.
    pub(crate) fn draft(&self, tool: &str, target: &str, sql: &str, params: &[Value]) -> Draft {
        Draft {
            record: AuditRecord {
                time: String::new(),
                tool: tool.to_owned(),
                outcome: Outcome::Ok,
                target: Some(target.chars().take(MAX_TARGET_CHARS).collect()),
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

    /// A record of a call refused for its size (M3 code review C2): the statement's hash, length and
    /// first KiB, the parameter count, never the whole input. Otherwise oversized calls could fill
    /// the disk and switch read auditing off.
    pub(crate) fn draft_oversized(&self, tool: &str, target: &str, sql: &str, params: &[Value]) -> Draft {
        let mut draft = self.draft(tool, target, "", &[]);
        let mut cut = REFUSED_HEAD_BYTES.min(sql.len());
        while !sql.is_char_boundary(cut) {
            cut -= 1;
        }
        draft.record.statement = Some(sql[..cut].to_owned());
        draft.record.statement_hash = Some(valetkey_core::write_request::statement_hash(sql));
        draft.record.reason = Some(format!(
            "input too large; recorded: the first {cut} of {} statement bytes, none of the {} parameters",
            sql.len(),
            params.len()
        ));
        draft
    }

    /// Writes the record with `outcome`. `false` (and a warning in `mcp.log`) when it can't be
    /// written.
    pub(crate) fn audit(&self, draft: &Draft, outcome: Outcome, reason: Option<&str>) -> bool {
        let mut record = draft.record.clone();
        record.time = now();
        record.outcome = outcome;
        if let Some(reason) = reason {
            record.reason = Some(match record.reason.take() {
                Some(note) => format!("{reason} ({note})"),
                None => reason.to_owned(),
            });
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
