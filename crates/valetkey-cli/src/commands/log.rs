//! `valetkey log [--follow]`: the audit log of SQL tool calls, one line per record, oldest first.
//!
//! An approved write whose outcome was never recorded (the broker was killed between `approved`
//! and the outcome) is shown as `unknown`. Everything printed is sanitized.

use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use valetkey_core::ValetkeyRoot;
use valetkey_core::audit::{self, AuditRecord, Outcome};
use valetkey_core::sanitize::for_display;

const STATEMENT_PREVIEW_CHARS: usize = 80;

pub(crate) fn run(follow: bool) -> anyhow::Result<ExitCode> {
    let root = crate::resolve_root()?;
    let mut out = std::io::stdout().lock();
    let mut offsets = print_all(&root, &mut out)?;
    if !follow {
        return Ok(ExitCode::SUCCESS);
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
        for (_, _, path) in audit::files(&root) {
            let offset = offsets.entry(path.clone()).or_insert(0);
            let Ok(mut file) = audit::open_read(&path) else {
                continue;
            };
            if file.seek(SeekFrom::Start(*offset)).is_err() {
                continue;
            }
            let mut buf = String::new();
            let Ok(n) = file.read_to_string(&mut buf) else { continue };
            // Only complete lines; a partial one is read again next time.
            let complete = buf.rfind('\n').map_or(0, |i| i + 1);
            *offset += complete.min(n) as u64;
            for record in audit::read_lines(&buf.as_bytes()[..complete]) {
                writeln!(out, "{}", format(&record, false))?;
            }
            out.flush()?;
        }
    }
}

/// Prints every record and returns how far each file was read.
pub(crate) fn print_all(root: &ValetkeyRoot, out: &mut dyn Write) -> anyhow::Result<HashMap<PathBuf, u64>> {
    let mut offsets = HashMap::new();
    let mut records = Vec::new();
    for (_, _, path) in audit::files(root) {
        let file = audit::open_read(&path)?;
        let len = file.metadata()?.len();
        records.extend(audit::read_lines(BufReader::new(file.take(len))));
        offsets.insert(path, len);
    }
    if records.is_empty() {
        writeln!(out, "The audit log is empty.")?;
    }
    // Approved writes with an outcome record later.
    let finished: HashSet<String> = records
        .iter()
        .flatten()
        .filter(|r| r.outcome != Outcome::Approved)
        .filter_map(|r| r.approval.as_ref().map(|a| a.id.clone()))
        .collect();
    for record in &records {
        let unknown = matches!(record, Ok(r) if r.outcome == Outcome::Approved
            && r.approval.as_ref().is_some_and(|a| !finished.contains(&a.id)));
        writeln!(out, "{}", format(record, unknown))?;
    }
    Ok(offsets)
}

fn format(record: &Result<AuditRecord, String>, unknown: bool) -> String {
    let r = match record {
        Ok(r) => r,
        Err(e) => return format!("[unreadable record: {}]", for_display(e)),
    };
    let outcome = if unknown {
        "unknown (approved; no outcome recorded)".to_owned()
    } else {
        format!("{:?}", r.outcome).to_lowercase()
    };
    let mut line = format!(
        "{}  {:<9} {:<12} {}",
        for_display(&r.time),
        outcome,
        r.tool,
        for_display(r.target.as_deref().unwrap_or("-"))
    );
    if let Some(a) = &r.approval {
        line.push_str(&format!("  approval {}", for_display(&a.id)));
    }
    if let Some(n) = r.rows_affected {
        line.push_str(&format!("  affected {n}"));
    } else if let Some(n) = r.rows {
        line.push_str(&format!("  rows {n}"));
    }
    if let Some(h) = &r.statement_hash {
        line.push_str(&format!("  {}", h.get(..12).unwrap_or(h)));
    }
    if let Some(s) = &r.statement {
        let first = s.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        let preview: String = first.chars().take(STATEMENT_PREVIEW_CHARS).collect();
        let more = if s.trim().lines().count() > 1 || first.chars().count() > STATEMENT_PREVIEW_CHARS {
            " …"
        } else {
            ""
        };
        line.push_str(&format!("  {}{more}", for_display(preview.trim())));
    }
    if let Some(reason) = &r.reason
        && r.outcome != Outcome::Ok
    {
        line.push_str(&format!("  ({})", for_display(reason)));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use valetkey_core::audit::ApprovalRef;

    fn record(outcome: Outcome, approval: Option<&str>) -> AuditRecord {
        AuditRecord {
            time: "2026-10-09T10:00:00Z".into(),
            tool: "sql_execute".into(),
            outcome,
            target: Some("local-app".into()),
            project_key: None,
            project_root: None,
            client_name: None,
            client_version: None,
            broker_pid: 1,
            session_id: "s".into(),
            statement: Some("UPDATE t\u{202e} SET a = 1\nWHERE id = 2".into()),
            statement_hash: Some("0123456789abcdef".into()),
            params: vec![],
            rows: None,
            rows_affected: (outcome == Outcome::Ok).then_some(1),
            truncated: None,
            reason: None,
            approval: approval.map(|id| ApprovalRef {
                id: id.into(),
                request_hash: "h".into(),
                decided_at: "t".into(),
                tty: None,
            }),
            duration_ms: None,
        }
    }

    #[test]
    fn prints_sanitized_and_marks_approved_writes_without_an_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        for r in [
            record(Outcome::Approved, Some("1-aaaa")),
            record(Outcome::Ok, Some("1-aaaa")),
            record(Outcome::Approved, Some("2-bbbb")),
        ] {
            audit::append(&root, &r).unwrap();
        }
        let mut out = Vec::new();
        print_all(&root, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert!(lines[0].contains("approved") && !lines[0].contains("unknown"), "{out}");
        assert!(lines[1].contains("ok") && lines[1].contains("affected 1"), "{out}");
        assert!(lines[2].contains("unknown (approved; no outcome recorded)"), "{out}");
        assert!(out.contains("UPDATE t\\u{202e} SET a = 1 …"), "{out}");
    }
}
