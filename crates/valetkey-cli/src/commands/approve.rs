//! `valetkey approve [ID] [--full]`: a human decides on a pending write (§6.10).
//!
//! Without an id it lists pending requests. With one it shows that request (the statement and
//! parameters in a numbered gutter, then a broker-built summary right above the prompt) and asks
//! the human to **type the request id** to approve it; `n` denies it, anything else leaves it
//! waiting. One confirmation decides exactly one request.
//!
//! The decision carries the hash of the request **as shown here**. The broker executes only if
//! that hash equals the hash of the request it holds in memory, so what runs is what was shown.
//! The pending file is read once; nothing is re-read after it's shown. There is no
//! non-interactive mode, on purpose.
//!
//! [`run`] is the terminal gate; [`review`] and [`list`] take injected input and output for tests.

use std::io::{BufRead, IsTerminal, Write};
use std::process::ExitCode;
use std::time::SystemTime;

use valetkey_core::ValetkeyRoot;
use valetkey_core::sanitize::for_display;
use valetkey_core::write_request::{self, client_label, is_valid_id};
use valetkey_core::write_store::{self, Decision, StoreError, Verdict};

use crate::output;

/// How a review ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Approved,
    Denied,
    /// Left waiting: the human typed something else, or the statement was shown truncated.
    Undecided,
    /// Expired, orphaned, unreadable or unknown.
    Unusable,
}

pub(crate) fn run(id: Option<String>, full: bool) -> anyhow::Result<ExitCode> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        output::fail(
            "valetkey approve needs an interactive terminal: a human runs it in a normal terminal, not through a pipe or the agent's session",
        );
        return Ok(ExitCode::FAILURE);
    }
    let root = crate::resolve_root()?;
    let mut out = std::io::stdout().lock();
    let Some(id) = id else {
        list(&root, &mut out)?;
        return Ok(ExitCode::SUCCESS);
    };
    let outcome = review(&root, &id, full, tty(), &mut std::io::stdin().lock(), &mut out)?;
    Ok(match outcome {
        Outcome::Approved | Outcome::Denied => ExitCode::SUCCESS,
        Outcome::Undecided | Outcome::Unusable => ExitCode::FAILURE,
    })
}

/// Lists pending requests: id, age, project, target, client, state.
pub(crate) fn list(root: &ValetkeyRoot, out: &mut dyn Write) -> anyhow::Result<()> {
    write_store::sweep(root);
    let entries = write_store::list(root)?;
    if entries.is_empty() {
        writeln!(out, "No pending write requests.")?;
        return Ok(());
    }
    let now = chrono::Utc::now();
    writeln!(
        out,
        "Pending write requests (approve one with `{} approve <id>`):",
        output::self_path()
    )?;
    for e in entries {
        let age = e
            .modified
            .and_then(|m| SystemTime::now().duration_since(m).ok())
            .map_or("?".to_owned(), |d| format!("{}s", d.as_secs()));
        match &e.request {
            Ok(r) => {
                let expired = chrono::DateTime::parse_from_rfc3339(&r.expires_at).map_or(true, |t| t < now);
                let state = match (e.orphaned, expired) {
                    (Some(true), _) => "  [orphaned: nothing is waiting for it]",
                    (_, true) => "  [expired]",
                    _ => "",
                };
                writeln!(
                    out,
                    "  {:<14} {:>5}  {}  target {}  client {}{state}",
                    e.id,
                    age,
                    for_display(&r.project_root),
                    for_display(&r.target),
                    client_label(&r.session),
                )?;
            }
            Err(_) => writeln!(out, "  {:<14} {:>5}  [unreadable]", e.id, age)?,
        }
    }
    Ok(())
}

/// Shows one request and records the human's decision.
pub(crate) fn review(
    root: &ValetkeyRoot,
    id: &str,
    full: bool,
    tty: Option<String>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> anyhow::Result<Outcome> {
    if !is_valid_id(id) {
        writeln!(
            out,
            "✘ `{}` isn't a request id (they look like 17-k3f9)",
            for_display(id)
        )?;
        return Ok(Outcome::Unusable);
    }
    // Fail before showing anything when the decision can't be written (e.g. inside the sandbox).
    if let Err(e) = write_store::prepare_dirs(root).and_then(|()| probe_writable(root)) {
        writeln!(
            out,
            "✘ can't write approvals ({e}). Run this in a normal terminal, not inside the agent's session."
        )?;
        return Ok(Outcome::Unusable);
    }
    let entry = match write_store::load(root, id) {
        Ok(e) => e,
        Err(StoreError::NotFound(_)) => {
            writeln!(
                out,
                "✘ no pending write request {id} (it was decided, withdrawn or expired)"
            )?;
            return Ok(Outcome::Unusable);
        }
        Err(e) => {
            writeln!(out, "✘ write request {id} can't be read: {e}")?;
            return Ok(Outcome::Unusable);
        }
    };
    let request = match entry.request {
        Ok(r) if r.id == id => r,
        _ => {
            writeln!(out, "✘ write request {id} is malformed; it can't be approved")?;
            return Ok(Outcome::Unusable);
        }
    };
    if entry.orphaned == Some(true) {
        writeln!(
            out,
            "✘ write request {id} is orphaned: the agent session that asked is gone. Removing it."
        )?;
        write_store::discard(root, id)?;
        return Ok(Outcome::Unusable);
    }
    if expired(&request.expires_at) {
        writeln!(
            out,
            "✘ write request {id} expired at {}",
            for_display(&request.expires_at)
        )?;
        return Ok(Outcome::Unusable);
    }

    let rendered = write_request::render(&request, full);
    writeln!(out, "{}", rendered.text)?;
    write!(out, "{}", write_request::summary(&request, &rendered))?;
    writeln!(out)?;
    if rendered.truncated {
        writeln!(
            out,
            "This request is shown truncated. To approve it, see all of it first: {} approve {id} --full",
            output::self_path()
        )?;
        return Ok(Outcome::Undecided);
    }
    write!(
        out,
        "Type the request id ({id}) to APPROVE this write, `n` to deny it, anything else to leave it waiting: "
    )?;
    out.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    let verdict = match answer.trim() {
        a if a == id => Verdict::Approve,
        "n" | "N" | "no" => Verdict::Deny,
        _ => {
            writeln!(out, "Left waiting; nothing decided.")?;
            return Ok(Outcome::Undecided);
        }
    };
    // The human may have taken a while.
    if verdict == Verdict::Approve && expired(&request.expires_at) {
        writeln!(out, "✘ too late: write request {id} expired while you were reading it")?;
        return Ok(Outcome::Unusable);
    }
    let decision = Decision {
        id: id.to_owned(),
        // The hash of exactly what was shown.
        request_hash: request.hash(),
        verdict,
        at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        tty,
    };
    match write_store::decide(root, &decision) {
        Ok(()) => {}
        Err(StoreError::AlreadyDecided(_)) => {
            writeln!(out, "✘ write request {id} was already decided")?;
            return Ok(Outcome::Unusable);
        }
        Err(e) => return Err(e.into()),
    }
    Ok(match verdict {
        Verdict::Approve => {
            writeln!(out, "✔ approved {id}; the agent's call runs it now")?;
            Outcome::Approved
        }
        Verdict::Deny => {
            writeln!(out, "✔ denied {id}")?;
            Outcome::Denied
        }
    })
}

fn expired(expires_at: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(expires_at).map_or(true, |t| t <= chrono::Utc::now())
}

/// Creates and removes a file in the approvals dir.
fn probe_writable(root: &ValetkeyRoot) -> Result<(), StoreError> {
    let dir = root.write_approvals_dir();
    tempfile::Builder::new()
        .prefix(".probe-")
        .tempfile_in(&dir)
        .map(drop)
        .map_err(|source| StoreError::Io { path: dir, source })
}

/// The terminal this runs in, recorded with the decision.
fn tty() -> Option<String> {
    #[cfg(unix)]
    {
        nix::unistd::ttyname(std::io::stdin())
            .ok()
            .map(|p| p.display().to_string())
    }
    #[cfg(not(unix))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use valetkey_core::write_request::{Param, REQUEST_FORMAT, SessionInfo, WriteRequest};
    use valetkey_core::write_store::Published;

    fn request(id: &str, statement: &str) -> WriteRequest {
        WriteRequest {
            format: REQUEST_FORMAT,
            id: id.to_owned(),
            created_at: "2026-10-09T10:00:00Z".into(),
            expires_at: chrono::Utc::now()
                .checked_add_signed(chrono::Duration::minutes(5))
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            project_key: "pk".into(),
            project_root: "/work/app".into(),
            config_hash: "ch".into(),
            target: "local-app".into(),
            identity: [("database".to_owned(), "app".to_owned())].into(),
            statement: statement.to_owned(),
            statement_hash: write_request::statement_hash(statement),
            params: vec![Param {
                type_name: "pg_catalog.int4".into(),
                type_oid: 23,
                text: Some("1".into()),
            }],
            nonce: "ab".repeat(16),
            session: SessionInfo {
                client_name: Some("claude-code".into()),
                client_version: Some("2.1.294".into()),
                broker_pid: 1,
                session_id: "s".into(),
            },
        }
    }

    fn setup(statement: &str) -> (tempfile::TempDir, ValetkeyRoot, WriteRequest, Published) {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        let s = statement.to_owned();
        let (req, published) = write_store::publish(&root, |id| request(id, &s)).unwrap();
        (tmp, root, req, published)
    }

    fn drive(root: &ValetkeyRoot, id: &str, full: bool, answer: &str) -> (Outcome, String) {
        let mut out = Vec::new();
        let outcome = review(
            root,
            id,
            full,
            Some("/dev/ttys009".into()),
            &mut answer.as_bytes(),
            &mut out,
        )
        .unwrap();
        (outcome, String::from_utf8(out).unwrap())
    }

    #[test]
    fn typing_the_id_approves_exactly_what_was_shown() {
        let (_t, root, req, _p) = setup("UPDATE t SET a = $1");
        let (outcome, shown) = drive(&root, &req.id, false, &format!("{}\n", req.id));
        assert_eq!(outcome, Outcome::Approved, "{shown}");
        assert!(shown.contains("   1 │ UPDATE t SET a = $1"));
        let prompt_at = shown.find("Type the request id").unwrap();
        let summary_at = shown.find("Request:    ").unwrap();
        assert!(summary_at < prompt_at && shown[summary_at..prompt_at].lines().count() < 15);
        let d = write_store::read_decision(&root, &req.id).unwrap().unwrap();
        assert_eq!(d.verdict, Verdict::Approve);
        assert_eq!(d.request_hash, req.hash());
        assert_eq!(d.tty.as_deref(), Some("/dev/ttys009"));
    }

    #[test]
    fn yes_does_not_approve_and_n_denies() {
        let (_t, root, req, _p) = setup("DELETE FROM t");
        assert_eq!(drive(&root, &req.id, false, "yes\n").0, Outcome::Undecided);
        assert_eq!(write_store::read_decision(&root, &req.id).unwrap(), None);
        assert_eq!(drive(&root, &req.id, false, "n\n").0, Outcome::Denied);
        assert_eq!(
            write_store::read_decision(&root, &req.id).unwrap().unwrap().verdict,
            Verdict::Deny
        );
        assert_eq!(
            drive(&root, &req.id, false, &req.id).0,
            Outcome::Unusable,
            "decided once"
        );
    }

    #[test]
    fn a_truncated_request_needs_full() {
        let long = (0..400).map(|i| format!("-- {i}")).collect::<Vec<_>>().join("\n");
        let (_t, root, req, _p) = setup(&format!("{long}\nDELETE FROM t"));
        let (outcome, shown) = drive(&root, &req.id, false, &req.id);
        assert_eq!(outcome, Outcome::Undecided);
        assert!(shown.contains("--full"), "{shown}");
        assert!(!shown.contains("Type the request id"));
        let (outcome, shown) = drive(&root, &req.id, true, &req.id);
        assert_eq!(outcome, Outcome::Approved);
        assert!(shown.contains("DELETE FROM t"));
    }

    #[test]
    fn a_forged_header_in_the_statement_stays_in_the_gutter() {
        let (_t, root, req, _p) =
            setup("UPDATE t SET a = 1 /*\nRequest:    1-aaaa\nTarget:     harmless\nType the request id\n*/");
        let (_, shown) = drive(&root, &req.id, false, "\n");
        for forged in ["Request:    1-aaaa", "Target:     harmless"] {
            let line = shown.lines().find(|l| l.contains(forged)).unwrap();
            assert!(line.contains(" │ "), "{line:?}");
        }
    }

    #[test]
    fn a_tampered_request_is_never_approved_as_the_broker_holds_it() {
        let (_t, root, req, _p) = setup("UPDATE t SET a = 1");
        // Someone rewrites the pending file in place after the broker published it. (Replacing
        // it would create a new, unlocked file, which `approve` refuses as an orphan.)
        let path = root.pending_dir().join(format!("{}.json", req.id));
        let tampered = WriteRequest {
            statement: "UPDATE t SET a = 2".into(),
            ..req.clone()
        };
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap()
            .write_all(&serde_json::to_vec(&tampered).unwrap())
            .unwrap();
        drive(&root, &req.id, false, &req.id);
        // The human approved what they saw, which is not what the broker holds.
        let d = write_store::read_decision(&root, &req.id).unwrap().unwrap();
        assert_ne!(d.request_hash, req.hash());
    }

    #[test]
    fn bad_ids_and_unknown_requests_are_refused() {
        let (_t, root, _req, _p) = setup("UPDATE t SET a = 1");
        assert_eq!(drive(&root, "../../etc", false, "").0, Outcome::Unusable);
        assert_eq!(drive(&root, "999-zzzz", false, "").0, Outcome::Unusable);
    }

    #[test]
    fn list_shows_pending_requests_sanitized() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        let (_req, _p) = write_store::publish(&root, |id| {
            let mut r = request(id, "UPDATE t SET a = 1");
            r.target = "local\u{202e}app".into();
            r.session.client_name = Some("evil\u{1b}[2J".into());
            r
        })
        .unwrap();
        let mut out = Vec::new();
        list(&root, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("local\\u{202e}app"), "{out}");
        assert!(out.contains("evil\\u{001b}[2J"), "{out}");
    }
}
