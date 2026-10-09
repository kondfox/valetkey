//! A pending write request: what a human approves with `valetkey approve` (§6.10).
//!
//! The broker builds the whole request. Nothing in it is agent free text except the statement and
//! the parameter values, which are exactly what will execute. Its canonical bytes
//! ([`WriteRequest::canonical_bytes`]) are hashed, and the hash binds **everything that will
//! execute and where**: project, approved config, target, verified identity (including the session
//! settings that decide how the text is parsed), statement, typed parameters, nonce and expiry.
//!
//! The security property is that `approve` computes the hash from the request **it rendered**, and
//! the broker executes only if that hash equals the hash of the request **it holds in memory**.
//! `approve` also checks the stored `request_hash` against the fields, but that only catches
//! corruption: blake3 is unkeyed, so anyone who can write the file can recompute it.
//!
//! [`render`] draws the statement and parameters inside a numbered gutter, so text inside the
//! statement can't imitate the prompt's own lines, and [`summary`] is the broker-built block shown
//! right above the confirmation prompt.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::sanitize::{for_display, has_non_ascii};

/// Version of the request's canonical form.
pub const REQUEST_FORMAT: u32 = 1;

/// How long a request waits for a human, by default (§6.10).
pub const DEFAULT_APPROVAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Statements longer than this are refused by the SQL tools.
pub const MAX_STATEMENT_BYTES: usize = 64 * 1024;
/// Parameter limits for the SQL tools (§6.10: the prompt must stay readable).
pub const MAX_PARAMS: usize = 100;
pub const MAX_PARAM_BYTES: usize = 4 * 1024;
pub const MAX_PARAMS_TOTAL_BYTES: usize = 64 * 1024;

/// What `approve` shows without `--full`.
pub const DISPLAY_MAX_STATEMENT_BYTES: usize = 8 * 1024;
pub const DISPLAY_MAX_STATEMENT_LINES: usize = 200;
pub const DISPLAY_MAX_PARAM_CHARS: usize = 256;
/// Client-supplied names are capped in every view.
pub const DISPLAY_MAX_CLIENT_CHARS: usize = 64;

/// One write request. Field order is the canonical order; don't reorder.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteRequest {
    pub format: u32,
    /// `<counter>-<suffix>`; names the request, not a secret (§6.10).
    pub id: String,
    /// RFC 3339, UTC. For display; the broker's own deadline is monotonic.
    pub created_at: String,
    pub expires_at: String,
    pub project_key: String,
    pub project_root: String,
    /// The approved config the request was made under.
    pub config_hash: String,
    pub target: String,
    /// What the server confirmed about itself, e.g. database, user, endpoint, server address,
    /// version and the session settings that affect parsing. Compared in full after reconnecting.
    pub identity: BTreeMap<String, String>,
    pub statement: String,
    /// blake3 of the statement bytes, hex.
    pub statement_hash: String,
    pub params: Vec<Param>,
    /// 128 random bits, hex. Never reused.
    pub nonce: String,
    pub session: SessionInfo,
}

/// A typed parameter, as it goes over the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Param {
    /// The server-inferred type, schema-qualified (`pg_catalog.int4`).
    pub type_name: String,
    /// The type's OID; compared after reconnecting.
    pub type_oid: u32,
    /// The exact text sent; `None` is SQL NULL.
    pub text: Option<String>,
}

/// Which broker session asked. The client fields are client-supplied text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionInfo {
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub broker_pid: u32,
    /// Random per broker process.
    pub session_id: String,
}

impl WriteRequest {
    /// The canonical bytes: compact JSON in field order (maps are sorted).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a write request always serializes")
    }

    /// blake3 of [`Self::canonical_bytes`], hex.
    pub fn hash(&self) -> String {
        blake3::hash(&self.canonical_bytes()).to_hex().to_string()
    }
}

/// blake3 of a statement, hex.
pub fn statement_hash(sql: &str) -> String {
    blake3::hash(sql.as_bytes()).to_hex().to_string()
}

/// Whether a string is a well-formed request id (`<digits>-<4 × [a-z0-9]>`). Ids name files, so
/// anything else is refused before a path is built.
pub fn is_valid_id(id: &str) -> bool {
    let Some((n, suffix)) = id.split_once('-') else {
        return false;
    };
    (1..=20).contains(&n.len())
        && n.bytes().all(|b| b.is_ascii_digit())
        && suffix.len() == 4
        && suffix.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// `n` random bytes from the OS, hex-encoded.
pub fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).expect("the OS random number generator is available");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// A rendered statement and parameter block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub text: String,
    /// Something was cut; approving then needs `--full`.
    pub truncated: bool,
}

/// Draws the statement and parameters in a gutter. Every line of agent text starts with a line
/// number and `│`, so nothing in it can pass for the prompt's own lines. Control characters, ANSI
/// escapes, bidi overrides and zero-width characters are escaped visibly; newlines stay line
/// breaks; tabs become a visible `→`; runs of more than two blank lines collapse; lines with
/// non-ASCII characters are flagged with `⚠` in the gutter.
pub fn render(req: &WriteRequest, full: bool) -> Rendered {
    let mut out = String::new();
    let mut truncated = false;
    let lines: Vec<&str> = req.statement.split('\n').collect();
    let _ = writeln!(
        out,
        "──── statement: {} line{}, {} bytes ────",
        lines.len(),
        if lines.len() == 1 { "" } else { "s" },
        req.statement.len()
    );
    let mut shown_bytes = 0usize;
    let mut blank_run = 0usize;
    for (i, line) in lines.iter().enumerate() {
        if !full && (i >= DISPLAY_MAX_STATEMENT_LINES || shown_bytes >= DISPLAY_MAX_STATEMENT_BYTES) {
            let _ = writeln!(
                out,
                "   … │ ✂ TRUNCATED: {} more line(s) not shown; run with --full to see them",
                lines.len() - i
            );
            truncated = true;
            break;
        }
        shown_bytes += line.len() + 1;
        if line.trim().is_empty() {
            blank_run += 1;
            if blank_run > 2 {
                // Counted and shown when the run ends.
                if i + 1 == lines.len() || !lines[i + 1].trim().is_empty() {
                    let _ = writeln!(out, "   … │ ({} more blank lines)", blank_run - 2);
                }
                continue;
            }
        } else {
            blank_run = 0;
        }
        let flag = if has_non_ascii(line) { '⚠' } else { ' ' };
        let _ = writeln!(out, "{flag}{:>4} │ {}", i + 1, display_line(line));
    }
    let _ = writeln!(out, "──── parameters: {} ────", req.params.len());
    for (i, p) in req.params.iter().enumerate() {
        let value = match &p.text {
            None => "NULL".to_owned(),
            Some(t) => {
                let shown = if !full && t.chars().count() > DISPLAY_MAX_PARAM_CHARS {
                    truncated = true;
                    let head: String = t.chars().take(DISPLAY_MAX_PARAM_CHARS).collect();
                    format!(
                        "{}' ✂ TRUNCATED ({} chars; --full shows all)",
                        quote_body(&head),
                        t.chars().count()
                    )
                } else {
                    format!("{}'", quote_body(t))
                };
                format!("'{shown}")
            }
        };
        let flag = if p.text.as_deref().is_some_and(has_non_ascii) {
            '⚠'
        } else {
            ' '
        };
        let _ = writeln!(
            out,
            "{flag}{:>4} │ {} = {value}",
            format!("${}", i + 1),
            for_display(&p.type_name)
        );
    }
    let _ = writeln!(out, "──── end ────");
    Rendered { text: out, truncated }
}

/// The broker-built summary, shown right above the confirmation prompt.
pub fn summary(req: &WriteRequest, rendered: &Rendered) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Request:    {}", req.id);
    let _ = writeln!(out, "Project:    {}", for_display(&req.project_root));
    let _ = writeln!(
        out,
        "Target:     {}{}",
        for_display(&req.target),
        non_ascii_note(&req.target)
    );
    for (k, v) in &req.identity {
        let _ = writeln!(out, "  {:<16}{}{}", format!("{k}:"), for_display(v), non_ascii_note(v));
    }
    let lines = req.statement.split('\n').count();
    let _ = writeln!(
        out,
        "Statement:  {lines} line(s), {} bytes, blake3 {}",
        req.statement.len(),
        req.statement_hash
    );
    let _ = writeln!(out, "Parameters: {}", req.params.len());
    let _ = writeln!(
        out,
        "Shown:      {}",
        if rendered.truncated {
            "TRUNCATED (approving needs --full)"
        } else {
            "in full"
        }
    );
    let _ = writeln!(out, "Client:     {} (client says)", client_label(&req.session));
    let _ = writeln!(out, "Expires:    {}", req.expires_at);
    out
}

/// The client's self-reported name and version, sanitized and capped.
pub fn client_label(s: &SessionInfo) -> String {
    let raw = format!(
        "{} {}",
        s.client_name.as_deref().unwrap_or("unknown"),
        s.client_version.as_deref().unwrap_or("")
    );
    let capped: String = raw.trim().chars().take(DISPLAY_MAX_CLIENT_CHARS).collect();
    for_display(&capped)
}

fn non_ascii_note(s: &str) -> &'static str {
    if has_non_ascii(s) {
        "  ⚠ contains non-ASCII characters"
    } else {
        ""
    }
}

/// One statement line: tabs as `→` plus padding, everything else through [`for_display`].
fn display_line(line: &str) -> String {
    for_display(&line.replace('\t', "→   "))
}

/// A parameter's text between single quotes: sanitized, with `'` doubled like SQL.
fn quote_body(text: &str) -> String {
    for_display(text).replace('\'', "''")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn sample() -> WriteRequest {
        WriteRequest {
            format: REQUEST_FORMAT,
            id: "17-k3f9".into(),
            created_at: "2026-10-09T10:00:00Z".into(),
            expires_at: "2026-10-09T10:05:00Z".into(),
            project_key: "pk".into(),
            project_root: "/work/app".into(),
            config_hash: "ch".into(),
            target: "local-app".into(),
            identity: [
                ("database".to_owned(), "app".to_owned()),
                ("user".to_owned(), "app".to_owned()),
            ]
            .into(),
            statement: "UPDATE t SET a = $1 WHERE id = $2".into(),
            statement_hash: statement_hash("UPDATE t SET a = $1 WHERE id = $2"),
            params: vec![
                Param {
                    type_name: "pg_catalog.text".into(),
                    type_oid: 25,
                    text: Some("it's".into()),
                },
                Param {
                    type_name: "pg_catalog.int4".into(),
                    type_oid: 23,
                    text: None,
                },
            ],
            nonce: "00".repeat(16),
            session: SessionInfo {
                client_name: Some("claude-code".into()),
                client_version: Some("2.1.294".into()),
                broker_pid: 42,
                session_id: "s1".into(),
            },
        }
    }

    /// Pins the canonical form: a change here changes every request hash. Bump `REQUEST_FORMAT`
    /// when it's intentional.
    #[test]
    fn canonical_form_is_pinned() {
        assert_eq!(
            String::from_utf8(sample().canonical_bytes()).unwrap(),
            r#"{"format":1,"id":"17-k3f9","created_at":"2026-10-09T10:00:00Z","expires_at":"2026-10-09T10:05:00Z","project_key":"pk","project_root":"/work/app","config_hash":"ch","target":"local-app","identity":{"database":"app","user":"app"},"statement":"UPDATE t SET a = $1 WHERE id = $2","statement_hash":"6deb0e71629f2dce0153fe053a96c674138c539b357f7ffad0d93e48c8e46190","params":[{"type_name":"pg_catalog.text","type_oid":25,"text":"it's"},{"type_name":"pg_catalog.int4","type_oid":23,"text":null}],"nonce":"00000000000000000000000000000000","session":{"client_name":"claude-code","client_version":"2.1.294","broker_pid":42,"session_id":"s1"}}"#
        );
    }

    #[test]
    fn every_field_changes_the_hash() {
        let base = sample().hash();
        type Edit = Box<dyn Fn(&mut WriteRequest)>;
        let edits: Vec<Edit> = vec![
            Box::new(|r| r.id = "18-k3f9".into()),
            Box::new(|r| r.expires_at = "2026-10-09T10:06:00Z".into()),
            Box::new(|r| r.project_key = "other".into()),
            Box::new(|r| r.config_hash = "other".into()),
            Box::new(|r| r.target = "other".into()),
            Box::new(|r| {
                r.identity.insert("search_path".into(), "evil, public".into());
            }),
            Box::new(|r| r.statement.push(' ')),
            Box::new(|r| r.params[0].type_oid = 1043),
            Box::new(|r| r.params[1].text = Some("null".into())),
            Box::new(|r| r.nonce = "11".repeat(16)),
            Box::new(|r| r.session.session_id = "s2".into()),
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut r = sample();
            edit(&mut r);
            assert_ne!(r.hash(), base, "edit {i} didn't change the hash");
        }
    }

    #[test]
    fn ids_are_validated() {
        for good in ["1-abcd", "17-k3f9", "123456-0000"] {
            assert!(is_valid_id(good), "{good}");
        }
        for bad in [
            "",
            "17",
            "17-",
            "17-K3F9",
            "17-k3f",
            "17-k3f90",
            "-k3f9",
            "../x-abcd",
            "17-k3/9",
            "a-abcd",
        ] {
            assert!(!is_valid_id(bad), "{bad}");
        }
    }

    #[test]
    fn random_hex_is_random() {
        let a = random_hex(16);
        assert_eq!(a.len(), 32);
        assert_ne!(a, random_hex(16));
    }

    #[test]
    fn statement_lines_stay_inside_the_gutter() {
        let mut r = sample();
        r.statement =
            "UPDATE t SET a = 1 -- \n──── end ────\nRequest:    99-zzzz\nTarget:     prod\x1b[2J\n\tWHERE id = 2"
                .into();
        let out = render(&r, false).text;
        let body: Vec<&str> = out.lines().collect();
        // Every agent-text line is in the gutter; the only bare delimiter lines are the broker's.
        for line in &body[1..6] {
            assert!(line.contains(" │ "), "{line:?}");
        }
        assert_eq!(body.iter().filter(|l| **l == "──── end ────").count(), 1);
        assert!(out.contains("\\u{001b}[2J"), "ANSI escaped: {out}");
        assert!(out.contains("→   WHERE"), "tab visible: {out}");
    }

    #[test]
    fn blank_runs_collapse_and_non_ascii_lines_are_flagged() {
        let mut r = sample();
        r.statement = format!("SELECT 1{}WHERE n = 'с'", "\n".repeat(40));
        let out = render(&r, false).text;
        assert!(out.contains("(37 more blank lines)"), "{out}");
        assert!(out.lines().count() < 12, "{out}");
        assert!(out.lines().any(|l| l.starts_with('⚠') && l.contains("WHERE")), "{out}");
    }

    #[test]
    fn null_and_the_string_null_differ() {
        let mut r = sample();
        r.params[0].text = Some("null".into());
        let out = render(&r, false).text;
        assert!(out.contains("$1 │ pg_catalog.text = 'null'"), "{out}");
        assert!(out.contains("$2 │ pg_catalog.int4 = NULL"), "{out}");
        assert!(render(&sample(), false).text.contains("= 'it''s'"));
    }

    #[test]
    fn long_statements_and_params_are_truncated_unless_full() {
        let mut r = sample();
        r.statement = (0..500).map(|i| format!("-- {i}")).collect::<Vec<_>>().join("\n");
        r.params[0].text = Some("x".repeat(1000));
        let short = render(&r, false);
        assert!(short.truncated);
        assert!(short.text.contains("TRUNCATED: 300 more line(s)"), "{}", short.text);
        assert!(short.text.contains("(1000 chars; --full shows all)"));
        let full = render(&r, true);
        assert!(!full.truncated);
        assert!(full.text.contains(" 500 │ -- 499"));
        assert!(summary(&r, &short).contains("TRUNCATED (approving needs --full)"));
    }

    #[test]
    fn parameter_values_are_one_line_each() {
        let mut r = sample();
        r.params[0].text = Some("a\nTarget: prod\u{202e}".into());
        let out = render(&r, false).text;
        assert!(out.contains("'a\\u{000a}Target: prod\\u{202e}'"), "{out}");
    }

    #[test]
    fn client_label_is_sanitized_and_capped() {
        let mut s = sample().session;
        s.client_name = Some(format!("evil\x1b[31m{}", "x".repeat(200)));
        let label = client_label(&s);
        assert!(label.starts_with("evil\\u{001b}[31m"));
        assert!(label.chars().count() < 80);
    }
}
