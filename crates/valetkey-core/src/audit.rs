//! The audit log (§6.7 step 7): one JSON line per SQL tool call in
//! `~/.valetkey/audit/<YYYY-MM>.<N>.jsonl`.
//!
//! - Each record is written with one `write_all` while holding an exclusive `flock` on the file,
//!   so records from concurrent brokers never interleave.
//! - Files never stop growing because of a cap: past [`ROLLOVER_BYTES`] the next record goes to
//!   `<N+1>`. (A stopping cap would let the agent switch auditing off by padding its calls.)
//! - A write gets an [`Outcome::Approved`] record **before** it executes and an outcome record
//!   after. An `approved` record with no outcome record for the same request means the outcome is
//!   unknown: the broker was killed in between.
//! - Never a secret. Statement text and parameters are the agent's own input.
//!
//! The directory is write-denied to the agent by the fence (§6.5), and deny-read from M4.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths::{ValetkeyRoot, check_private, ensure_private_dir};

/// A file rolls over to the next number past this size.
pub const ROLLOVER_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("the audit directory {0} is not private: {1}")]
    NotPrivate(PathBuf, String),
    #[error("{0} isn't a regular, singly linked file")]
    NotRegular(PathBuf),
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

/// How a call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Ok,
    /// Refused by policy or a guard before anything ran.
    Refused,
    /// Failed while running (rolled back for writes).
    Error,
    /// A human denied the write, or it changed while waiting.
    Denied,
    /// Nobody decided in time.
    Timeout,
    /// The client cancelled, or the broker shut down, before the write was approved.
    Cancelled,
    /// Written before an approved write executes.
    Approved,
    /// The commit's result is unknown (the connection dropped during `COMMIT`).
    Unknown,
}

/// The approval behind a write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRef {
    pub id: String,
    pub request_hash: String,
    pub decided_at: String,
    pub tty: Option<String>,
}

/// One audit record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// RFC 3339, UTC.
    pub time: String,
    pub tool: String,
    pub outcome: Outcome,
    pub target: Option<String>,
    pub project_key: Option<String>,
    pub project_root: Option<String>,
    /// Client-supplied.
    pub client_name: Option<String>,
    pub client_version: Option<String>,
    pub broker_pid: u32,
    pub session_id: String,
    pub statement: Option<String>,
    pub statement_hash: Option<String>,
    /// Text as sent; `null` is SQL NULL.
    pub params: Vec<Option<String>>,
    pub rows: Option<u64>,
    pub rows_affected: Option<u64>,
    pub truncated: Option<bool>,
    /// Why it was refused or failed, or a note (fixed text, or the server's message).
    pub reason: Option<String>,
    pub approval: Option<ApprovalRef>,
    pub duration_ms: Option<u64>,
}

/// Appends one record.
pub fn append(root: &ValetkeyRoot, record: &AuditRecord) -> Result<(), AuditError> {
    let dir = root.audit_dir();
    let io_err = |path: &Path| {
        let path = path.to_owned();
        move |source| AuditError::Io { path, source }
    };
    ensure_private_dir(&dir).map_err(io_err(&dir))?;
    check_private(&dir).map_err(|e| AuditError::NotPrivate(dir.clone(), e))?;
    let month = record.time.get(..7).unwrap_or("unknown").to_owned();
    let mut line = serde_json::to_vec(record).expect("an audit record serializes");
    line.push(b'\n');

    let mut n = files(root)
        .into_iter()
        .filter_map(|(m, n, _)| (m == month).then_some(n))
        .max()
        .unwrap_or(1);
    loop {
        let path = dir.join(format!("{month}.{n}.jsonl"));
        let file = open_append(&path).map_err(io_err(&path))?;
        let mut file = lock(file).map_err(io_err(&path))?;
        let meta = file.metadata().map_err(io_err(&path))?;
        if !meta.is_file() || link_count(&meta) != 1 {
            return Err(AuditError::NotRegular(path));
        }
        if meta.len() >= ROLLOVER_BYTES {
            n += 1;
            continue;
        }
        file.write_all(&line).map_err(io_err(&path))?;
        return Ok(());
    }
}

/// The audit files, oldest first: `(month, n, path)`.
pub fn files(root: &ValetkeyRoot) -> Vec<(String, u32, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(root.audit_dir()) else {
        return Vec::new();
    };
    let mut out: Vec<(String, u32, PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let stem = name.strip_suffix(".jsonl")?;
            let (month, n) = stem.rsplit_once('.')?;
            let valid_month = month.len() == 7 && month.as_bytes()[4] == b'-';
            valid_month.then_some((month.to_owned(), n.parse().ok()?, e.path()))
        })
        .collect();
    out.sort();
    out
}

/// Reads the records of one file. Lines that don't parse are returned as errors, not skipped.
pub fn read_file(path: &Path) -> Result<Vec<Result<AuditRecord, String>>, AuditError> {
    let file = open_read(path).map_err(|source| AuditError::Io {
        path: path.to_owned(),
        source,
    })?;
    Ok(read_lines(BufReader::new(file)))
}

/// Parses audit lines from any reader (used by `valetkey log --follow` too).
pub fn read_lines(reader: impl BufRead) -> Vec<Result<AuditRecord, String>> {
    reader
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(&l).map_err(|e| e.to_string()))
        .collect()
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    options.open(path)
}

/// Opens an audit file for reading without following links.
pub fn open_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(file)
}

#[cfg(unix)]
fn lock(file: File) -> io::Result<nix::fcntl::Flock<File>> {
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive).map_err(|(_, e)| io::Error::from(e))
}

#[cfg(not(unix))]
fn lock(file: File) -> io::Result<File> {
    Ok(file)
}

#[cfg(unix)]
fn link_count(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.nlink()
}

#[cfg(not(unix))]
fn link_count(_: &std::fs::Metadata) -> u64 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn record(time: &str, outcome: Outcome) -> AuditRecord {
        AuditRecord {
            time: time.into(),
            tool: "sql_execute".into(),
            outcome,
            target: Some("local-app".into()),
            project_key: Some("pk".into()),
            project_root: Some("/work/app".into()),
            client_name: Some("claude-code".into()),
            client_version: None,
            broker_pid: 1,
            session_id: "s".into(),
            statement: Some("UPDATE t SET a = 1".into()),
            statement_hash: Some("h".into()),
            params: vec![None, Some("x".into())],
            rows: None,
            rows_affected: Some(3),
            truncated: Some(false),
            reason: None,
            approval: None,
            duration_ms: Some(5),
        }
    }

    #[test]
    fn appends_by_month_and_reads_back() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        let a = record("2026-10-09T10:00:00Z", Outcome::Approved);
        let b = record("2026-10-09T10:00:01Z", Outcome::Ok);
        let c = record("2026-11-01T00:00:00Z", Outcome::Ok);
        for r in [&a, &b, &c] {
            append(&root, r).unwrap();
        }
        let f = files(&root);
        assert_eq!(
            f.iter().map(|(m, n, _)| (m.as_str(), *n)).collect::<Vec<_>>(),
            [("2026-10", 1), ("2026-11", 1)]
        );
        let october: Vec<AuditRecord> = read_file(&f[0].2).unwrap().into_iter().map(Result::unwrap).collect();
        assert_eq!(october, [a, b]);
    }

    #[test]
    fn full_files_roll_over_instead_of_stopping() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        let r = record("2026-10-09T10:00:00Z", Outcome::Ok);
        append(&root, &r).unwrap();
        let first = &files(&root)[0].2;
        std::fs::OpenOptions::new()
            .write(true)
            .open(first)
            .unwrap()
            .set_len(ROLLOVER_BYTES)
            .unwrap();
        append(&root, &r).unwrap();
        append(&root, &r).unwrap();
        let f = files(&root);
        assert_eq!(f.len(), 2);
        assert_eq!(f[1].1, 2);
        assert_eq!(read_file(&f[1].2).unwrap().len(), 2);
    }

    #[test]
    fn concurrent_appends_never_interleave() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        let mut big = record("2026-10-09T10:00:00Z", Outcome::Ok);
        big.statement = Some("x".repeat(200 * 1024));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (root, big) = (root.clone(), big.clone());
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        append(&root, &big).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let records = read_file(&files(&root)[0].2).unwrap();
        assert_eq!(records.len(), 80);
        assert!(records.iter().all(Result::is_ok));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_audit_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        ensure_private_dir(&root.audit_dir()).unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::write(&elsewhere, "").unwrap();
        std::os::unix::fs::symlink(&elsewhere, root.audit_dir().join("2026-10.1.jsonl")).unwrap();
        assert!(append(&root, &record("2026-10-09T10:00:00Z", Outcome::Ok)).is_err());
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"");
    }
}
