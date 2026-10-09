//! The two stores of §6.10: pending write requests (`~/.valetkey/pending/<id>.json`, written by
//! the broker) and human decisions (`~/.valetkey/write-approvals/<id>.json`, written by
//! `valetkey approve`).
//!
//! - Files are published atomically: written to a temporary name, then hard-linked into place
//!   (which never replaces an existing file), then the temporary name is removed. A reader never
//!   sees half a file, and an id is never reused.
//! - A live request is **locked**: the broker holds an exclusive `flock` on its pending file for
//!   the whole wait, taken on the temporary file before it's published. `approve` tries a shared
//!   lock; if it gets one, no broker is waiting and the request is an orphan (the client was
//!   killed, or the broker crashed). Windows has no `flock` here, so orphans are found only by
//!   expiry.
//! - Everything is read with [`read_private`]: no links, owned by the user, mode 0600, size cap.
//!
//! These files aren't the security boundary by themselves: the broker executes only what it holds
//! in memory, and only when a decision carries that request's hash (see [`crate::write_request`]).

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::paths::{ValetkeyRoot, check_private, ensure_private_dir};
use crate::safe_read::{SafeReadError, read_private};
use crate::write_request::{WriteRequest, is_valid_id, random_hex};

const MAX_FILE_LEN: u64 = 512 * 1024;
const SEQ_FILE: &str = ".seq";
/// Decisions whose request is gone are removed after this long.
const STALE_DECISION_AGE: Duration = Duration::from_secs(15 * 60);
/// Leftover temporary files are removed after this long.
const STALE_TMP_AGE: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid request id `{0}`")]
    InvalidId(String),
    #[error("{0} is not private: {1}")]
    NotPrivate(PathBuf, String),
    #[error("no pending request {0}")]
    NotFound(String),
    #[error("request {0} was already decided")]
    AlreadyDecided(String),
    #[error(transparent)]
    Read(#[from] SafeReadError),
    #[error("{path} is invalid: {message}")]
    Invalid { path: PathBuf, message: String },
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_owned(),
        source,
    }
}

/// What a human decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Approve,
    Deny,
}

/// The content of `write-approvals/<id>.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub id: String,
    /// The hash `approve` computed from the request it showed.
    pub request_hash: String,
    pub verdict: Verdict,
    /// RFC 3339, UTC.
    pub at: String,
    /// The terminal `approve` ran in, when known.
    pub tty: Option<String>,
}

fn pending_path(root: &ValetkeyRoot, id: &str) -> PathBuf {
    root.pending_dir().join(format!("{id}.json"))
}

fn decision_path(root: &ValetkeyRoot, id: &str) -> PathBuf {
    root.write_approvals_dir().join(format!("{id}.json"))
}

/// Creates the root and both store directories (0700) and checks they're private.
pub fn prepare_dirs(root: &ValetkeyRoot) -> Result<(), StoreError> {
    for dir in [root.dir().to_owned(), root.pending_dir(), root.write_approvals_dir()] {
        ensure_private_dir(&dir).map_err(io_err(&dir))?;
        check_private(&dir).map_err(|e| StoreError::NotPrivate(dir.clone(), e))?;
    }
    Ok(())
}

/// A published pending request. Holds the lock that marks it live; [`Published::withdraw`] (or
/// dropping it) removes the request and any decision for it.
#[derive(Debug)]
pub struct Published {
    root: ValetkeyRoot,
    id: String,
    #[cfg(unix)]
    _lock: nix::fcntl::Flock<File>,
    #[cfg(not(unix))]
    _lock: File,
}

impl Published {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Removes the request and its decision. Idempotent.
    pub fn withdraw(&self) {
        for path in [pending_path(&self.root, &self.id), decision_path(&self.root, &self.id)] {
            if let Err(e) = std::fs::remove_file(&path)
                && e.kind() != io::ErrorKind::NotFound
            {
                tracing::warn!("can't remove {}: {e}", path.display());
            }
        }
    }
}

impl Drop for Published {
    fn drop(&mut self) {
        self.withdraw();
    }
}

/// Publishes a new pending request. `build` gets the fresh id and returns the request to store;
/// it's called again with a new id if the first one is taken.
pub fn publish(
    root: &ValetkeyRoot,
    mut build: impl FnMut(&str) -> WriteRequest,
) -> Result<(WriteRequest, Published), StoreError> {
    prepare_dirs(root)?;
    for _ in 0..16 {
        let id = next_id(root)?;
        let request = build(&id);
        assert_eq!(request.id, id, "the request must carry the id it was built for");
        let mut bytes = serde_json::to_vec_pretty(&request).expect("a request serializes");
        bytes.extend_from_slice(b"\n");
        let tmp = root.pending_dir().join(format!(".tmp-{id}-{}", random_hex(4)));
        let file = write_new(&tmp, &bytes)?;
        let lock = lock_exclusive(file, &tmp)?;
        let target = pending_path(root, &id);
        let linked = std::fs::hard_link(&tmp, &target);
        let _ = std::fs::remove_file(&tmp);
        match linked {
            Ok(()) => {
                // A leftover decision with this id (after a crash) can't match this request's
                // hash and nonce, but it would deny it at once; clear it.
                let leftover = decision_path(root, &id);
                if std::fs::remove_file(&leftover).is_ok() {
                    tracing::warn!("removed a leftover decision for reused id {id}");
                }
                return Ok((
                    request,
                    Published {
                        root: root.clone(),
                        id,
                        _lock: lock,
                    },
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io_err(&target)(e)),
        }
    }
    Err(StoreError::Io {
        path: root.pending_dir(),
        source: io::Error::other("couldn't find a free request id"),
    })
}

/// `<counter>-<suffix>`. The counter is best effort (two brokers can read the same value); the
/// random suffix and the no-replace publish make ids unique.
fn next_id(root: &ValetkeyRoot) -> Result<String, StoreError> {
    let seq_path = root.pending_dir().join(SEQ_FILE);
    let current = match read_private(&seq_path, 64) {
        Ok(text) => text.trim().parse::<u64>().unwrap_or(0),
        Err(SafeReadError::NotFound(_)) => 0,
        Err(e) => {
            tracing::warn!("ignoring the request counter: {e}");
            0
        }
    };
    let next = current.saturating_add(1);
    let tmp = root.pending_dir().join(format!(".seq-{}", random_hex(4)));
    write_new(&tmp, format!("{next}\n").as_bytes())?;
    std::fs::rename(&tmp, &seq_path).map_err(io_err(&seq_path))?;
    let mut suffix = String::new();
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("the OS random number generator is available");
    for b in bytes {
        suffix.push(char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[usize::from(b) % 36]));
    }
    Ok(format!("{next}-{suffix}"))
}

/// One entry of [`list`].
#[derive(Debug)]
pub struct PendingEntry {
    pub id: String,
    pub request: Result<WriteRequest, String>,
    /// `Some(true)`: no broker is waiting for it. `None`: unknown (no `flock` on this platform).
    pub orphaned: Option<bool>,
    pub modified: Option<SystemTime>,
}

/// Every pending request, oldest id first.
pub fn list(root: &ValetkeyRoot) -> Result<Vec<PendingEntry>, StoreError> {
    let dir = root.pending_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io_err(&dir)(e)),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(".json") else { continue };
        if !is_valid_id(id) {
            continue;
        }
        let path = entry.path();
        out.push(PendingEntry {
            id: id.to_owned(),
            request: load_request(&path).map_err(|e| e.to_string()),
            orphaned: is_orphaned(&path),
            modified: entry.metadata().ok().and_then(|m| m.modified().ok()),
        });
    }
    out.sort_by_key(|e| {
        let (n, s) = e.id.split_once('-').unwrap_or((&e.id, ""));
        (n.parse::<u64>().unwrap_or(u64::MAX), s.to_owned())
    });
    Ok(out)
}

/// Loads one pending request for `approve`.
pub fn load(root: &ValetkeyRoot, id: &str) -> Result<PendingEntry, StoreError> {
    if !is_valid_id(id) {
        return Err(StoreError::InvalidId(id.to_owned()));
    }
    let path = pending_path(root, id);
    let mut request = load_request(&path);
    // A request is briefly hard-linked twice while it's being published.
    if matches!(request, Err(StoreError::Read(SafeReadError::HardLinked(_)))) {
        std::thread::sleep(Duration::from_millis(100));
        request = load_request(&path);
    }
    let request = match request {
        Err(StoreError::Read(SafeReadError::NotFound(_))) => return Err(StoreError::NotFound(id.to_owned())),
        other => other?,
    };
    Ok(PendingEntry {
        id: id.to_owned(),
        orphaned: is_orphaned(&path),
        modified: std::fs::metadata(&path).ok().and_then(|m| m.modified().ok()),
        request: Ok(request),
    })
}

fn load_request(path: &Path) -> Result<WriteRequest, StoreError> {
    let text = read_private(path, MAX_FILE_LEN)?;
    serde_json::from_str(&text).map_err(|e| StoreError::Invalid {
        path: path.to_owned(),
        message: e.to_string(),
    })
}

/// Removes a pending request (an orphan or an expired one) and any decision for it.
pub fn discard(root: &ValetkeyRoot, id: &str) -> Result<(), StoreError> {
    if !is_valid_id(id) {
        return Err(StoreError::InvalidId(id.to_owned()));
    }
    for path in [pending_path(root, id), decision_path(root, id)] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(&path)(e)),
        }
    }
    Ok(())
}

/// Records a human's decision. Never replaces an existing one.
pub fn decide(root: &ValetkeyRoot, decision: &Decision) -> Result<(), StoreError> {
    if !is_valid_id(&decision.id) {
        return Err(StoreError::InvalidId(decision.id.clone()));
    }
    prepare_dirs(root)?;
    let mut bytes = serde_json::to_vec_pretty(decision).expect("a decision serializes");
    bytes.push(b'\n');
    let tmp = root
        .write_approvals_dir()
        .join(format!(".tmp-{}-{}", decision.id, random_hex(4)));
    drop(write_new(&tmp, &bytes)?);
    let target = decision_path(root, &decision.id);
    let linked = std::fs::hard_link(&tmp, &target);
    let _ = std::fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(StoreError::AlreadyDecided(decision.id.clone())),
        Err(e) => Err(io_err(&target)(e)),
    }
}

/// The broker's poll: the decision for `id`, if one has been made. A file caught mid-publish
/// (two links) reads as "not yet".
pub fn read_decision(root: &ValetkeyRoot, id: &str) -> Result<Option<Decision>, StoreError> {
    let path = decision_path(root, id);
    match read_private(&path, MAX_FILE_LEN) {
        Ok(text) => serde_json::from_str(&text).map(Some).map_err(|e| StoreError::Invalid {
            path,
            message: e.to_string(),
        }),
        Err(SafeReadError::NotFound(_)) | Err(SafeReadError::HardLinked(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Removes what nobody can use any more: orphaned requests past their expiry (by wall clock),
/// decisions whose request is gone, and old temporary files. A live broker's request can look
/// expired by wall clock before its monotonic deadline passes; it's locked, so it's never swept,
/// and `approve` refuses it as expired.
pub fn sweep(root: &ValetkeyRoot) {
    let now = chrono::Utc::now();
    if let Ok(entries) = list(root) {
        for e in entries {
            let expired = match &e.request {
                Ok(r) => chrono::DateTime::parse_from_rfc3339(&r.expires_at).map_or(true, |t| t < now),
                Err(_) => true,
            };
            // Unknown lock state (Windows): only expiry decides.
            if expired && e.orphaned != Some(false) {
                let _ = discard(root, &e.id);
            }
        }
    }
    let age = |p: &Path| {
        std::fs::symlink_metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
    };
    for dir in [root.pending_dir(), root.write_approvals_dir()] {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            let stale = if name.starts_with(".tmp-") || (name.starts_with(".seq-")) {
                age(&path).is_some_and(|a| a > STALE_TMP_AGE)
            } else if dir == root.write_approvals_dir() {
                let request_gone = !root.pending_dir().join(&name).exists();
                request_gone && age(&path).is_some_and(|a| a > STALE_DECISION_AGE)
            } else {
                false
            };
            if stale {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// Creates a new private file and writes `bytes` to it.
fn write_new(path: &Path, bytes: &[u8]) -> Result<File, StoreError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(io_err(path))?;
    file.write_all(bytes).map_err(io_err(path))?;
    file.sync_all().map_err(io_err(path))?;
    Ok(file)
}

#[cfg(unix)]
fn lock_exclusive(file: File, path: &Path) -> Result<nix::fcntl::Flock<File>, StoreError> {
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, errno)| io_err(path)(io::Error::from(errno)))
}

#[cfg(not(unix))]
fn lock_exclusive(file: File, _: &Path) -> Result<File, StoreError> {
    Ok(file)
}

/// Whether nobody holds the request's lock. `None` when it can't be told.
#[cfg(unix)]
fn is_orphaned(path: &Path) -> Option<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockSharedNonblock) {
        Ok(_shared) => Some(true),
        Err((_, nix::errno::Errno::EWOULDBLOCK)) => Some(false),
        Err(_) => None,
    }
}

#[cfg(not(unix))]
fn is_orphaned(_: &Path) -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_request::tests::sample;

    fn root() -> (tempfile::TempDir, ValetkeyRoot) {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        (tmp, root)
    }

    fn build(id: &str) -> WriteRequest {
        WriteRequest {
            id: id.to_owned(),
            ..sample()
        }
    }

    #[test]
    fn publish_lists_and_withdraws() {
        let (_t, root) = root();
        let (req, published) = publish(&root, build).unwrap();
        assert!(is_valid_id(&req.id));
        let listed = list(&root).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].request.as_ref().unwrap(), &req);
        #[cfg(unix)]
        assert_eq!(listed[0].orphaned, Some(false), "the broker holds the lock");
        let loaded = load(&root, &req.id).unwrap();
        assert_eq!(loaded.request.unwrap().hash(), req.hash());
        drop(published);
        assert!(list(&root).unwrap().is_empty());
        assert!(matches!(load(&root, &req.id), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn ids_are_never_reused() {
        let (_t, root) = root();
        let (a, pa) = publish(&root, build).unwrap();
        drop(pa);
        let (b, _pb) = publish(&root, build).unwrap();
        assert_ne!(a.id, b.id);
        let n = |id: &str| id.split_once('-').unwrap().0.parse::<u64>().unwrap();
        assert!(n(&b.id) > n(&a.id), "{} then {}", a.id, b.id);
    }

    #[cfg(unix)]
    #[test]
    fn a_request_without_its_broker_is_an_orphan() {
        let (_t, root) = root();
        let (req, published) = publish(&root, build).unwrap();
        // A killed broker leaves the file without its lock. Simulate it: keep the original lock
        // alive but put an unlocked copy (a new inode) at the published path.
        std::mem::forget(published);
        let path = pending_path(&root, &req.id);
        let copy = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        drop(write_new(&path, &copy).unwrap());
        assert_eq!(load(&root, &req.id).unwrap().orphaned, Some(true));
    }

    #[test]
    fn decisions_are_written_once_and_read_back() {
        let (_t, root) = root();
        let (req, _p) = publish(&root, build).unwrap();
        assert_eq!(read_decision(&root, &req.id).unwrap(), None);
        let d = Decision {
            id: req.id.clone(),
            request_hash: req.hash(),
            verdict: Verdict::Approve,
            at: "2026-10-09T10:01:00Z".into(),
            tty: Some("/dev/ttys003".into()),
        };
        decide(&root, &d).unwrap();
        assert_eq!(read_decision(&root, &req.id).unwrap(), Some(d.clone()));
        assert!(matches!(decide(&root, &d), Err(StoreError::AlreadyDecided(_))));
    }

    #[test]
    fn invalid_ids_never_become_paths() {
        let (_t, root) = root();
        assert!(matches!(load(&root, "../../x-abcd"), Err(StoreError::InvalidId(_))));
        assert!(matches!(discard(&root, "a/b"), Err(StoreError::InvalidId(_))));
        let d = Decision {
            id: "../1-abcd".into(),
            request_hash: String::new(),
            verdict: Verdict::Deny,
            at: String::new(),
            tty: None,
        };
        assert!(matches!(decide(&root, &d), Err(StoreError::InvalidId(_))));
    }

    #[cfg(unix)]
    #[test]
    fn linked_or_loose_decisions_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_t, root) = root();
        let (req, _p) = publish(&root, build).unwrap();
        let path = decision_path(&root, &req.id);
        let elsewhere = root.dir().join("elsewhere.json");
        std::fs::write(&elsewhere, "{}").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        assert!(read_decision(&root, &req.id).is_err(), "symlink refused");
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_decision(&root, &req.id).is_err(), "loose mode refused");
    }

    #[cfg(unix)]
    #[test]
    fn sweep_removes_expired_orphans_but_not_live_requests() {
        let (_t, root) = root();
        let expired = |id: &str| WriteRequest {
            expires_at: "2000-01-01T00:00:00Z".into(),
            ..build(id)
        };
        let (live, _held) = publish(&root, expired).unwrap();
        let (orphan, p) = publish(&root, expired).unwrap();
        let path = pending_path(&root, &orphan.id);
        let copy = std::fs::read(&path).unwrap();
        drop(p);
        drop(write_new(&path, &copy).unwrap());
        sweep(&root);
        let ids: Vec<String> = list(&root).unwrap().into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![live.id]);
    }

    #[cfg(unix)]
    #[test]
    fn store_dirs_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_t, root) = root();
        prepare_dirs(&root).unwrap();
        std::fs::set_permissions(root.pending_dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(prepare_dirs(&root), Err(StoreError::NotPrivate(..))));
    }
}
