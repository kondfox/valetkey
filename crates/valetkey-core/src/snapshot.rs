//! Approved config snapshots (§6.1, decision `2026-10-04-human-approved-config-snapshot`).
//!
//! `valetkey allow` stores the canonical config a human approved in
//! `~/.valetkey/projects/<project-key>/snapshot.json`. The broker serves **only** that snapshot,
//! and only while the working `valetkey.toml` still canonicalizes to the same hash.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::{CANONICAL_FORMAT, ConfigHash, ProjectConfig};
use crate::paths::{ValetkeyRoot, ensure_private_dir};
use crate::project::Project;

const SNAPSHOT_FILE: &str = "snapshot.json";

/// Version of the snapshot file format.
pub const SNAPSHOT_FORMAT: u32 = 1;

/// What a human approved, and where.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub format: u32,
    /// The canonical project root the approval is bound to.
    pub project_root: PathBuf,
    pub config_hash: ConfigHash,
    pub config: ProjectConfig,
    pub approved_at_unix: u64,
    /// The valetkey version that wrote the snapshot.
    pub written_by: String,
}

impl Snapshot {
    pub fn new(project: &Project, config: ProjectConfig) -> Self {
        Self {
            format: SNAPSHOT_FORMAT,
            project_root: project.root.clone(),
            config_hash: config.hash(),
            config,
            approved_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            written_by: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("can't access {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{path} is corrupt: {source}")]
    Corrupt { path: PathBuf, source: serde_json::Error },
    #[error("{path} is inconsistent: {reason}")]
    Inconsistent { path: PathBuf, reason: &'static str },
}

fn snapshot_path(root: &ValetkeyRoot, project: &Project) -> PathBuf {
    root.project_dir(&project.key).join(SNAPSHOT_FILE)
}

/// Loads the project's snapshot, if one was ever approved.
pub fn load(root: &ValetkeyRoot, project: &Project) -> Result<Option<Snapshot>, SnapshotError> {
    let path = snapshot_path(root, project);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(SnapshotError::Io { path, source }),
    };
    let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|source| SnapshotError::Corrupt {
        path: path.clone(),
        source,
    })?;
    // The snapshot must be self-consistent: the broker compares against `config_hash` but serves
    // `config`, so the two must agree.
    let inconsistent = |reason| {
        Err(SnapshotError::Inconsistent {
            path: path.clone(),
            reason,
        })
    };
    if snapshot.format != SNAPSHOT_FORMAT {
        return inconsistent("unknown snapshot format");
    }
    if snapshot.config.format != CANONICAL_FORMAT {
        return inconsistent("unknown canonical format");
    }
    if snapshot.config.hash() != snapshot.config_hash {
        return inconsistent("the stored config doesn't match its hash");
    }
    Ok(Some(snapshot))
}

/// Stores a snapshot atomically (write a temp file in the same directory, sync, rename), with
/// owner-only permissions.
pub fn store(root: &ValetkeyRoot, project: &Project, snapshot: &Snapshot) -> Result<(), SnapshotError> {
    let path = snapshot_path(root, project);
    let dir = path.parent().expect("snapshot path has a parent");
    let io_err = |p: &Path| {
        let path = p.to_owned();
        move |source| SnapshotError::Io { path, source }
    };
    ensure_private_dir(dir).map_err(io_err(dir))?;
    let bytes = serde_json::to_vec_pretty(snapshot).expect("a snapshot always serializes");
    let mut tmp = tempfile_in(dir).map_err(io_err(dir))?;
    tmp.write_all(&bytes).map_err(io_err(&path))?;
    tmp.as_file().sync_all().map_err(io_err(&path))?;
    tmp.persist(&path).map_err(|e| SnapshotError::Io {
        path: path.clone(),
        source: e.error,
    })?;
    Ok(())
}

fn tempfile_in(dir: &Path) -> io::Result<tempfile::NamedTempFile> {
    // tempfile creates files with mode 0600 on unix.
    tempfile::Builder::new().prefix(".snapshot-").tempfile_in(dir)
}

/// Whether the working config may be served (§6.1).
#[derive(Clone, Debug, PartialEq)]
pub enum ApprovalState {
    /// No snapshot: a human never ran `valetkey allow` for this project.
    NotApproved,
    /// The snapshot matches the working config.
    Approved(Box<Snapshot>),
    /// The working config changed (or no longer parses) since approval.
    Stale { snapshot: Box<Snapshot>, reason: String },
    /// The snapshot belongs to a different root (it was written for another path).
    RootMismatch { snapshot: Box<Snapshot> },
}

impl ApprovalState {
    /// Compares the stored snapshot with the working config's canonical form. A config that can't
    /// be read or parsed is passed as `Err(())`: its details may quote file content, so they never
    /// end up in the state (callers log them).
    pub fn evaluate(snapshot: Option<Snapshot>, project: &Project, current: Result<&ProjectConfig, ()>) -> Self {
        let Some(snapshot) = snapshot else {
            return Self::NotApproved;
        };
        if snapshot.project_root != project.root {
            return Self::RootMismatch {
                snapshot: Box::new(snapshot),
            };
        }
        match current {
            Ok(config) if config.hash() == snapshot.config_hash => Self::Approved(Box::new(snapshot)),
            Ok(_) if snapshot.written_by != env!("CARGO_PKG_VERSION") => {
                let reason = format!(
                    "valetkey was upgraded since the approval ({} → {}), which can change how targets are checked; a human must re-approve",
                    snapshot.written_by,
                    env!("CARGO_PKG_VERSION")
                );
                Self::Stale {
                    snapshot: Box::new(snapshot),
                    reason,
                }
            }
            Ok(_) => Self::Stale {
                snapshot: Box::new(snapshot),
                reason: "valetkey.toml changed since it was approved".into(),
            },
            Err(()) => Self::Stale {
                snapshot: Box::new(snapshot),
                reason: "valetkey.toml can't be read or doesn't validate".into(),
            },
        }
    }

    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::parse;
    use crate::project::ProjectKey;

    fn project(root: &Path) -> Project {
        Project {
            root: root.to_owned(),
            config_path: root.join("valetkey.toml"),
            key: ProjectKey::for_root(root),
        }
    }

    #[test]
    fn store_and_load_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        let p = project(Path::new("/work/repo"));
        assert_eq!(load(&root, &p).unwrap(), None);

        let snap = Snapshot::new(&p, parse("[targets.a]\nkind = \"fake\"\n").unwrap());
        store(&root, &p, &snap).unwrap();
        assert_eq!(load(&root, &p).unwrap(), Some(snap));
    }

    #[cfg(unix)]
    #[test]
    fn stored_snapshot_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        let p = project(Path::new("/work/repo"));
        store(&root, &p, &Snapshot::new(&p, parse("").unwrap())).unwrap();
        let mode = std::fs::metadata(snapshot_path(&root, &p))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn inconsistent_snapshots_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        let p = project(Path::new("/work/repo"));
        let mut snap = Snapshot::new(&p, parse("[targets.a]\nkind = \"fake\"\nhost = \"h\"\n").unwrap());
        // Tamper with the served config but keep the hash the broker compares against.
        snap.config = parse("[targets.a]\nkind = \"fake\"\nhost = \"evil\"\n").unwrap();
        store(&root, &p, &snap).unwrap();
        assert!(matches!(load(&root, &p), Err(SnapshotError::Inconsistent { .. })));
    }

    #[test]
    fn upgrade_staleness_is_explained() {
        let p = project(Path::new("/work/repo"));
        let mut snap = Snapshot::new(&p, parse("[targets.a]\nkind = \"fake\"\n").unwrap());
        snap.written_by = "0.0.1".into();
        let changed = parse("[targets.a]\nkind = \"fake\"\nhost = \"h\"\n").unwrap();
        match ApprovalState::evaluate(Some(snap), &p, Ok(&changed)) {
            ApprovalState::Stale { reason, .. } => assert!(reason.contains("upgraded"), "{reason}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn approval_state() {
        let p = project(Path::new("/work/repo"));
        let approved = parse("[targets.a]\nkind = \"fake\"\nhost = \"h\"\n").unwrap();
        let reformatted = parse("# same\n[targets.a]\nhost = \"h\"\nkind = \"fake\"\n").unwrap();
        let changed = parse("[targets.a]\nkind = \"fake\"\nhost = \"evil\"\n").unwrap();
        let snap = Snapshot::new(&p, approved);

        assert_eq!(
            ApprovalState::evaluate(None, &p, Ok(&changed)),
            ApprovalState::NotApproved
        );
        assert!(ApprovalState::evaluate(Some(snap.clone()), &p, Ok(&reformatted)).is_approved());
        assert!(matches!(
            ApprovalState::evaluate(Some(snap.clone()), &p, Ok(&changed)),
            ApprovalState::Stale { .. }
        ));
        assert!(matches!(
            ApprovalState::evaluate(Some(snap.clone()), &p, Err(())),
            ApprovalState::Stale { .. }
        ));

        let other = project(Path::new("/work/other"));
        assert!(matches!(
            ApprovalState::evaluate(Some(snap), &other, Ok(&reformatted)),
            ApprovalState::RootMismatch { .. }
        ));
    }
}
