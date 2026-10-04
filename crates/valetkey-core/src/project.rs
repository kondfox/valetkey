//! Finding a project: the directory of the first `valetkey.toml` found walking up from a start
//! directory, and its **project key** (§6.1).
//!
//! The start directory is supplied by the client (`CLAUDE_PROJECT_DIR`, roots) or is the CLI's
//! current directory. Cross-checking client-supplied values is the MCP server's job.

use std::fmt;
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::config::CONFIG_FILE_NAME;

/// `blake3(canonical project root)`, the first 32 hex characters. Names the project's snapshot
/// directory. Each clone and each git worktree is a different project.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProjectKey(String);

impl ProjectKey {
    pub fn for_root(canonical_root: &Path) -> Self {
        let hash = blake3::hash(canonical_root.as_os_str().as_encoded_bytes());
        Self(hash.to_hex()[..32].to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProjectKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A discovered project.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Project {
    /// The canonical (`realpath`) project root. On case-insensitive volumes `realpath` returns the
    /// on-disk case, so different spellings of one directory map to one key.
    pub root: PathBuf,
    /// `<root>/valetkey.toml`.
    pub config_path: PathBuf,
    pub key: ProjectKey,
}

#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error("no {CONFIG_FILE_NAME} found in {0} or any parent directory")]
    NotFound(PathBuf),
    #[error("{0} is a symlink; valetkey only reads a real {CONFIG_FILE_NAME}")]
    ConfigIsSymlink(PathBuf),
    #[error("{0} is a symlink between the start directory and the project root; refusing to follow it")]
    SymlinkOnPath(PathBuf),
    #[error("the start directory must be an absolute path, got {0}")]
    NotAbsolute(PathBuf),
    #[error("the start directory must not contain `.` or `..` components, got {0}")]
    NotNormalized(PathBuf),
    #[error("can't inspect {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

/// Walks up from `start` to the first directory containing `valetkey.toml`.
///
/// Refuses when `valetkey.toml` itself, or a directory between `start` and the root, is a
/// symlink. Symlinks *above* the root (macOS `/var`, `/tmp`, a relocated home) are fine.
pub fn discover(start: &Path) -> Result<Project, ProjectError> {
    if !start.is_absolute() {
        return Err(ProjectError::NotAbsolute(start.to_owned()));
    }
    // Parents are walked lexically, so `..` would make the walk check the wrong ancestors.
    if start
        .components()
        .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(ProjectError::NotNormalized(start.to_owned()));
    }
    let io_err = |path: &Path| {
        let path = path.to_owned();
        move |source| ProjectError::Io { path, source }
    };

    let mut walked = Vec::new();
    let mut dir = start;
    let root = loop {
        let candidate = dir.join(CONFIG_FILE_NAME);
        match std::fs::symlink_metadata(&candidate) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(ProjectError::ConfigIsSymlink(candidate)),
            Ok(meta) if meta.is_file() => break dir,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(&candidate)(e)),
        }
        walked.push(dir);
        dir = dir.parent().ok_or_else(|| ProjectError::NotFound(start.to_owned()))?;
    };

    for dir in walked {
        let meta = std::fs::symlink_metadata(dir).map_err(io_err(dir))?;
        if meta.file_type().is_symlink() {
            return Err(ProjectError::SymlinkOnPath(dir.to_owned()));
        }
    }

    let canonical = std::fs::canonicalize(root).map_err(io_err(root))?;
    Ok(Project {
        config_path: canonical.join(CONFIG_FILE_NAME),
        key: ProjectKey::for_root(&canonical),
        root: canonical,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let p = fs::canonicalize(t.path()).unwrap();
        (t, p)
    }

    #[test]
    fn finds_the_nearest_config_walking_up() {
        let (_t, base) = tmp();
        fs::create_dir_all(base.join("repo/apps/web/src")).unwrap();
        fs::write(base.join("repo/valetkey.toml"), "").unwrap();
        fs::write(base.join("repo/apps/web/valetkey.toml"), "").unwrap();

        let p = discover(&base.join("repo/apps/web/src")).unwrap();
        assert_eq!(p.root, base.join("repo/apps/web"), "the nested config wins");
        let p = discover(&base.join("repo/apps")).unwrap();
        assert_eq!(p.root, base.join("repo"));
        assert_eq!(p.config_path, base.join("repo/valetkey.toml"));
    }

    #[test]
    fn non_normalized_start_is_rejected() {
        // A literal path: on Windows, pushing `..` onto a canonical (verbatim) path resolves it.
        let start = if cfg!(windows) { r"C:\work\a\.." } else { "/work/a/.." };
        assert!(matches!(
            discover(Path::new(start)),
            Err(ProjectError::NotNormalized(_))
        ));
        let start = if cfg!(windows) { r"C:\work\.\a" } else { "/work/./a" };
        assert!(matches!(
            discover(Path::new(start)),
            Err(ProjectError::NotNormalized(_))
        ));
    }

    #[test]
    fn relative_start_is_rejected() {
        assert!(matches!(discover(Path::new("rel")), Err(ProjectError::NotAbsolute(_))));
    }

    #[test]
    fn key_depends_only_on_the_canonical_root() {
        let (_t, base) = tmp();
        fs::create_dir_all(base.join("a/b")).unwrap();
        fs::write(base.join("a/valetkey.toml"), "").unwrap();
        assert_eq!(
            discover(&base.join("a")).unwrap().key,
            discover(&base.join("a/b")).unwrap().key
        );
        assert_ne!(
            ProjectKey::for_root(&base.join("a")),
            ProjectKey::for_root(&base.join("c"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_is_refused() {
        let (_t, base) = tmp();
        fs::create_dir_all(base.join("repo")).unwrap();
        fs::write(base.join("elsewhere.toml"), "").unwrap();
        std::os::unix::fs::symlink(base.join("elsewhere.toml"), base.join("repo/valetkey.toml")).unwrap();
        assert!(matches!(
            discover(&base.join("repo")),
            Err(ProjectError::ConfigIsSymlink(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_between_start_and_root_is_refused() {
        let (_t, base) = tmp();
        fs::create_dir_all(base.join("repo")).unwrap();
        fs::create_dir_all(base.join("outside/deep")).unwrap();
        fs::write(base.join("repo/valetkey.toml"), "").unwrap();
        std::os::unix::fs::symlink(base.join("outside"), base.join("repo/link")).unwrap();
        // Walking up from repo/link/deep passes through the symlink `repo/link`.
        let err = discover(&base.join("repo/link/deep"));
        assert!(
            matches!(err, Err(ProjectError::SymlinkOnPath(ref p)) if p.ends_with("repo/link")),
            "{err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_above_the_root_is_fine() {
        let (_t, base) = tmp();
        fs::create_dir_all(base.join("real/repo")).unwrap();
        fs::write(base.join("real/repo/valetkey.toml"), "").unwrap();
        std::os::unix::fs::symlink(base.join("real"), base.join("alias")).unwrap();
        let p = discover(&base.join("alias/repo")).unwrap();
        assert_eq!(p.root, base.join("real/repo"));
    }
}
