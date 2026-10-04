//! The valetkey root, `~/.valetkey/`, and everything under it (§6.2.1, decision
//! `2026-10-04-valetkey-root-dir`).
//!
//! The home directory comes from the **OS user database**, never from `HOME` or any other
//! environment variable: a Claude Code settings `env` block reaches every MCP server (M0), so an
//! environment-derived root could be moved outside the fence.

use std::io;
use std::path::{Path, PathBuf};

use crate::project::ProjectKey;

/// Name of the root directory inside the user's home.
pub const ROOT_DIR_NAME: &str = ".valetkey";

/// Debug builds only: overrides the root, so tests never touch the developer's real
/// `~/.valetkey/`. Release builds ignore it (the shipped binary is always a release build).
pub const DEV_ROOT_ENV: &str = "VALETKEY_DEV_ROOT";

#[derive(Debug, thiserror::Error)]
pub enum PathsError {
    #[error("can't find the current user's home directory in the OS user database: {0}")]
    NoHome(String),
}

/// The valetkey root directory and the layout under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValetkeyRoot {
    dir: PathBuf,
}

impl ValetkeyRoot {
    /// Resolves `<home>/.valetkey`, with `<home>` from the OS user database.
    pub fn resolve() -> Result<Self, PathsError> {
        #[cfg(debug_assertions)]
        if let Some(dir) = std::env::var_os(DEV_ROOT_ENV) {
            return Ok(Self::at(dir));
        }
        Ok(Self::at(os_home_dir()?.join(ROOT_DIR_NAME)))
    }

    /// A root at an explicit location (tests, and the dev override).
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn bin_dir(&self) -> PathBuf {
        self.dir.join("bin")
    }

    /// Config snapshots, one directory per project key (§6.1).
    pub fn project_dir(&self, key: &ProjectKey) -> PathBuf {
        self.dir.join("projects").join(key.as_str())
    }

    /// Pending write requests (§6.10).
    pub fn pending_dir(&self) -> PathBuf {
        self.dir.join("pending")
    }

    /// Human approvals of write requests (§6.10). Separate from config snapshots.
    pub fn write_approvals_dir(&self) -> PathBuf {
        self.dir.join("write-approvals")
    }

    /// The directory a proxy puts a target's socket in: `sockets/<alias>/` (§6.2).
    pub fn socket_dir(&self, alias: &str) -> PathBuf {
        self.dir.join("sockets").join(alias)
    }

    pub fn secrets_dir(&self) -> PathBuf {
        self.dir.join("secrets")
    }

    pub fn audit_dir(&self) -> PathBuf {
        self.dir.join("audit")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.dir.join("logs")
    }

    /// User-level config: vendor CLI paths, CA bundle, proxy (§6.8). Never project config.
    pub fn user_config_file(&self) -> PathBuf {
        self.dir.join("config.toml")
    }
}

/// Creates `dir` and any missing parents, owner-only (`0700`) on unix.
pub fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// The home directory according to the OS user database.
#[cfg(unix)]
pub fn os_home_dir() -> Result<PathBuf, PathsError> {
    let uid = nix::unistd::getuid();
    match nix::unistd::User::from_uid(uid) {
        Ok(Some(user)) => Ok(user.dir),
        Ok(None) => Err(PathsError::NoHome(format!("no entry for uid {uid}"))),
        Err(e) => Err(PathsError::NoHome(e.to_string())),
    }
}

/// The home directory according to the user profile API (`FOLDERID_Profile`), not `USERPROFILE`.
#[cfg(windows)]
pub fn os_home_dir() -> Result<PathBuf, PathsError> {
    known_folders::get_known_folder_path(known_folders::KnownFolder::Profile)
        .ok_or_else(|| PathsError::NoHome("FOLDERID_Profile is not available".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_under_the_root() {
        let root = ValetkeyRoot::at("/r");
        assert_eq!(root.bin_dir(), Path::new("/r/bin"));
        assert_eq!(root.socket_dir("stage-core"), Path::new("/r/sockets/stage-core"));
        assert_eq!(root.write_approvals_dir(), Path::new("/r/write-approvals"));
        assert_eq!(root.user_config_file(), Path::new("/r/config.toml"));
    }

    #[cfg(unix)]
    #[test]
    fn os_home_dir_exists() {
        let home = os_home_dir().expect("home from the user database");
        assert!(home.is_absolute());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("a/b");
        ensure_private_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
}
