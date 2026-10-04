//! `~/.valetkey/config.toml`: user-level settings a **human** approved with `valetkey setup`
//! (§6.8). Never project config. The broker takes vendor CLI paths and their environment only
//! from here, never from its inherited environment.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::paths::{ValetkeyRoot, ensure_private_dir};
use crate::safe_read::{SafeReadError, read_private};

const MAX_LEN: u64 = 64 * 1024;

/// The whole file.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// Vendor CLIs by name (`gcloud`, later `aws`, `az`, `op`).
    #[serde(default)]
    pub tools: BTreeMap<String, ToolConfig>,
}

/// One vendor CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolConfig {
    /// The canonical absolute path `setup` checked.
    pub path: PathBuf,
    /// Extra environment for the tool (e.g. `CLOUDSDK_PYTHON`), also checked by `setup`.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum UserConfigError {
    #[error(transparent)]
    Read(#[from] SafeReadError),
    #[error("{path} is invalid: {message}")]
    Invalid { path: PathBuf, message: String },
    #[error("can't write {path}: {source}")]
    Write { path: PathBuf, source: std::io::Error },
}

impl UserConfig {
    /// Loads the file; a missing file is an empty config. The file must be private (`0600`).
    pub fn load(root: &ValetkeyRoot) -> Result<Self, UserConfigError> {
        let path = root.user_config_file();
        match read_private(&path, MAX_LEN) {
            Ok(text) => toml::from_str(&text).map_err(|e| UserConfigError::Invalid {
                path,
                message: e.message().to_owned(),
            }),
            Err(SafeReadError::NotFound(_)) => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Writes the file atomically with mode `0600`.
    pub fn store(&self, root: &ValetkeyRoot) -> Result<(), UserConfigError> {
        let path = root.user_config_file();
        let werr = |source| UserConfigError::Write {
            path: path.clone(),
            source,
        };
        ensure_private_dir(root.dir()).map_err(werr)?;
        let text = toml::to_string_pretty(self).expect("a user config always serializes");
        let mut tmp = tempfile::Builder::new()
            .prefix(".config-")
            .tempfile_in(root.dir())
            .map_err(werr)?;
        tmp.write_all(b"# Written by `valetkey setup`. Re-run it rather than editing by hand.\n")
            .map_err(werr)?;
        tmp.write_all(text.as_bytes()).map_err(werr)?;
        tmp.as_file().sync_all().map_err(werr)?;
        tmp.persist(&path).map_err(|e| werr(e.error))?;
        Ok(())
    }

    pub fn tool(&self, name: &str) -> Option<&ToolConfig> {
        self.tools.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_private() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        assert_eq!(UserConfig::load(&root).unwrap(), UserConfig::default());

        let mut c = UserConfig::default();
        c.tools.insert(
            "gcloud".into(),
            ToolConfig {
                path: "/opt/sdk/bin/gcloud".into(),
                env: [("CLOUDSDK_PYTHON".into(), "/usr/local/bin/python3".into())].into(),
            },
        );
        c.store(&root).unwrap();
        assert_eq!(UserConfig::load(&root).unwrap(), c);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(root.user_config_file()).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let root = ValetkeyRoot::at(tmp.path().join("vk"));
        crate::paths::ensure_private_dir(root.dir()).unwrap();
        std::fs::write(root.user_config_file(), "[tools.gcloud]\npath = \"/x\"\nshell = true\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.user_config_file(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(UserConfig::load(&root), Err(UserConfigError::Invalid { .. })));
    }
}
