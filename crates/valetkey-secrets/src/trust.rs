//! Deciding whether a vendor CLI path is safe to run from the broker (decision D4 of M2, §6.8).
//!
//! The broker runs a tool outside the agent's sandbox, so the tool, everything it executes from
//! (its SDK tree) and its interpreter must not be somewhere the agent can write. `valetkey setup`
//! checks every path with [`check`] before a human confirms it.

use std::path::{Path, PathBuf};

/// What [`check`] compares against.
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    /// The user's home directory (from the user database). Project markers aren't looked for at
    /// or above it.
    pub home: PathBuf,
    /// The current project, if any: tools inside it are refused.
    pub project: Option<PathBuf>,
    /// Temp directories (canonical): tools inside them are refused.
    pub temp_dirs: Vec<PathBuf>,
}

impl TrustPolicy {
    /// The policy for this machine: the standard temp dirs plus the human's `$TMPDIR`.
    pub fn for_this_machine(home: PathBuf, project: Option<PathBuf>) -> Self {
        let mut temp_dirs: Vec<PathBuf> = [
            "/tmp",
            "/var/tmp",
            "/var/folders",
            "/private/tmp",
            "/private/var/tmp",
            "/private/var/folders",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        if let Some(t) = std::env::var_os("TMPDIR").and_then(|t| std::fs::canonicalize(t).ok()) {
            temp_dirs.push(t);
        }
        Self {
            home,
            project,
            temp_dirs,
        }
    }
}

/// Like [`check`], but warnings are refusals too. For paths that steer a tool rather than run as
/// code, such as gcloud's config directory (endpoint, proxy and CA overrides): there, even a
/// group-writable directory is too much.
pub fn check_strict(path: &Path, policy: &TrustPolicy) -> Result<(), String> {
    match check(path, policy)?.into_iter().next() {
        Some(warning) => Err(warning),
        None => Ok(()),
    }
}

/// Checks gcloud's config directory **and the files gcloud reads in it** (`active_config`,
/// `properties`, `configurations/config_*`): each must resolve inside the directory (a dotfiles
/// manager may have made one a symlink into an agent-writable tree) and pass [`check_strict`].
pub fn check_gcloud_config(dir: &Path, policy: &TrustPolicy) -> Result<(), String> {
    let dir = std::fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    check_strict(&dir, policy)?;
    let mut files = vec![dir.join("active_config"), dir.join("properties")];
    if let Ok(entries) = std::fs::read_dir(dir.join("configurations")) {
        files.extend(entries.filter_map(Result::ok).map(|e| e.path()));
    }
    for file in files {
        if std::fs::symlink_metadata(&file).is_err() {
            continue;
        }
        let real = std::fs::canonicalize(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        if !real.starts_with(&dir) {
            return Err(format!(
                "{} resolves to {}, outside the config directory",
                file.display(),
                real.display()
            ));
        }
        check_strict(&real, policy)?;
    }
    Ok(())
}

/// Whether `path` is a version-manager shim (pyenv, asdf, mise, rbenv, …). A shim picks the real
/// program from files such as a project-local `.python-version`, which an agent can write.
pub fn is_shim(path: &Path) -> bool {
    path.parent().and_then(|p| p.file_name()).is_some_and(|n| n == "shims")
}

/// Checks a canonical path. `Ok` carries warnings that don't block; `Err` explains the refusal.
pub fn check(path: &Path, policy: &TrustPolicy) -> Result<Vec<String>, String> {
    let shown = path.display();
    let canonical = std::fs::canonicalize(path).map_err(|e| format!("{shown}: {e}"))?;
    if canonical != path {
        return Err(format!(
            "{shown} isn't canonical (it resolves to {})",
            canonical.display()
        ));
    }
    if let Some(t) = policy.temp_dirs.iter().find(|t| path.starts_with(t)) {
        return Err(format!("{shown} is inside the temp directory {}", t.display()));
    }
    if let Some(project) = &policy.project
        && path.starts_with(project)
    {
        return Err(format!("{shown} is inside the current project"));
    }
    let mut warnings = Vec::new();
    for dir in path.ancestors() {
        check_owner_and_mode(dir, &mut warnings)?;
        let below_home = dir.starts_with(&policy.home) && dir != policy.home;
        if below_home && dir != path {
            for marker in [".git", "valetkey.toml", ".claude"] {
                if dir.join(marker).exists() {
                    return Err(format!(
                        "{shown} is inside {}, which contains {marker}: it looks like a project an agent may write to",
                        dir.display()
                    ));
                }
            }
        }
    }
    Ok(warnings)
}

#[cfg(unix)]
fn check_owner_and_mode(path: &Path, warnings: &mut Vec<String>) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let uid = nix::unistd::getuid().as_raw();
    if meta.uid() != 0 && meta.uid() != uid {
        return Err(format!(
            "{} is owned by another user (uid {})",
            path.display(),
            meta.uid()
        ));
    }
    let mode = meta.mode();
    if mode & 0o002 != 0 {
        return Err(format!(
            "{} is writable by every user (mode {:o})",
            path.display(),
            mode & 0o7777
        ));
    }
    if mode & 0o020 != 0 {
        warnings.push(format!(
            "{} is group-writable (mode {:o})",
            path.display(),
            mode & 0o7777
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_and_mode(_: &Path, _: &mut Vec<String>) -> Result<(), String> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn setup() -> (tempfile::TempDir, PathBuf, TrustPolicy) {
        // Not under /tmp: on Linux it's world-writable, which `check` (rightly) refuses for every
        // path below it. `target/` is owned by the user and not world-writable.
        let target = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/trust-tests");
        std::fs::create_dir_all(&target).unwrap();
        let tmp = tempfile::tempdir_in(&target).unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        // `base` stands in for home, so project markers above it (this repository's `.git`) are
        // outside the check, as they are for a real home directory.
        let policy = TrustPolicy {
            home: base.clone(),
            project: Some(base.join("repo")),
            temp_dirs: vec![],
        };
        (tmp, base, policy)
    }

    #[test]
    fn a_plain_sdk_dir_is_trusted() {
        let (_t, base, policy) = setup();
        let bin = base.join("sdk/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("gcloud"), "").unwrap();
        assert!(check(&bin.join("gcloud"), &policy).is_ok());
    }

    #[test]
    fn refuses_projects_temp_and_git_trees() {
        let (_t, base, mut policy) = setup();
        std::fs::create_dir_all(base.join("repo/bin")).unwrap();
        std::fs::write(base.join("repo/bin/gcloud"), "").unwrap();
        assert!(
            check(&base.join("repo/bin/gcloud"), &policy)
                .unwrap_err()
                .contains("current project")
        );

        for marker in [".git", "valetkey.toml", ".claude"] {
            let dir = base.join(format!("other-{}", marker.trim_start_matches('.')));
            std::fs::create_dir_all(dir.join("bin")).unwrap();
            if marker == "valetkey.toml" {
                std::fs::write(dir.join(marker), "").unwrap();
            } else {
                std::fs::create_dir_all(dir.join(marker)).unwrap();
            }
            std::fs::write(dir.join("bin/tool"), "").unwrap();
            let err = check(&dir.join("bin/tool"), &policy).unwrap_err();
            assert!(err.contains(marker), "{marker}: {err}");
        }

        std::fs::create_dir_all(base.join("tmpdir")).unwrap();
        std::fs::write(base.join("tmpdir/tool"), "").unwrap();
        policy.temp_dirs = vec![base.join("tmpdir")];
        assert!(
            check(&base.join("tmpdir/tool"), &policy)
                .unwrap_err()
                .contains("temp directory")
        );
    }

    #[test]
    fn gcloud_config_files_must_stay_inside_the_dir() {
        let (_t, base, policy) = setup();
        let cfg = base.join("gcloud");
        std::fs::create_dir_all(cfg.join("configurations")).unwrap();
        std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(cfg.join("active_config"), "default").unwrap();
        std::fs::write(cfg.join("configurations/config_default"), "[core]\n").unwrap();
        assert!(check_gcloud_config(&cfg, &policy).is_ok());

        // A dotfiles-style symlink into the project (agent-writable).
        std::fs::create_dir_all(base.join("repo")).unwrap();
        std::fs::write(base.join("repo/config_default"), "[api_endpoint_overrides]\n").unwrap();
        std::fs::remove_file(cfg.join("configurations/config_default")).unwrap();
        std::os::unix::fs::symlink(
            base.join("repo/config_default"),
            cfg.join("configurations/config_default"),
        )
        .unwrap();
        let err = check_gcloud_config(&cfg, &policy).unwrap_err();
        assert!(err.contains("outside the config directory"), "{err}");
    }

    #[test]
    fn refuses_world_writable_and_non_canonical_paths() {
        let (_t, base, policy) = setup();
        let dir = base.join("loose");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tool"), "").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            check(&dir.join("tool"), &policy)
                .unwrap_err()
                .contains("writable by every user")
        );

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(dir.join("tool"), base.join("alias")).unwrap();
        assert!(
            check(&base.join("alias"), &policy)
                .unwrap_err()
                .contains("isn't canonical")
        );
    }
}
