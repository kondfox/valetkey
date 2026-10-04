//! Reading files from agent-writable directories without being tricked (§6.2.1, the
//! confused-deputy rule).
//!
//! The broker runs outside the fence, so a plain `read_to_string` on a path the agent controls
//! could follow a symlink or a hard link to a file the fence denies the agent, and the content
//! could then leak through an error message. [`read_untrusted`] opens without following
//! symlinks, without blocking on a FIFO, and then checks the **open handle** (not the path, so
//! there's no check-then-use race): a regular file, owned by the current user, exactly one link,
//! and at most `max_len` bytes.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Upper bound for `valetkey.toml`.
pub const MAX_CONFIG_LEN: u64 = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum SafeReadError {
    #[error("{0} doesn't exist")]
    NotFound(PathBuf),
    #[error("{0} is a symlink or another kind of link; refusing to follow it")]
    Link(PathBuf),
    #[error("{0} isn't a regular file")]
    NotRegular(PathBuf),
    #[error("{0} has more than one hard link; refusing to read it")]
    HardLinked(PathBuf),
    #[error("{0} isn't owned by the current user")]
    WrongOwner(PathBuf),
    #[error("{0} is readable or writable by other users; it must be private (chmod 600)")]
    NotPrivate(PathBuf),
    #[error("{path} is larger than {max} bytes")]
    TooLarge { path: PathBuf, max: u64 },
    #[error("{0} isn't valid UTF-8")]
    NotUtf8(PathBuf),
    #[error("can't read {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

/// Reads a UTF-8 text file the agent may have tampered with. See the module docs.
pub fn read_untrusted(path: &Path, max_len: u64) -> Result<String, SafeReadError> {
    let file = open_no_follow(path)?;
    read_checked(file, path, max_len, false)
}

/// Like [`read_untrusted`], and the file must also be private to its owner (mode `0600` or
/// stricter on unix). For valetkey's own secret files.
pub fn read_private(path: &Path, max_len: u64) -> Result<String, SafeReadError> {
    let file = open_no_follow(path)?;
    read_checked(file, path, max_len, true)
}

/// Reads `relative` (a `/`-separated path without `.`, `..` or empty segments) **beneath**
/// `base`, opening one component at a time without following symlinks. A symlinked directory
/// anywhere on the way is refused, so the file can't be outside `base`; and because each step
/// opens relative to the previous directory handle, swapping a directory for a symlink after a
/// check doesn't help. For `env-file://` paths (§6.2.1).
pub fn read_untrusted_beneath(base: &Path, relative: &str, max_len: u64) -> Result<String, SafeReadError> {
    let full = base.join(relative);
    let segments: Vec<&str> = relative.split('/').collect();
    if segments.iter().any(|s| s.is_empty() || *s == "." || *s == "..") {
        return Err(SafeReadError::Link(full));
    }
    let file = open_beneath(base, &segments, &full)?;
    read_checked(file, &full, max_len, false)
}

fn read_checked(file: File, path: &Path, max_len: u64, private: bool) -> Result<String, SafeReadError> {
    let meta = file.metadata().map_err(|source| SafeReadError::Io {
        path: path.to_owned(),
        source,
    })?;
    check_handle(path, &meta)?;
    if private {
        check_private_mode(path, &meta)?;
    }
    if meta.len() > max_len {
        return Err(SafeReadError::TooLarge {
            path: path.to_owned(),
            max: max_len,
        });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    // Bounded even if the file grows after the fstat.
    file.take(max_len + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| SafeReadError::Io {
            path: path.to_owned(),
            source,
        })?;
    if bytes.len() as u64 > max_len {
        return Err(SafeReadError::TooLarge {
            path: path.to_owned(),
            max: max_len,
        });
    }
    String::from_utf8(bytes).map_err(|_| SafeReadError::NotUtf8(path.to_owned()))
}

#[cfg(unix)]
fn check_private_mode(path: &Path, meta: &std::fs::Metadata) -> Result<(), SafeReadError> {
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(SafeReadError::NotPrivate(path.to_owned()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_mode(_: &Path, _: &std::fs::Metadata) -> Result<(), SafeReadError> {
    Ok(())
}

#[cfg(unix)]
fn open_beneath(base: &Path, segments: &[&str], full: &Path) -> Result<File, SafeReadError> {
    use nix::fcntl::{OFlag, open, openat};
    use nix::sys::stat::Mode;
    let errno = |e: nix::errno::Errno| match e {
        nix::errno::Errno::ENOENT => SafeReadError::NotFound(full.to_owned()),
        nix::errno::Errno::ELOOP | nix::errno::Errno::ENOTDIR => SafeReadError::Link(full.to_owned()),
        e => SafeReadError::Io {
            path: full.to_owned(),
            source: io::Error::from(e),
        },
    };
    let dir_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut dir = open(base, dir_flags, Mode::empty()).map_err(errno)?;
    let (last, dirs) = segments.split_last().expect("at least one segment");
    for segment in dirs {
        dir = openat(&dir, *segment, dir_flags, Mode::empty()).map_err(errno)?;
    }
    let file_flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_NOCTTY | OFlag::O_CLOEXEC;
    let fd = openat(&dir, *last, file_flags, Mode::empty()).map_err(errno)?;
    Ok(File::from(fd))
}

/// Windows: no `openat`; check each component for reparse points, then open without following.
/// Native Windows is unfenced (§2.7), so env-files there are never protected anyway.
#[cfg(not(unix))]
fn open_beneath(base: &Path, segments: &[&str], full: &Path) -> Result<File, SafeReadError> {
    let mut path = base.to_owned();
    for segment in &segments[..segments.len() - 1] {
        path.push(segment);
        let meta = std::fs::symlink_metadata(&path).map_err(|_| SafeReadError::NotFound(full.to_owned()))?;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(SafeReadError::Link(full.to_owned()));
        }
    }
    open_no_follow(full)
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<File, SafeReadError> {
    use nix::fcntl::OFlag;
    use std::os::unix::fs::OpenOptionsExt;
    let flags = OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_NOCTTY;
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits())
        .open(path)
    {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(SafeReadError::NotFound(path.to_owned())),
        // O_NOFOLLOW on a symlink fails with ELOOP.
        Err(e) if e.raw_os_error() == Some(nix::errno::Errno::ELOOP as i32) => {
            Err(SafeReadError::Link(path.to_owned()))
        }
        Err(source) => Err(SafeReadError::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(unix)]
fn check_handle(path: &Path, meta: &std::fs::Metadata) -> Result<(), SafeReadError> {
    use std::os::unix::fs::MetadataExt;
    if !meta.file_type().is_file() {
        return Err(SafeReadError::NotRegular(path.to_owned()));
    }
    if meta.nlink() != 1 {
        return Err(SafeReadError::HardLinked(path.to_owned()));
    }
    if meta.uid() != nix::unistd::getuid().as_raw() {
        return Err(SafeReadError::WrongOwner(path.to_owned()));
    }
    Ok(())
}

#[cfg(windows)]
fn open_no_follow(path: &Path) -> Result<File, SafeReadError> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(SafeReadError::NotFound(path.to_owned())),
        Err(source) => Err(SafeReadError::Io {
            path: path.to_owned(),
            source,
        }),
    }
}

#[cfg(windows)]
fn check_handle(path: &Path, meta: &std::fs::Metadata) -> Result<(), SafeReadError> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(SafeReadError::Link(path.to_owned()));
    }
    if !meta.file_type().is_file() {
        return Err(SafeReadError::NotRegular(path.to_owned()));
    }
    // Hard-link counts and ownership aren't available from stable std on Windows. Native
    // Windows is unfenced anyway (§2.7), so protected targets are never served there.
    // REVISIT if a Windows fence profile is ever added: add the nlink and owner checks then
    // (GetFileInformationByHandle, GetSecurityInfo).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn reads_a_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("valetkey.toml");
        fs::write(&p, "a = 1\n").unwrap();
        assert_eq!(read_untrusted(&p, MAX_CONFIG_LEN).unwrap(), "a = 1\n");
    }

    #[test]
    fn refuses_missing_and_oversized_files() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("big");
        assert!(matches!(read_untrusted(&p, 10), Err(SafeReadError::NotFound(_))));
        fs::write(&p, "x".repeat(11)).unwrap();
        assert!(matches!(read_untrusted(&p, 10), Err(SafeReadError::TooLarge { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("secret");
        fs::write(&secret, "TOKEN").unwrap();
        let link = tmp.path().join("valetkey.toml");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert!(matches!(
            read_untrusted(&link, MAX_CONFIG_LEN),
            Err(SafeReadError::Link(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_hard_links() {
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("secret");
        fs::write(&secret, "TOKEN").unwrap();
        let link = tmp.path().join("valetkey.toml");
        fs::hard_link(&secret, &link).unwrap();
        assert!(matches!(
            read_untrusted(&link, MAX_CONFIG_LEN),
            Err(SafeReadError::HardLinked(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn refuses_fifos_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("valetkey.toml");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
        assert!(matches!(
            read_untrusted(&fifo, MAX_CONFIG_LEN),
            Err(SafeReadError::NotRegular(_))
        ));
    }

    /// Windows symlinks are reparse points; they must not be followed.
    #[cfg(windows)]
    #[test]
    fn refuses_windows_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let secret = tmp.path().join("secret");
        fs::write(&secret, "TOKEN").unwrap();
        let link = tmp.path().join("valetkey.toml");
        if let Err(e) = std::os::windows::fs::symlink_file(&secret, &link) {
            // Creating symlinks needs Developer Mode or admin rights. CI runners have them, so
            // there a failure to create one is a real failure, not a reason to skip.
            assert!(std::env::var_os("CI").is_none(), "can't create a symlink in CI: {e}");
            eprintln!("skipping: can't create a symlink here: {e}");
            return;
        }
        let result = read_untrusted(&link, MAX_CONFIG_LEN);
        assert!(matches!(result, Err(SafeReadError::Link(_))), "{result:?}");
    }

    #[cfg(unix)]
    #[test]
    fn beneath_reads_nested_files_but_refuses_symlinked_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("project");
        fs::create_dir_all(base.join("apps/web")).unwrap();
        fs::write(base.join("apps/web/.env"), "K=v\n").unwrap();
        assert_eq!(
            read_untrusted_beneath(&base, "apps/web/.env", MAX_CONFIG_LEN).unwrap(),
            "K=v\n"
        );

        // `apps/link` → a directory outside the project that holds a "fenced" file.
        let outside = tmp.path().join("aws");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("credentials"), "SECRET").unwrap();
        std::os::unix::fs::symlink(&outside, base.join("apps/link")).unwrap();
        let r = read_untrusted_beneath(&base, "apps/link/credentials", MAX_CONFIG_LEN);
        assert!(matches!(r, Err(SafeReadError::Link(_))), "{r:?}");
        // A plain read through the same path would follow it: the reason this function exists.
        assert_eq!(
            fs::read_to_string(base.join("apps/link/credentials")).unwrap(),
            "SECRET"
        );
    }

    #[test]
    fn beneath_rejects_dot_segments() {
        let tmp = tempfile::tempdir().unwrap();
        for rel in ["../x", "a/../b", "./a", "a//b", ""] {
            assert!(
                read_untrusted_beneath(tmp.path(), rel, MAX_CONFIG_LEN).is_err(),
                "{rel}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_files_must_be_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("secret");
        fs::write(&p, "s").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(read_private(&p, 10), Err(SafeReadError::NotPrivate(_))));
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private(&p, 10).unwrap(), "s");
    }

    #[test]
    fn refuses_directories() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_untrusted(tmp.path(), MAX_CONFIG_LEN).is_err());
    }
}
