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
    let meta = file.metadata().map_err(|source| SafeReadError::Io {
        path: path.to_owned(),
        source,
    })?;
    check_handle(path, &meta)?;
    if meta.len() > max_len {
        return Err(SafeReadError::TooLarge {
            path: path.to_owned(),
            max: max_len,
        });
    }
    let mut bytes = Vec::new();
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

    #[test]
    fn refuses_directories() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(read_untrusted(tmp.path(), MAX_CONFIG_LEN).is_err());
    }
}
