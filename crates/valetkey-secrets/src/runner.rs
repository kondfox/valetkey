//! The hardened process runner (§6.8): how the broker calls vendor CLIs such as `gcloud`.
//!
//! - an absolute program path and an argument vector, never a shell
//! - the environment is built from nothing: the caller passes every variable
//! - stdin is closed; stdout and stderr are capped
//! - a timeout kills the whole process group, and so does dropping the future (`gcloud` is a shell
//!   wrapper around Python, so the direct child isn't the only process)
//! - stdout (the secret) goes into a buffer allocated once at its cap, so it never reallocates and
//!   leaves no stray copies; it's returned as a [`SecretBox`] and zeroized on drop. Output beyond
//!   the cap kills the process: it's an error, never a truncated secret.
//! - stderr is drained (so the child can't block on it), capped, sanitized and meant for the log
//!   only, never for the agent

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use secrecy::{ExposeSecretMut, SecretBox};
use tokio::io::{AsyncRead, AsyncReadExt};

/// What to run.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// Absolute path to the program, resolved by a human through `valetkey setup`.
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// The complete environment. Nothing is inherited.
    pub env: Vec<(OsString, OsString)>,
}

/// Bounds for one run.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub timeout: Duration,
    pub max_stdout: usize,
    pub max_stderr: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(20),
            max_stdout: 64 * 1024,
            max_stderr: 4 * 1024,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("{0} isn't an absolute path")]
    NotAbsolute(PathBuf),
    #[error("{0} doesn't exist")]
    NotFound(PathBuf),
    #[error("can't start {program}: {source}")]
    Spawn { program: PathBuf, source: std::io::Error },
    #[error("{program} didn't finish within {timeout:?}")]
    Timeout { program: PathBuf, timeout: Duration },
    #[error("{program} printed more than {max} bytes")]
    StdoutTooLarge { program: PathBuf, max: usize },
    /// The program failed. `stderr` is capped and sanitized; it's for the log, not the agent.
    #[error("{program} exited with {status}")]
    Failed {
        program: PathBuf,
        status: ExitStatus,
        stderr: String,
    },
    #[error("reading from {program} failed: {source}")]
    Io { program: PathBuf, source: std::io::Error },
}

impl RunError {
    /// For the broker's log: the error plus the program's sanitized stderr, if it failed.
    pub fn log_detail(&self) -> String {
        match self {
            Self::Failed { stderr, .. } if !stderr.is_empty() => format!("{self}; stderr: {stderr}"),
            other => other.to_string(),
        }
    }
}

/// Runs the invocation and returns its stdout.
pub async fn run(invocation: &Invocation, limits: Limits) -> Result<SecretBox<Vec<u8>>, RunError> {
    let program = &invocation.program;
    if !program.is_absolute() {
        return Err(RunError::NotAbsolute(program.clone()));
    }
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(&invocation.args)
        .env_clear()
        .envs(invocation.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = spawn(&mut cmd, program).await?;
    // Kills the group on every exit path, including when the caller drops this future.
    let pid = child.id();
    let group = GroupKiller(std::sync::atomic::AtomicU32::new(pid.unwrap_or(0)));
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");

    let work = async {
        let out = async {
            let mut buf = SecretBox::new(Box::new(Vec::with_capacity(limits.max_stdout)));
            let fits = read_bounded(&mut stdout, buf.expose_secret_mut(), limits.max_stdout).await?;
            if !fits {
                // Kill now, so the stderr reader below sees EOF instead of waiting for a child
                // that's blocked writing to the stdout pipe nobody reads anymore.
                kill_group(pid);
            }
            Ok::<_, std::io::Error>((buf, fits))
        };
        let (out, err) = tokio::join!(out, drain_capped(&mut stderr, limits.max_stderr));
        // On stdout overflow, return at once: the guard kills the group, so `wait` isn't needed.
        let (out, fits) = out?;
        if !fits {
            return Ok((out, false, err?, None));
        }
        let status = child.wait().await?;
        // The leader is reaped now, so its pid (= the group id) may be reused at any moment:
        // never signal it again. Members that still held the pipes kept us from getting here
        // (we only reach `wait` after both pipes closed); a member that detached its stdio is
        // left alone.
        group.disarm();
        Ok::<_, std::io::Error>((out, true, err?, Some(status)))
    };
    let (out, fits, err, status) = match tokio::time::timeout(limits.timeout, work).await {
        Ok(r) => r.map_err(|source| RunError::Io {
            program: program.clone(),
            source,
        })?,
        Err(_) => {
            return Err(RunError::Timeout {
                program: program.clone(),
                timeout: limits.timeout,
            });
        }
    };
    if !fits {
        return Err(RunError::StdoutTooLarge {
            program: program.clone(),
            max: limits.max_stdout,
        });
    }
    let status = status.expect("set when stdout fits");
    if !status.success() {
        return Err(RunError::Failed {
            program: program.clone(),
            status,
            stderr: sanitize_stderr(&err),
        });
    }
    Ok(out)
}

/// Spawns, retrying briefly on "text file busy" (ETXTBSY). On Linux, exec fails with it while any
/// process still holds the program open for writing; that happens when the tool is being
/// updated, and when another thread forks right after the file was written (tests).
async fn spawn(
    cmd: &mut tokio::process::Command,
    program: &std::path::Path,
) -> Result<tokio::process::Child, RunError> {
    let mut attempts = 0;
    loop {
        match cmd.spawn() {
            Ok(child) => return Ok(child),
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && attempts < 5 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(20 * attempts)).await;
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Err(RunError::NotFound(program.to_owned()));
            }
            Err(source) => {
                return Err(RunError::Spawn {
                    program: program.to_owned(),
                    source,
                });
            }
        }
    }
}

/// Sends SIGKILL to the child's process group when dropped, unless disarmed. Only armed while
/// the leader is unreaped, which keeps its pid (the group id) from being reused.
struct GroupKiller(std::sync::atomic::AtomicU32);

impl GroupKiller {
    fn disarm(&self) {
        self.0.store(0, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for GroupKiller {
    fn drop(&mut self) {
        let pid = self.0.load(std::sync::atomic::Ordering::SeqCst);
        if pid != 0 {
            kill_group(Some(pid));
        }
    }
}

/// Reads into `buf` (allocated with capacity `cap`) until EOF. Returns `false` as soon as more
/// than `cap` bytes arrive; the extra bytes are never stored.
async fn read_bounded(reader: &mut (impl AsyncRead + Unpin), buf: &mut Vec<u8>, cap: usize) -> std::io::Result<bool> {
    // Zeroized on every exit, including when the future is dropped mid-read.
    let mut chunk = secrecy::zeroize::Zeroizing::new([0u8; 8192]);
    loop {
        let n = reader.read(&mut chunk[..]).await?;
        if n == 0 {
            return Ok(true);
        }
        if buf.len() + n > cap {
            return Ok(false);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Reads to EOF, keeping at most `cap` bytes.
async fn drain_capped(reader: &mut (impl AsyncRead + Unpin), cap: usize) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(kept);
        }
        let room = cap.saturating_sub(kept.len());
        kept.extend_from_slice(&buf[..n.min(room)]);
    }
}

fn sanitize_stderr(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    valetkey_core::sanitize::for_display(text.trim())
}

#[cfg(unix)]
fn kill_group(pid: Option<u32>) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;
    if let Some(pid) = pid.and_then(|p| i32::try_from(p).ok()) {
        // The child is its own group leader (`process_group(0)`); ESRCH just means it's gone.
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
}

#[cfg(not(unix))]
fn kill_group(_pid: Option<u32>) {
    // `kill_on_drop` covers the direct child on Windows.
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::os::unix::fs::PermissionsExt;

    /// Writes an executable shell script and returns its absolute path.
    fn script(dir: &std::path::Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn inv(program: PathBuf, args: &[&str], env: &[(&str, &str)]) -> Invocation {
        Invocation {
            program,
            args: args.iter().map(OsString::from).collect(),
            env: env
                .iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v)))
                .collect(),
        }
    }

    #[tokio::test]
    async fn returns_stdout_and_passes_args_verbatim() {
        let tmp = tempfile::tempdir().unwrap();
        let p = script(tmp.path(), "echo-args", r#"printf '%s|' "$@""#);
        let out = run(&inv(p, &["a b", "$(id)", ";rm -rf /"], &[]), Limits::default())
            .await
            .unwrap();
        assert_eq!(out.expose_secret().as_slice(), b"a b|$(id)|;rm -rf /|");
    }

    #[tokio::test]
    async fn the_environment_is_exactly_what_the_caller_passes() {
        let tmp = tempfile::tempdir().unwrap();
        let p = script(tmp.path(), "env", "/usr/bin/env");
        // SAFETY-relevant: the test process has HOME, PATH etc.; none may leak.
        let out = run(&inv(p, &[], &[("ONLY", "this")]), Limits::default()).await.unwrap();
        let env = String::from_utf8(out.expose_secret().clone()).unwrap();
        let names: Vec<_> = env
            .lines()
            .filter_map(|l| l.split('=').next())
            .filter(|n| *n != "PWD" && *n != "SHLVL" && *n != "_")
            .collect();
        assert_eq!(names, ["ONLY"], "{env}");
    }

    #[tokio::test]
    async fn stdin_is_closed() {
        let tmp = tempfile::tempdir().unwrap();
        // `cat` would hang forever if stdin were inherited from an interactive terminal.
        let p = script(tmp.path(), "cat", "cat; echo done");
        let out = run(&inv(p, &[], &[]), Limits::default()).await.unwrap();
        assert_eq!(out.expose_secret().as_slice(), b"done\n");
    }

    #[tokio::test]
    async fn failures_keep_stderr_for_the_log_only() {
        let tmp = tempfile::tempdir().unwrap();
        let p = script(tmp.path(), "fail", "echo 'ERROR: \x1b[31mnope' >&2; exit 3");
        match run(&inv(p, &[], &[]), Limits::default()).await {
            Err(RunError::Failed { status, stderr, .. }) => {
                assert_eq!(status.code(), Some(3));
                assert!(stderr.contains("nope") && !stderr.contains('\x1b'), "{stderr}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_hanging_program_is_killed_with_its_children() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("grandchild-alive");
        let body = format!("(sleep 2; touch {}) & sleep 30", marker.display());
        let p = script(tmp.path(), "hang", &body);
        let limits = Limits {
            timeout: Duration::from_millis(300),
            ..Limits::default()
        };
        let started = std::time::Instant::now();
        assert!(matches!(
            run(&inv(p, &[], &[]), limits).await,
            Err(RunError::Timeout { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!marker.exists(), "the grandchild survived the timeout");
    }

    #[tokio::test]
    async fn oversized_output_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let p = script(tmp.path(), "big", "head -c 200000 /dev/zero");
        let limits = Limits {
            max_stdout: 1000,
            ..Limits::default()
        };
        assert!(matches!(
            run(&inv(p, &[], &[]), limits).await,
            Err(RunError::StdoutTooLarge { .. })
        ));
    }

    #[tokio::test]
    async fn a_stderr_flood_neither_blocks_nor_grows_unbounded() {
        let tmp = tempfile::tempdir().unwrap();
        let p = script(
            tmp.path(),
            "flood",
            "head -c 1000000 /dev/zero | tr '\\0' 'e' >&2; printf ok",
        );
        let out = run(&inv(p, &[], &[]), Limits::default()).await.unwrap();
        assert_eq!(out.expose_secret().as_slice(), b"ok");
    }

    #[tokio::test]
    async fn dropping_the_future_kills_the_group() {
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("survived");
        let p = script(tmp.path(), "slow", &format!("sleep 2; touch {}", marker.display()));
        let invocation = inv(p, &[], &[]);
        let fut = run(&invocation, Limits::default());
        let _ = tokio::time::timeout(Duration::from_millis(300), fut).await;
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(!marker.exists(), "the child outlived the dropped future");
    }

    #[tokio::test]
    async fn missing_and_relative_programs_are_typed_errors() {
        assert!(matches!(
            run(&inv("/nonexistent/gcloud".into(), &[], &[]), Limits::default()).await,
            Err(RunError::NotFound(_))
        ));
        assert!(matches!(
            run(&inv("gcloud".into(), &[], &[]), Limits::default()).await,
            Err(RunError::NotAbsolute(_))
        ));
    }
}
