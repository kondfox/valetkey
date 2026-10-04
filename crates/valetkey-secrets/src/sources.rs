//! The four v1 secret sources (§2.3, §6.0). Every error's public message is fixed text; details
//! (paths, exit codes, sanitized stderr) go to the log through [`SourceError::detail`].

use std::ffi::OsString;
use std::path::PathBuf;

use secrecy::{ExposeSecret, SecretString};
use valetkey_core::SecretRef;
use valetkey_core::paths::{check_private, os_home_dir};
use valetkey_core::safe_read::{read_private, read_untrusted_beneath};
use valetkey_core::secret_source::{FenceRules, FetchCx, FetchFuture, SecretSource, SourceError};
use valetkey_core::user_config::UserConfig;

use crate::dotenv;
use crate::runner::{self, Invocation, Limits};

/// The largest env-file or local secret file read.
const MAX_FILE: u64 = 256 * 1024;

fn wrong_scheme(scheme: &str) -> SourceError {
    SourceError::new(
        "internal error: a reference reached the wrong source",
        format!("expected {scheme}"),
    )
}

/// `env-file://<path>#<KEY>`: a key in a dotenv file inside the project. Exposed by definition.
#[derive(Debug, Default)]
pub struct EnvFileSource;

impl SecretSource for EnvFileSource {
    fn scheme(&self) -> &'static str {
        "env-file"
    }

    fn fetch<'a>(&'a self, reference: &'a SecretRef, cx: &'a FetchCx<'a>) -> FetchFuture<'a> {
        Box::pin(async move {
            let SecretRef::EnvFile { path, key } = reference else {
                return Err(wrong_scheme("env-file"));
            };
            let text = read_untrusted_beneath(cx.project_root, path, MAX_FILE).map_err(|e| {
                SourceError::new(
                    format!("can't read the env-file `{path}` (see the valetkey log)"),
                    e.to_string(),
                )
            })?;
            let value = dotenv::lookup(&text, key).ok_or_else(|| {
                SourceError::new(format!("the env-file `{path}` doesn't define `{key}`"), String::new())
            })?;
            Ok(SecretString::from(value))
        })
    }

    fn fence(&self, _: &UserConfig) -> FenceRules {
        FenceRules::default()
    }
}

/// `local://<id>`: valetkey's own store, one private file per secret in `~/.valetkey/secrets/`.
#[derive(Debug, Default)]
pub struct LocalSource;

/// Managing `local://` secrets (`valetkey secret …`). Values are written atomically with mode
/// `0600` in a `0700` directory; ids are validated like `local://` references.
impl LocalSource {
    fn checked_path(root: &valetkey_core::ValetkeyRoot, id: &str) -> std::io::Result<PathBuf> {
        let reference: SecretRef =
            format!("local://{id}")
                .parse()
                .map_err(|e: valetkey_core::secret_ref::SecretRefError| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
                })?;
        let SecretRef::Local { id } = reference else {
            unreachable!("parsed as local")
        };
        Ok(root.secrets_dir().join(id))
    }

    /// Stores a secret. Refuses to overwrite an existing one unless `replace` is set.
    pub fn store(
        root: &valetkey_core::ValetkeyRoot,
        id: &str,
        value: &SecretString,
        replace: bool,
    ) -> std::io::Result<()> {
        use std::io::Write;
        let path = Self::checked_path(root, id)?;
        let dir = root.secrets_dir();
        valetkey_core::paths::ensure_private_dir(&dir)?;
        if !replace && std::fs::symlink_metadata(&path).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("local://{id} already exists; use --replace"),
            ));
        }
        let mut tmp = tempfile::Builder::new().prefix(".secret-").tempfile_in(&dir)?;
        tmp.write_all(value.expose_secret().as_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist(&path).map_err(|e| e.error)?;
        Ok(())
    }

    /// Removes a secret. `Ok(false)` if it didn't exist.
    pub fn remove(root: &valetkey_core::ValetkeyRoot, id: &str) -> std::io::Result<bool> {
        match std::fs::remove_file(Self::checked_path(root, id)?) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The ids of stored secrets, sorted. Never their values.
    pub fn list(root: &valetkey_core::ValetkeyRoot) -> std::io::Result<Vec<String>> {
        let mut ids = Vec::new();
        match std::fs::read_dir(root.secrets_dir()) {
            Ok(entries) => {
                for entry in entries {
                    let name = entry?.file_name().to_string_lossy().into_owned();
                    if !name.starts_with('.') && Self::checked_path(root, &name).is_ok() {
                        ids.push(name);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        ids.sort();
        Ok(ids)
    }
}

impl SecretSource for LocalSource {
    fn scheme(&self) -> &'static str {
        "local"
    }

    fn fetch<'a>(&'a self, reference: &'a SecretRef, cx: &'a FetchCx<'a>) -> FetchFuture<'a> {
        Box::pin(async move {
            let SecretRef::Local { id } = reference else {
                return Err(wrong_scheme("local"));
            };
            let dir = cx.root.secrets_dir();
            check_private(&dir).map_err(|p| {
                SourceError::new("valetkey's secrets directory isn't private (run `valetkey doctor`)", p)
            })?;
            let text = read_private(&dir.join(id), MAX_FILE).map_err(|e| {
                SourceError::new(
                    format!("can't read local://{id} (set it with `valetkey secret set {id}`)"),
                    e.to_string(),
                )
            })?;
            Ok(SecretString::from(strip_one_newline(text)))
        })
    }

    fn fence(&self, _: &UserConfig) -> FenceRules {
        // The whole valetkey root is fenced (write), and `secrets/` deny-read, by the profile.
        FenceRules::default()
    }
}

fn strip_one_newline(mut s: String) -> String {
    if s.ends_with("\r\n") {
        s.truncate(s.len() - 2);
    } else if s.ends_with('\n') {
        s.truncate(s.len() - 1);
    }
    s
}

/// `keyring://<service>/<account>`: the OS keyring. Exposed on macOS (M0), so it only matters
/// for protected use on Linux.
#[derive(Debug, Default)]
pub struct KeyringSource;

impl SecretSource for KeyringSource {
    fn scheme(&self) -> &'static str {
        "keyring"
    }

    fn fetch<'a>(&'a self, reference: &'a SecretRef, _cx: &'a FetchCx<'a>) -> FetchFuture<'a> {
        Box::pin(async move {
            let SecretRef::Keyring { service, account } = reference else {
                return Err(wrong_scheme("keyring"));
            };
            let (service, account) = (service.clone(), account.clone());
            let result =
                tokio::task::spawn_blocking(move || keyring::Entry::new(&service, &account)?.get_password()).await;
            match result {
                Ok(Ok(value)) => Ok(SecretString::from(value)),
                Ok(Err(e)) => Err(SourceError::new(
                    "can't read the keyring entry (see the valetkey log)",
                    e.to_string(),
                )),
                Err(e) => Err(SourceError::new(
                    "can't read the keyring entry (see the valetkey log)",
                    e.to_string(),
                )),
            }
        })
    }

    fn fence(&self, _: &UserConfig) -> FenceRules {
        FenceRules::default()
    }
}

/// `gcp-sm://<project>/<name>`: GCP Secret Manager through the `gcloud` that `valetkey setup`
/// recorded. Verified against the gcloud 496 source: the default output format is
/// `value[terminator="",private](payload.data.decode(base64).decode(utf8))`, i.e. the UTF-8
/// value with no trailing newline (wiki: integrations/gcloud).
#[derive(Debug, Default)]
pub struct GcpSmSource {
    pub limits: Limits,
}

impl GcpSmSource {
    /// The exact invocation for a reference. Public for tests and `doctor`.
    pub fn invocation(user: &UserConfig, project: &str, name: &str) -> Result<Invocation, SourceError> {
        let tool = user.tool("gcloud").ok_or_else(|| {
            SourceError::new(
                "gcloud isn't configured for valetkey; a human must run `valetkey setup`",
                "no [tools.gcloud]",
            )
        })?;
        let home =
            os_home_dir().map_err(|e| SourceError::new("can't resolve the user's home directory", e.to_string()))?;
        let mut env: Vec<(OsString, OsString)> = vec![
            ("PATH".into(), minimal_path(&tool.path)),
            ("HOME".into(), home.into_os_string()),
            ("LANG".into(), "C.UTF-8".into()),
            // Never prompt; never check for updates from the broker.
            ("CLOUDSDK_CORE_DISABLE_PROMPTS".into(), "1".into()),
            ("CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK".into(), "1".into()),
        ];
        env.extend(tool.env.iter().map(|(k, v)| (k.into(), v.into())));
        let args = [
            "secrets",
            "versions",
            "access",
            "latest",
            "--secret",
            name,
            "--project",
            project,
            "--quiet",
        ];
        Ok(Invocation {
            program: tool.path.clone(),
            args: args.iter().map(OsString::from).collect(),
            env,
        })
    }
}

fn minimal_path(program: &std::path::Path) -> OsString {
    let mut path = OsString::new();
    if let Some(dir) = program.parent() {
        path.push(dir);
        path.push(":");
    }
    path.push("/usr/bin:/bin");
    path
}

impl SecretSource for GcpSmSource {
    fn scheme(&self) -> &'static str {
        "gcp-sm"
    }

    fn fetch<'a>(&'a self, reference: &'a SecretRef, cx: &'a FetchCx<'a>) -> FetchFuture<'a> {
        Box::pin(async move {
            let SecretRef::GcpSm { project, name } = reference else {
                return Err(wrong_scheme("gcp-sm"));
            };
            let invocation = Self::invocation(cx.user, project, name)?;
            let out = runner::run(&invocation, self.limits).await.map_err(|e| {
                SourceError::new(
                    "fetching the secret from GCP Secret Manager failed (see the valetkey log)",
                    e.to_string(),
                )
            })?;
            let text = std::str::from_utf8(out.expose_secret())
                .map_err(|_| SourceError::new("the secret from GCP Secret Manager isn't UTF-8", String::new()))?;
            if text.is_empty() {
                return Err(SourceError::new(
                    "GCP Secret Manager returned an empty secret",
                    String::new(),
                ));
            }
            Ok(SecretString::from(text.to_owned()))
        })
    }

    fn fence(&self, user: &UserConfig) -> FenceRules {
        // gcloud's credentials: CLOUDSDK_CONFIG if set, else ~/.config/gcloud.
        let config = user
            .tool("gcloud")
            .and_then(|t| t.env.get("CLOUDSDK_CONFIG").map(PathBuf::from))
            .or_else(|| os_home_dir().ok().map(|h| h.join(".config/gcloud")));
        FenceRules {
            deny_read: config.into_iter().collect(),
        }
    }
}

/// Every source this build supports, by scheme.
pub fn all_sources() -> Vec<Box<dyn SecretSource>> {
    vec![
        Box::new(EnvFileSource),
        Box::new(LocalSource),
        Box::new(KeyringSource),
        Box::new(GcpSmSource::default()),
    ]
}

/// Fetches `reference` with the matching source.
pub async fn fetch(reference: &SecretRef, cx: &FetchCx<'_>) -> Result<SecretString, SourceError> {
    match reference {
        SecretRef::EnvFile { .. } => EnvFileSource.fetch(reference, cx).await,
        SecretRef::Local { .. } => LocalSource.fetch(reference, cx).await,
        SecretRef::Keyring { .. } => KeyringSource.fetch(reference, cx).await,
        SecretRef::GcpSm { .. } => GcpSmSource::default().fetch(reference, cx).await,
    }
}
