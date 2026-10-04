//! The sources against real files and a fake `gcloud`. Every failure's public message is checked
//! for leaked content.

use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;
use valetkey_core::secret_source::FetchCx;
use valetkey_core::user_config::{ToolConfig, UserConfig};
use valetkey_core::{SecretRef, ValetkeyRoot};

struct Env {
    _tmp: tempfile::TempDir,
    base: PathBuf,
    project: PathBuf,
    root: ValetkeyRoot,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let project = base.join("repo");
    std::fs::create_dir_all(&project).unwrap();
    Env {
        project,
        root: ValetkeyRoot::at(base.join("vk")),
        base,
        _tmp: tmp,
    }
}

async fn fetch(e: &Env, user: &UserConfig, reference: &str) -> Result<String, String> {
    let cx = FetchCx {
        project_root: &e.project,
        root: &e.root,
        user,
    };
    let r: SecretRef = reference.parse().unwrap();
    valetkey_secrets::fetch(&r, &cx)
        .await
        .map(|s| s.expose_secret().to_owned())
        .map_err(|err| {
            let public = err.to_string();
            assert!(
                !public.contains("CANARY"),
                "secret material in a public error: {public}"
            );
            public
        })
}

#[tokio::test]
async fn env_file_reads_a_key() {
    let e = env();
    std::fs::write(e.project.join(".env"), "OTHER=CANARY-other\nPOSTGRES_PASSWORD=s3cret\n").unwrap();
    assert_eq!(
        fetch(&e, &UserConfig::default(), "env-file://.env#POSTGRES_PASSWORD")
            .await
            .unwrap(),
        "s3cret"
    );
    let missing = fetch(&e, &UserConfig::default(), "env-file://.env#NOPE")
        .await
        .unwrap_err();
    assert!(missing.contains("doesn't define `NOPE`"), "{missing}");
}

#[cfg(unix)]
#[tokio::test]
async fn env_file_never_follows_a_symlinked_directory() {
    let e = env();
    let outside = e.base.join("aws");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("credentials"), "KEY=CANARY-fenced\n").unwrap();
    std::os::unix::fs::symlink(&outside, e.project.join("conf")).unwrap();
    let err = fetch(&e, &UserConfig::default(), "env-file://conf/credentials#KEY")
        .await
        .unwrap_err();
    assert!(err.contains("can't read the env-file"), "{err}");
}

#[cfg(unix)]
fn write_private(path: &Path, content: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, content).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn local_secrets_must_be_private() {
    let e = env();
    let dir = e.root.secrets_dir();
    valetkey_core::paths::ensure_private_dir(&dir).unwrap();
    write_private(&dir.join("app"), "pw\n", 0o600);
    assert_eq!(
        fetch(&e, &UserConfig::default(), "local://app").await.unwrap(),
        "pw",
        "one trailing newline is dropped"
    );

    write_private(&dir.join("app"), "CANARY-pw", 0o644);
    let err = fetch(&e, &UserConfig::default(), "local://app").await.unwrap_err();
    assert!(err.contains("can't read local://app"), "{err}");

    let missing = fetch(&e, &UserConfig::default(), "local://nope").await.unwrap_err();
    assert!(missing.contains("valetkey secret set nope"), "{missing}");
}

/// A fake `gcloud` that records its argv and environment, then prints like the real one:
/// the value with no trailing newline (gcloud 496 source, wiki: integrations/gcloud).
#[cfg(unix)]
fn fake_gcloud(dir: &Path, behaviour: &str) -> PathBuf {
    let path = dir.join("gcloud");
    let log = dir.join("gcloud.log");
    let script = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{log}.args'\n/usr/bin/env > '{log}.env'\n{behaviour}\n",
        log = log.display()
    );
    write_private(&path, &script, 0o700);
    path
}

#[cfg(unix)]
fn user_with(gcloud: PathBuf) -> UserConfig {
    let mut user = UserConfig::default();
    user.tools.insert(
        "gcloud".into(),
        ToolConfig {
            path: gcloud,
            env: [("CLOUDSDK_PYTHON".into(), "/opt/py/bin/python3".into())].into(),
        },
    );
    user
}

#[cfg(unix)]
#[tokio::test]
async fn gcp_sm_runs_the_configured_gcloud_with_exact_args_and_env() {
    let e = env();
    let tools = e.base.join("sdk/bin");
    std::fs::create_dir_all(&tools).unwrap();
    let gcloud = fake_gcloud(&tools, "printf 'db-pass'");
    let value = fetch(&e, &user_with(gcloud), "gcp-sm://acme-stage/DB_PASSWORD")
        .await
        .unwrap();
    assert_eq!(value, "db-pass");

    let args = std::fs::read_to_string(tools.join("gcloud.log.args")).unwrap();
    assert_eq!(
        args.lines().collect::<Vec<_>>(),
        [
            "secrets",
            "versions",
            "access",
            "latest",
            "--secret",
            "DB_PASSWORD",
            "--project",
            "acme-stage",
            "--quiet"
        ]
    );
    let env = std::fs::read_to_string(tools.join("gcloud.log.env")).unwrap();
    let mut names: Vec<_> = env
        .lines()
        .filter_map(|l| l.split('=').next())
        .filter(|n| !["PWD", "SHLVL", "_"].contains(n))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK",
            "CLOUDSDK_CORE_DISABLE_PROMPTS",
            "CLOUDSDK_PYTHON",
            "HOME",
            "LANG",
            "PATH"
        ],
        "{env}"
    );
    assert!(
        env.contains(&format!("PATH={}:/usr/bin:/bin", tools.display())),
        "{env}"
    );
    let home = valetkey_core::paths::os_home_dir().unwrap();
    assert!(env.contains(&format!("HOME={}", home.display())), "{env}");
}

#[cfg(unix)]
#[tokio::test]
async fn gcp_sm_failures_stay_out_of_the_public_message() {
    let e = env();
    let gcloud = fake_gcloud(
        &e.base,
        "echo 'ERROR: CANARY permission denied on DB_PASSWORD' >&2; exit 1",
    );
    let err = fetch(&e, &user_with(gcloud), "gcp-sm://acme-stage/DB_PASSWORD")
        .await
        .unwrap_err();
    assert!(err.contains("see the valetkey log"), "{err}");
}

#[tokio::test]
async fn gcp_sm_without_setup_says_so() {
    let e = env();
    let err = fetch(&e, &UserConfig::default(), "gcp-sm://acme-stage/DB_PASSWORD")
        .await
        .unwrap_err();
    assert!(err.contains("valetkey setup"), "{err}");
}

#[cfg(unix)]
#[tokio::test]
async fn local_secrets_can_be_managed() {
    use secrecy::SecretString;
    use valetkey_secrets::sources::LocalSource;
    let e = env();
    LocalSource::store(&e.root, "app", &SecretString::from("one"), false).unwrap();
    assert!(
        LocalSource::store(&e.root, "app", &SecretString::from("two"), false).is_err(),
        "no silent overwrite"
    );
    LocalSource::store(&e.root, "app", &SecretString::from("two"), true).unwrap();
    assert_eq!(fetch(&e, &UserConfig::default(), "local://app").await.unwrap(), "two");
    assert!(LocalSource::store(&e.root, "../escape", &SecretString::from("x"), false).is_err());
    assert_eq!(LocalSource::list(&e.root).unwrap(), ["app"]);
    assert!(LocalSource::remove(&e.root, "app").unwrap());
    assert!(!LocalSource::remove(&e.root, "app").unwrap());
    assert!(LocalSource::list(&e.root).unwrap().is_empty());
}
