//! The `valetkey` binary, end to end. Every test uses its own `VALETKEY_DEV_ROOT` (honoured by
//! debug builds only), so the developer's real `~/.valetkey/` is never touched.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use valetkey_core::snapshot::{self, Snapshot};
use valetkey_core::{NormalizeCx, Platform, Registry, ValetkeyRoot, project};

const BIN: &str = env!("CARGO_BIN_EXE_valetkey");

const CONFIG: &str = r#"
[targets.local-app]
kind = "postgres"
host = "localhost"
database = "app"
user = "app"
secret = "env-file://.env#POSTGRES_PASSWORD"
"#;

struct Env {
    _tmp: tempfile::TempDir,
    project: PathBuf,
    root: PathBuf,
}

fn env() -> Env {
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let project = base.join("repo");
    std::fs::create_dir_all(&project).unwrap();
    Env {
        project,
        root: base.join("vk"),
        _tmp: tmp,
    }
}

fn run(e: &Env, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(&e.project)
        .env("VALETKEY_DEV_ROOT", &e.root)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn approve(e: &Env) {
    let root = ValetkeyRoot::at(&e.root);
    let p = project::discover(&e.project).unwrap();
    let cx = NormalizeCx {
        root: &root,
        platform: Platform::current(),
    };
    let config = Registry::default()
        .with(valetkey_postgres::PostgresKind)
        .parse(CONFIG, &cx)
        .unwrap();
    snapshot::store(&root, &p, &Snapshot::new(&p, config)).unwrap();
}

#[test]
fn version() {
    let o = Command::new(BIN).arg("--version").output().unwrap();
    assert!(o.status.success());
    assert!(stdout(&o).starts_with("valetkey "));
}

#[test]
fn init_creates_a_valid_config_once() {
    let e = env();
    let o = run(&e, &["init"]);
    assert!(o.status.success(), "{}", stdout(&o));
    assert!(e.project.join("valetkey.toml").exists());
    let again = run(&e, &["init"]);
    assert!(!again.status.success());
    assert!(stdout(&again).contains("already exists"));
}

#[test]
fn allow_refuses_without_a_terminal_and_writes_nothing() {
    let e = env();
    std::fs::write(e.project.join("valetkey.toml"), CONFIG).unwrap();
    let o = run(&e, &["allow"]);
    assert!(!o.status.success());
    assert!(stdout(&o).contains("needs an interactive terminal"));
    assert!(!e.root.join("projects").exists());
}

#[test]
fn doctor_reports_the_approval_state() {
    let e = env();
    std::fs::write(e.project.join("valetkey.toml"), CONFIG).unwrap();
    let o = run(&e, &["doctor"]);
    assert!(!o.status.success());
    assert!(stdout(&o).contains("not approved on this machine"), "{}", stdout(&o));

    approve(&e);
    let o = run(&e, &["doctor"]);
    assert!(o.status.success(), "{}", stdout(&o));
    assert!(stdout(&o).contains("✔ approved on this machine"));
}

#[test]
fn doctor_reports_config_problems() {
    let e = env();
    std::fs::write(
        e.project.join("valetkey.toml"),
        CONFIG.replace("env-file://.env#POSTGRES_PASSWORD", "local://app"),
    )
    .unwrap();
    let o = run(&e, &["doctor"]);
    assert!(!o.status.success());
    assert!(stdout(&o).contains("can't be sent over plain TCP"), "{}", stdout(&o));
}

#[test]
fn doctor_without_a_project() {
    let e = env();
    let o = run(&e, &["doctor"]);
    assert!(!o.status.success());
    assert!(stdout(&o).contains("no valetkey.toml found"), "{}", stdout(&o));
}

/// The real binary speaks MCP on stdout (nothing else may write there) and logs to a file.
#[tokio::test]
async fn mcp_server_serves_valetkey_targets() {
    let e = env();
    std::fs::write(e.project.join("valetkey.toml"), CONFIG).unwrap();
    approve(&e);

    let project: &Path = &e.project;
    let transport = TokioChildProcess::new(tokio::process::Command::new(BIN).configure(|cmd| {
        cmd.arg("mcp")
            .env("VALETKEY_DEV_ROOT", &e.root)
            .env("CLAUDE_PROJECT_DIR", project);
    }))
    .unwrap();
    let client = ().serve(transport).await.unwrap();
    let result = client
        .call_tool(CallToolRequestParams::new("valetkey_targets"))
        .await
        .unwrap();
    let report: serde_json::Value = serde_json::from_str(&result.content[0].as_text().unwrap().text).unwrap();
    client.cancel().await.unwrap();

    assert_eq!(report["project"]["approval"], "approved");
    // This client sends no roots, so the project dir can't be verified.
    assert_eq!(report["project"]["dir_verified"], false);
    assert_eq!(report["targets"][0]["id"], "local-app");
    let log = std::fs::read_to_string(e.root.join("logs/mcp.log")).unwrap();
    assert!(log.contains("broker starting"));
}

/// The root comes from the OS user database, never from `HOME` (or `USERPROFILE` on Windows):
/// a settings `env` block can set those for the broker (M0).
#[test]
fn the_root_ignores_home() {
    let e = env();
    let fake_home = e.root.parent().unwrap().join("fake-home");
    let o = Command::new(BIN)
        .arg("doctor")
        .current_dir(&e.project)
        .env_remove("VALETKEY_DEV_ROOT")
        .env("HOME", &fake_home)
        .env("USERPROFILE", &fake_home)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let out = stdout(&o);
    let real = valetkey_core::paths::os_home_dir().unwrap().join(".valetkey");
    assert!(out.contains(&format!("valetkey root: {}", real.display())), "{out}");
    assert!(
        !out.contains(&format!("valetkey root: {}", fake_home.display())),
        "{out}"
    );
}

#[test]
fn doctor_prints_the_proxy_command_for_a_missing_socket() {
    let e = env();
    let config = "[targets.staging-app]\nkind = \"postgres\"\nsocket = \"stage-core\"\ndatabase = \"app\"\nuser = \"vk_reader\"\nsecret = \"gcp-sm://acme-stage/DB_PASSWORD\"\n";
    std::fs::write(e.project.join("valetkey.toml"), config).unwrap();
    let out = stdout(&run(&e, &["doctor"]));
    let socket_dir = ValetkeyRoot::at(&e.root).socket_dir("stage-core");
    assert!(out.contains("no proxy socket yet"), "{out}");
    assert!(
        out.contains(&format!("unix-socket-path={}", socket_dir.display())),
        "{out}"
    );
}

#[test]
fn setup_and_secret_set_refuse_without_a_terminal() {
    let e = env();
    for args in [&["setup"][..], &["secret", "set", "app"][..]] {
        let o = run(&e, args);
        assert!(!o.status.success(), "{args:?}");
        assert!(
            stdout(&o).contains("needs an interactive terminal"),
            "{args:?}: {}",
            stdout(&o)
        );
    }
    assert!(!e.root.join("secrets").exists());
    assert!(!e.root.join("config.toml").exists());
}

#[test]
fn secret_ls_and_rm_never_show_values() {
    let e = env();
    let root = ValetkeyRoot::at(&e.root);
    valetkey_secrets::sources::LocalSource::store(&root, "app", &secrecy::SecretString::from("CANARY-value"), false)
        .unwrap();
    let ls = stdout(&run(&e, &["secret", "ls"]));
    assert_eq!(ls.trim(), "local://app");
    let rm = run(&e, &["secret", "rm", "app"]);
    assert!(rm.status.success());
    assert!(!stdout(&rm).contains("CANARY"));
    assert!(stdout(&run(&e, &["secret", "ls"])).trim().is_empty());
}

#[test]
fn doctor_says_which_secret_is_missing_and_how_to_set_it() {
    let e = env();
    let config = "require_fence = false\n[targets.staging-app]\nkind = \"postgres\"\nsocket = \"stage-core\"\ndatabase = \"app\"\nuser = \"vk_reader\"\nsecret = \"local://staging-app\"\n\n[targets.cloud-app]\nkind = \"postgres\"\nsocket = \"cloud-core\"\ndatabase = \"app\"\nuser = \"vk_reader\"\nsecret = \"gcp-sm://acme-stage/DB_PASSWORD\"\n";
    std::fs::write(e.project.join("valetkey.toml"), config).unwrap();
    let out = stdout(&run(&e, &["doctor"]));
    assert!(out.contains("local://staging-app isn't set"), "{out}");
    assert!(out.contains("secret set staging-app"), "{out}");
    assert!(out.contains("gcloud isn't configured"), "{out}");
}
