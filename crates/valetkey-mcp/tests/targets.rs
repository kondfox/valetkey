#![allow(deprecated)] // MCP roots are deprecated (SEP-2577), but Claude Code sends them and the broker cross-checks them.
//! `valetkey_targets` end to end over an in-process MCP connection, with a fake client that
//! answers `roots/list` the way Claude Code does (M0: first root = realpath of the launch dir).

use std::path::{Path, PathBuf};
use std::time::Duration;

use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation, ListRootsResult, Root};
use rmcp::service::RequestContext;
use rmcp::{ClientHandler, ErrorData, RoleClient, ServiceExt};
use serde_json::{Value, json};
use valetkey_core::snapshot::{self, Snapshot};
use valetkey_core::{NormalizeCx, Platform, Registry, ValetkeyRoot, project};
use valetkey_mcp::{Broker, BrokerConfig};
use valetkey_postgres::PostgresKind;

const CONFIG: &str = r#"
[targets.local-app]
kind = "postgres"
host = "localhost"
database = "app"
user = "app"
secret = "env-file://.env#POSTGRES_PASSWORD"
writable = true

[targets.staging-app]
kind = "postgres"
socket = "stage-core"
database = "app"
user = "vk_reader"
secret = "gcp-sm://acme-stage/DB_PASSWORD"
"#;

/// How the fake client answers `roots/list`.
#[derive(Clone)]
enum Roots {
    /// No roots capability at all.
    Unsupported,
    /// These directories, as `file://` URIs.
    Dirs(Vec<PathBuf>),
    /// These raw URIs.
    Uris(Vec<String>),
    /// An error response.
    Fails,
    /// An answer that comes too late.
    Slow,
}

#[derive(Clone)]
struct FakeClient {
    roots: Roots,
}

impl ClientHandler for FakeClient {
    fn get_info(&self) -> ClientConfig {
        let caps = match self.roots {
            Roots::Unsupported => ClientCapabilities::default(),
            _ => ClientCapabilities::builder().enable_roots().build(),
        };
        ClientConfig::new(caps, Implementation::new("claude-code", "test"))
    }

    async fn list_roots(&self, _cx: RequestContext<RoleClient>) -> Result<ListRootsResult, ErrorData> {
        let uris = match &self.roots {
            Roots::Unsupported => Vec::new(),
            Roots::Dirs(dirs) => dirs
                .iter()
                .map(|p| url::Url::from_directory_path(p).unwrap().to_string())
                .collect(),
            Roots::Uris(uris) => uris.clone(),
            Roots::Fails => return Err(ErrorData::internal_error("no roots for you", None)),
            Roots::Slow => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                Vec::new()
            }
        };
        Ok(ListRootsResult::new(uris.into_iter().map(Root::new).collect()))
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    project: PathBuf,
    root: ValetkeyRoot,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let project = base.join("repo");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("valetkey.toml"), CONFIG).unwrap();
    // A short root keeps socket paths under the macOS limit, whatever the temp dir is.
    let root = ValetkeyRoot::at(base.join("vk"));
    Fixture {
        _tmp: tmp,
        project,
        root,
    }
}

fn registry() -> Registry {
    Registry::default().with(PostgresKind)
}

fn approve(f: &Fixture) {
    let p = project::discover(&f.project).unwrap();
    let text = std::fs::read_to_string(&p.config_path).unwrap();
    let cx = NormalizeCx {
        root: &f.root,
        platform: Platform::Linux,
    };
    let config = registry().parse(&text, &cx).unwrap();
    snapshot::store(&f.root, &p, &Snapshot::new(&p, config)).unwrap();
}

async fn call(f: &Fixture, env_dir: Option<&Path>, roots: Option<Vec<PathBuf>>) -> Value {
    call_with(f, env_dir, roots.map_or(Roots::Unsupported, Roots::Dirs)).await
}

async fn call_with(f: &Fixture, env_dir: Option<&Path>, roots: Roots) -> Value {
    let broker = Broker::new(BrokerConfig {
        root: f.root.clone(),
        registry: registry(),
        platform: Platform::Linux,
        env_project_dir: env_dir.map(Path::to_owned),
        self_path: PathBuf::from("/opt/valetkey/bin/valetkey"),
        roots_timeout: Duration::from_millis(300),
        approval_timeout: valetkey_mcp::writes::APPROVAL_TIMEOUT,
    });
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move { broker.serve(server_io).await.unwrap().waiting().await });
    let client = FakeClient { roots }.serve(client_io).await.unwrap();

    let tools = client.list_all_tools().await.unwrap();
    let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    names.sort_unstable();
    assert_eq!(names, ["sql_describe", "sql_execute", "sql_query", "valetkey_targets"]);

    let result = client
        .call_tool(CallToolRequestParams::new("valetkey_targets"))
        .await
        .unwrap();
    let text = result.content[0].as_text().expect("text content").text.clone();
    client.cancel().await.unwrap();
    let _ = server.await;
    serde_json::from_str(&text).unwrap()
}

#[tokio::test]
async fn unapproved_project_lists_nothing() {
    let f = fixture();
    let r = call(&f, Some(&f.project), Some(vec![f.project.clone()])).await;
    assert_eq!(r["project"]["approval"], "not_approved");
    assert!(
        r["project"]["message"]
            .as_str()
            .unwrap()
            .contains("/opt/valetkey/bin/valetkey allow")
    );
    assert_eq!(r["targets"].as_array().unwrap().len(), 0);
    assert_eq!(r["client"]["fence_profile"], "claude-code");
}

#[tokio::test]
async fn approved_project_lists_its_targets() {
    let f = fixture();
    approve(&f);
    let r = call(&f, Some(&f.project), Some(vec![f.project.clone()])).await;
    assert_eq!(r["project"]["approval"], "approved");
    assert_eq!(r["project"]["dir_verified"], true);
    let targets = r["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0]["id"], "local-app");
    assert_eq!(targets[0]["secret_exposure"], "exposed");
    assert_eq!(targets[1]["id"], "staging-app");
    assert_eq!(targets[1]["secret_exposure"], "protected");
    // The exposed target is usable; the protected one waits for fence detection (M4).
    assert_eq!(targets[0]["available"], true);
    // It's writable, so it offers sql_execute, and says writes wait for `valetkey approve`.
    assert_eq!(targets[0]["tools"], json!(["sql_query", "sql_describe", "sql_execute"]));
    assert!(targets[0]["writes"].as_str().unwrap().contains("valetkey approve"), "{r}");
    assert_eq!(targets[1]["available"], false);
    assert!(
        targets[1]["reason"]
            .as_str()
            .unwrap()
            .contains("fence detection arrives in M4"),
        "{r}"
    );
}

#[tokio::test]
async fn a_subdirectory_launch_finds_the_project() {
    let f = fixture();
    approve(&f);
    let sub = f.project.join("apps/web");
    std::fs::create_dir_all(&sub).unwrap();
    let r = call(&f, Some(&sub), Some(vec![sub.clone()])).await;
    assert_eq!(r["project"]["approval"], "approved");
    assert_eq!(r["project"]["dir_verified"], true);
}

#[tokio::test]
async fn editing_the_config_after_approval_stops_serving() {
    let f = fixture();
    approve(&f);
    let edited = CONFIG.replace("vk_reader", "postgres");
    std::fs::write(f.project.join("valetkey.toml"), edited).unwrap();
    let r = call(&f, Some(&f.project), Some(vec![f.project.clone()])).await;
    assert_eq!(r["project"]["approval"], "stale");
    assert_eq!(r["targets"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn comment_only_edits_keep_the_approval() {
    let f = fixture();
    approve(&f);
    std::fs::write(f.project.join("valetkey.toml"), format!("# reviewed\n{CONFIG}")).unwrap();
    let r = call(&f, Some(&f.project), Some(vec![f.project.clone()])).await;
    assert_eq!(r["project"]["approval"], "approved");
}

#[tokio::test]
async fn project_dir_that_disagrees_with_roots_refuses_protected_targets() {
    let f = fixture();
    approve(&f);
    let elsewhere = f.project.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let r = call(&f, Some(&f.project), Some(vec![elsewhere])).await;
    assert_eq!(r["project"]["dir_verified"], false);
    let staging = &r["targets"][1];
    assert_eq!(staging["id"], "staging-app");
    assert!(staging["reason"].as_str().unwrap().starts_with("refused"));
}

#[tokio::test]
async fn client_without_roots_is_unverified() {
    let f = fixture();
    approve(&f);
    let r = call(&f, Some(&f.project), None).await;
    assert_eq!(r["project"]["dir_verified"], false);
    assert!(r["targets"][1]["reason"].as_str().unwrap().starts_with("refused"));
}

#[tokio::test]
async fn no_project_dir_at_all() {
    let f = fixture();
    let r = call(&f, None, None).await;
    assert_eq!(r["project"]["approval"], "no_project");
}

/// B1: nothing from the config file's content reaches the agent, even when it doesn't parse.
#[tokio::test]
async fn parse_errors_never_echo_file_content() {
    let f = fixture();
    approve(&f);
    std::fs::write(
        f.project.join("valetkey.toml"),
        "[targets.x]\nhost = \"SECRET-CANARY-91bc\n",
    )
    .unwrap();
    let r = call(&f, Some(&f.project), Some(vec![f.project.clone()])).await;
    assert_eq!(r["project"]["approval"], "stale");
    assert!(!r.to_string().contains("CANARY"), "{r}");
}

/// B1: a hard-linked config (possibly pointing at a fenced file) isn't read.
#[cfg(unix)]
#[tokio::test]
async fn hard_linked_config_is_not_read() {
    let f = fixture();
    approve(&f);
    let elsewhere = f.project.parent().unwrap().join("fenced-file");
    std::fs::rename(f.project.join("valetkey.toml"), &elsewhere).unwrap();
    std::fs::hard_link(&elsewhere, f.project.join("valetkey.toml")).unwrap();
    let r = call(&f, Some(&f.project), Some(vec![f.project.clone()])).await;
    assert_eq!(r["project"]["approval"], "stale", "{r}");
    assert_eq!(r["targets"].as_array().unwrap().len(), 0);
}

/// B1: a symlinked config isn't followed, and its target's content isn't echoed.
#[cfg(unix)]
#[tokio::test]
async fn symlinked_config_is_not_followed() {
    let f = fixture();
    let secret = f.project.parent().unwrap().join("secret.txt");
    std::fs::write(&secret, "TOKEN-CANARY-55aa").unwrap();
    std::fs::remove_file(f.project.join("valetkey.toml")).unwrap();
    std::os::unix::fs::symlink(&secret, f.project.join("valetkey.toml")).unwrap();
    let r = call(&f, Some(&f.project), Some(vec![f.project.clone()])).await;
    assert_eq!(r["project"]["approval"], "no_project");
    assert!(!r.to_string().contains("CANARY"), "{r}");
}

/// N2: a root that others can access doesn't serve protected targets.
#[cfg(unix)]
#[tokio::test]
async fn loose_root_permissions_refuse_protected_targets() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture();
    approve(&f);
    std::fs::set_permissions(f.root.dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let r = call(&f, Some(&f.project), Some(vec![f.project.clone()])).await;
    let staging = &r["targets"][1];
    assert!(staging["reason"].as_str().unwrap().contains("loose permissions"), "{r}");
}

/// Only the **first** root counts, as Claude Code puts the launch dir first (M0).
#[tokio::test]
async fn only_the_first_root_counts() {
    let f = fixture();
    approve(&f);
    let other = f.project.parent().unwrap().join("other");
    std::fs::create_dir_all(&other).unwrap();
    let first_is_project = call_with(
        &f,
        Some(&f.project),
        Roots::Dirs(vec![f.project.clone(), other.clone()]),
    )
    .await;
    assert_eq!(first_is_project["project"]["dir_verified"], true);
    let first_is_other = call_with(&f, Some(&f.project), Roots::Dirs(vec![other, f.project.clone()])).await;
    assert_eq!(first_is_other["project"]["dir_verified"], false);
}

#[tokio::test]
async fn percent_encoded_roots_are_decoded() {
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let project = base.join("my repo #1");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("valetkey.toml"), CONFIG).unwrap();
    let f = Fixture {
        _tmp: tmp,
        project: project.clone(),
        root: ValetkeyRoot::at(base.join("vk")),
    };
    approve(&f);
    let uri = url::Url::from_directory_path(&project).unwrap().to_string();
    assert!(uri.contains("%20") && uri.contains("%23"), "{uri}");
    let r = call_with(&f, Some(&project), Roots::Uris(vec![uri])).await;
    assert_eq!(r["project"]["dir_verified"], true, "{r}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_symlinked_project_dir_matches_its_realpath_root() {
    let f = fixture();
    approve(&f);
    let link = f.project.parent().unwrap().join("link-to-repo");
    std::os::unix::fs::symlink(&f.project, &link).unwrap();
    let r = call_with(&f, Some(&link), Roots::Dirs(vec![f.project.clone()])).await;
    assert_eq!(r["project"]["dir_verified"], true, "{r}");
}

/// Every way the roots answer can go wrong leaves the project dir unverified (fail closed).
#[tokio::test]
async fn unusable_roots_fail_closed() {
    let f = fixture();
    approve(&f);
    for (what, roots) in [
        ("a non-file root", Roots::Uris(vec!["https://example.com/repo".into()])),
        ("a malformed root", Roots::Uris(vec!["not a uri".into()])),
        ("no roots", Roots::Uris(vec![])),
        ("an error", Roots::Fails),
        ("a timeout", Roots::Slow),
    ] {
        let r = call_with(&f, Some(&f.project), roots).await;
        assert_eq!(r["project"]["dir_verified"], false, "{what}: {r}");
        assert!(
            r["targets"][1]["reason"]
                .as_str()
                .unwrap()
                .contains("couldn't be verified against the client's MCP roots"),
            "{what}: {r}"
        );
    }
}
