#![allow(deprecated)] // MCP roots are deprecated (SEP-2577), but Claude Code sends them and the broker cross-checks them.
//! `valetkey_targets` end to end over an in-process MCP connection, with a fake client that
//! answers `roots/list` the way Claude Code does (M0: first root = realpath of the launch dir).

use std::path::{Path, PathBuf};

use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation, ListRootsResult, Root};
use rmcp::service::RequestContext;
use rmcp::{ClientHandler, ErrorData, RoleClient, ServiceExt};
use serde_json::Value;
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

#[derive(Clone)]
struct FakeClient {
    roots: Option<Vec<PathBuf>>,
}

impl ClientHandler for FakeClient {
    fn get_info(&self) -> ClientConfig {
        let caps = if self.roots.is_some() {
            ClientCapabilities::builder().enable_roots().build()
        } else {
            ClientCapabilities::default()
        };
        ClientConfig::new(caps, Implementation::new("claude-code", "test"))
    }

    async fn list_roots(&self, _cx: RequestContext<RoleClient>) -> Result<ListRootsResult, ErrorData> {
        let roots = self.roots.clone().unwrap_or_default();
        Ok(ListRootsResult::new(
            roots
                .iter()
                .map(|p| Root::new(url::Url::from_directory_path(p).unwrap().to_string()))
                .collect(),
        ))
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
    let broker = Broker::new(BrokerConfig {
        root: f.root.clone(),
        registry: registry(),
        platform: Platform::Linux,
        env_project_dir: env_dir.map(Path::to_owned),
        self_path: PathBuf::from("/opt/valetkey/bin/valetkey"),
    });
    let (server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move { broker.serve(server_io).await.unwrap().waiting().await });
    let client = FakeClient { roots }.serve(client_io).await.unwrap();

    let tools = client.list_all_tools().await.unwrap();
    assert_eq!(
        tools.iter().map(|t| t.name.as_ref()).collect::<Vec<_>>(),
        ["valetkey_targets"]
    );

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
    assert!(targets.iter().all(|t| t["available"] == false));
    assert!(targets[1]["reason"].as_str().unwrap().contains("M2"));
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
