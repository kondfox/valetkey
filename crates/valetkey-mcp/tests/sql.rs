#![allow(deprecated)] // MCP roots are deprecated (SEP-2577), but Claude Code sends them.
//! `sql_query` / `sql_describe` end to end: a fake MCP client, the broker, a real Postgres
//! (testcontainers). Skipped without Docker locally; required in CI on Linux.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation, ListRootsResult, Root};
use rmcp::service::RequestContext;
use rmcp::{ClientHandler, ErrorData, RoleClient, ServiceExt};
use serde_json::{Value, json};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use valetkey_core::snapshot::{self, Snapshot};
use valetkey_core::{NormalizeCx, Platform, Registry, ValetkeyRoot, project};
use valetkey_mcp::{Broker, BrokerConfig};
use valetkey_postgres::PostgresKind;

fn docker_available() -> bool {
    let ok = std::process::Command::new("docker")
        .arg("info")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok && std::env::var_os("CI").is_some() && cfg!(target_os = "linux") {
        panic!("Docker is required for these tests in CI on Linux");
    }
    ok
}

/// Everything the broker logs during this test binary, to check nothing sensitive gets in.
fn captured_log() -> Arc<Mutex<Vec<u8>>> {
    static LOG: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOG.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let writer = buf.clone();
        // Exactly the production filter, so this checks what the real log would contain.
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Capture(writer.clone()))
            .with_env_filter(tracing_subscriber::EnvFilter::new(valetkey_mcp::LOG_FILTER))
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
        buf
    })
    .clone()
}

struct Capture(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Capture {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct Client {
    root: PathBuf,
}

impl ClientHandler for Client {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::new(
            ClientCapabilities::builder().enable_roots().build(),
            Implementation::new("claude-code", "test"),
        )
    }
    async fn list_roots(&self, _cx: RequestContext<RoleClient>) -> Result<ListRootsResult, ErrorData> {
        Ok(ListRootsResult::new(vec![Root::new(
            url::Url::from_directory_path(&self.root).unwrap().to_string(),
        )]))
    }
}

struct Env {
    _tmp: tempfile::TempDir,
    _pg: ContainerAsync<Postgres>,
    port: u16,
    project: PathBuf,
    root: ValetkeyRoot,
}

async fn env() -> Env {
    let pg = Postgres::default()
        .with_password("pw")
        .with_tag("17")
        .start()
        .await
        .unwrap();
    let port = pg.get_host_port_ipv4(5432).await.unwrap();
    let (client, conn) = tokio_postgres::connect(
        &format!("host=127.0.0.1 port={port} user=postgres password=pw"),
        tokio_postgres::NoTls,
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    client
        .batch_execute(
            "CREATE ROLE vk_reader LOGIN PASSWORD 'reader-pw';
             CREATE TABLE items(id int PRIMARY KEY, name text);
             INSERT INTO items VALUES (1, 'one'), (2, 'two');
             GRANT SELECT ON items TO vk_reader;",
        )
        .await
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let project = base.join("repo");
    std::fs::create_dir_all(&project).unwrap();
    // A short root keeps the socket path under the macOS limit.
    let root = ValetkeyRoot::at(base.join("vk"));
    valetkey_core::paths::ensure_private_dir(root.dir()).unwrap();
    Env {
        _tmp: tmp,
        _pg: pg,
        port,
        project,
        root,
    }
}

/// Bridges a unix socket in the valetkey sockets dir to the container's TCP port, standing in for
/// a Cloud SQL proxy (Docker Desktop can't share a container's unix socket with the host).
#[cfg(unix)]
fn socket_bridge(e: &Env, alias: &str) {
    let dir = e.root.socket_dir(alias);
    std::fs::create_dir_all(&dir).unwrap();
    let listener = tokio::net::UnixListener::bind(dir.join(".s.PGSQL.5432")).unwrap();
    let port = e.port;
    tokio::spawn(async move {
        while let Ok((mut unix, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut unix, &mut tcp).await;
            });
        }
    });
}

fn approve(e: &Env, config: &str) {
    std::fs::write(e.project.join("valetkey.toml"), config).unwrap();
    let p = project::discover(&e.project).unwrap();
    let cx = NormalizeCx {
        root: &e.root,
        platform: Platform::current(),
    };
    let parsed = Registry::default().with(PostgresKind).parse(config, &cx).unwrap();
    snapshot::store(&e.root, &p, &Snapshot::new(&p, parsed)).unwrap();
}

async fn call(e: &Env, broker: &Broker, tool: &str, args: Value) -> (bool, Value) {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    let b = broker.clone();
    let server = tokio::spawn(async move { b.serve(server_io).await.unwrap().waiting().await });
    let client = Client {
        root: e.project.clone(),
    }
    .serve(client_io)
    .await
    .unwrap();
    let r = client
        .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(args.as_object().unwrap().clone()))
        .await
        .unwrap();
    client.cancel().await.unwrap();
    let _ = server.await;
    let text = r.content[0].as_text().unwrap().text.clone();
    let is_error = r.is_error.unwrap_or(false);
    (is_error, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

fn broker(e: &Env) -> Broker {
    Broker::new(BrokerConfig {
        root: e.root.clone(),
        registry: Registry::default().with(PostgresKind),
        platform: Platform::current(),
        env_project_dir: Some(e.project.clone()),
        self_path: PathBuf::from("/opt/valetkey/bin/valetkey"),
        roots_timeout: Duration::from_secs(2),
    })
}

fn exposed(e: &Env) -> String {
    format!(
        "[targets.local-app]\nkind = \"postgres\"\nhost = \"127.0.0.1\"\nport = {}\ndatabase = \"postgres\"\nuser = \"vk_reader\"\nsecret = \"env-file://.env#PGPASSWORD\"\n",
        e.port
    )
}

#[tokio::test]
async fn sql_query_reads_an_exposed_target() {
    if !docker_available() {
        return;
    }
    let log = captured_log();
    let e = env().await;
    std::fs::write(e.project.join(".env"), "PGPASSWORD=reader-pw\n").unwrap();
    approve(&e, &exposed(&e));
    let b = broker(&e);

    let (err, r) = call(&e, &b, "sql_query", json!({ "target": "local-app", "sql": "SELECT name FROM items WHERE id = $1 AND $2::text <> 'CANARY-param'", "params": [2, "x"] })).await;
    assert!(!err, "{r}");
    assert_eq!(r["rows"], json!([["two"]]));
    assert_eq!(r["verified"]["user"], "vk_reader");
    assert!(r.get("fence").is_none(), "exposed targets need no fence note");

    let (err, r) = call(
        &e,
        &b,
        "sql_describe",
        json!({ "target": "local-app", "table": "items" }),
    )
    .await;
    assert!(!err, "{r}");
    let columns: Vec<&str> = r["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row[1].as_str().unwrap())
        .collect();
    assert_eq!(columns, ["id", "name"]);

    let (err, r) = call(&e, &b, "sql_query", json!({ "target": "nope", "sql": "SELECT 1" })).await;
    assert!(err);
    assert!(
        r.as_str()
            .unwrap()
            .contains("unknown target `nope`; approved targets: local-app"),
        "{r}"
    );

    let log = String::from_utf8(log.lock().unwrap().clone()).unwrap();
    assert!(log.contains("statement_hash"), "{log}");
    assert!(
        !log.contains("CANARY-param") && !log.contains("SELECT name") && !log.contains("reader-pw"),
        "{log}"
    );
}

#[tokio::test]
async fn a_rejected_password_is_dropped_from_the_cache() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    std::fs::write(e.project.join(".env"), "PGPASSWORD=wrong\n").unwrap();
    approve(&e, &exposed(&e));
    let b = broker(&e);
    let (err, r) = call(&e, &b, "sql_query", json!({ "target": "local-app", "sql": "SELECT 1" })).await;
    assert!(
        err && r.as_str().unwrap().contains("rejected the stored password"),
        "{r}"
    );
    std::fs::write(e.project.join(".env"), "PGPASSWORD=reader-pw\n").unwrap();
    let (err, r) = call(&e, &b, "sql_query", json!({ "target": "local-app", "sql": "SELECT 1" })).await;
    assert!(!err, "the next call fetched the corrected secret: {r}");
}

#[cfg(unix)]
#[tokio::test]
async fn protected_targets_wait_for_a_fence_and_policy_runs_before_the_cache() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    socket_bridge(&e, "pg");
    valetkey_secrets::sources::LocalSource::store(&e.root, "pg", &secrecy::SecretString::from("reader-pw"), false)
        .unwrap();
    let protected = "[targets.staging-app]\nkind = \"postgres\"\nsocket = \"pg\"\ndatabase = \"postgres\"\nuser = \"vk_reader\"\nsecret = \"local://pg\"\n";
    let b = broker(&e);

    approve(&e, protected);
    let (err, r) = call(
        &e,
        &b,
        "sql_query",
        json!({ "target": "staging-app", "sql": "SELECT 1" }),
    )
    .await;
    assert!(
        err && r.as_str().unwrap().contains("fence detection arrives in M4"),
        "{r}"
    );

    let unfenced = format!("require_fence = false\n{protected}");
    approve(&e, &unfenced);
    let (err, r) = call(
        &e,
        &b,
        "sql_query",
        json!({ "target": "staging-app", "sql": "SELECT count(*) FROM items" }),
    )
    .await;
    assert!(!err, "{r}");
    assert_eq!(r["rows"], json!([["2"]]));
    assert!(
        r["fence"].as_str().unwrap().starts_with("none"),
        "results say they're unfenced: {r}"
    );

    // The secret is now cached. Editing the config makes it stale: the next call is refused by
    // policy, cache or not.
    std::fs::write(
        e.project.join("valetkey.toml"),
        unfenced.replace("vk_reader", "postgres"),
    )
    .unwrap();
    let (err, r) = call(
        &e,
        &b,
        "sql_query",
        json!({ "target": "staging-app", "sql": "SELECT 1" }),
    )
    .await;
    assert!(
        err && r.as_str().unwrap().contains("changed since it was approved"),
        "{r}"
    );
}
