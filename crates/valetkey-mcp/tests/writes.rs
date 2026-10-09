#![allow(deprecated)] // MCP roots are deprecated (SEP-2577), but Claude Code sends them.
//! `sql_execute` end to end: a fake MCP client, the broker, a real Postgres (testcontainers), and
//! an "approver" task that plays the human with the same store API `valetkey approve` uses. Skipped
//! without Docker locally; required in CI on Linux.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResult, ClientCapabilities, ClientConfig, ClientRequest,
    Implementation, ListRootsResult, Root,
};
use rmcp::service::{PeerRequestOptions, RequestContext, RunningService};
use rmcp::{ClientHandler, ErrorData, RoleClient, ServiceExt};
use serde_json::{Value, json};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use valetkey_core::audit::{self, AuditRecord, Outcome};
use valetkey_core::snapshot::{self, Snapshot};
use valetkey_core::write_store::{self, Decision, Verdict};
use valetkey_core::{NormalizeCx, Platform, Registry, ValetkeyRoot, project};
use valetkey_mcp::{Broker, BrokerConfig};
use valetkey_postgres::PostgresKind;

fn docker_available() -> bool {
    let ok = std::process::Command::new("docker")
        .args(["info", "--format", "{{.OSType}}"])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "linux");
    if !ok && std::env::var_os("CI").is_some() && cfg!(target_os = "linux") {
        panic!("Docker is required for these tests in CI on Linux");
    }
    ok
}

/// Everything the broker logs during this test binary, to check no statement text gets in.
fn captured_log() -> Arc<Mutex<Vec<u8>>> {
    static LOG: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOG.get_or_init(|| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let writer = buf.clone();
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
    captured_log();
    let pg = Postgres::default()
        .with_password("pw")
        .with_tag("17")
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .await
        .unwrap();
    let mut port = None;
    for _ in 0..20 {
        if let Ok(p) = pg.get_host_port_ipv4(5432).await {
            port = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let port = port.unwrap();
    admin(
        port,
        "CREATE ROLE vk_writer LOGIN PASSWORD 'writer-pw';
         CREATE TABLE items(id int PRIMARY KEY, name text);
         INSERT INTO items VALUES (1, 'one'), (2, 'two');
         GRANT ALL ON items TO vk_writer;",
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let project = base.join("repo");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join(".env"), "PGPASSWORD=writer-pw\n").unwrap();
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

async fn admin_client(port: u16) -> tokio_postgres::Client {
    let (client, conn) = tokio_postgres::connect(
        &format!("host=127.0.0.1 port={port} user=postgres password=pw"),
        tokio_postgres::NoTls,
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    client
}

async fn admin(port: u16, sql: &str) {
    admin_client(port).await.batch_execute(sql).await.unwrap();
}

async fn name_of(e: &Env, id: i32) -> Option<String> {
    admin_client(e.port)
        .await
        .query_opt("SELECT name FROM items WHERE id = $1", &[&id])
        .await
        .unwrap()
        .map(|r| r.get(0))
}

fn config(e: &Env, writable: bool) -> String {
    format!(
        "[targets.local-app]\nkind = \"postgres\"\nhost = \"127.0.0.1\"\nport = {}\ndatabase = \"postgres\"\nuser = \"vk_writer\"\nsecret = \"env-file://.env#PGPASSWORD\"\nwritable = {writable}\n",
        e.port
    )
}

fn allow(e: &Env, text: &str) {
    std::fs::write(e.project.join("valetkey.toml"), text).unwrap();
    let p = project::discover(&e.project).unwrap();
    let cx = NormalizeCx {
        root: &e.root,
        platform: Platform::current(),
    };
    let parsed = Registry::default().with(PostgresKind).parse(text, &cx).unwrap();
    snapshot::store(&e.root, &p, &Snapshot::new(&p, parsed)).unwrap();
}

fn broker(e: &Env, approval_timeout: Duration) -> Broker {
    Broker::new(BrokerConfig {
        root: e.root.clone(),
        registry: Registry::default().with(PostgresKind),
        platform: Platform::current(),
        env_project_dir: Some(e.project.clone()),
        self_path: PathBuf::from("/opt/valetkey/bin/valetkey"),
        roots_timeout: Duration::from_secs(2),
        approval_timeout,
    })
}

struct Session {
    client: RunningService<RoleClient, Client>,
    server: tokio::task::JoinHandle<()>,
}

async fn connect(e: &Env, b: &Broker) -> Session {
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    let b = b.clone();
    let server = tokio::spawn(async move {
        let _ = b.serve(server_io).await.unwrap().waiting().await;
    });
    let client = Client {
        root: e.project.clone(),
    }
    .serve(client_io)
    .await
    .unwrap();
    Session { client, server }
}

fn params(args: Value) -> CallToolRequestParams {
    CallToolRequestParams::new("sql_execute").with_arguments(args.as_object().unwrap().clone())
}

async fn call(s: &Session, args: Value) -> (bool, Value) {
    let r = s.client.call_tool(params(args)).await.unwrap();
    decode(r)
}

fn decode(r: CallToolResult) -> (bool, Value) {
    let text = r.content[0].as_text().unwrap().text.clone();
    let is_error = r.is_error.unwrap_or(false);
    (is_error, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

fn update(name: &str) -> Value {
    json!({ "target": "local-app", "sql": "UPDATE items SET name = $1 WHERE id = $2", "params": [name, 1], "allow_write": true })
}

/// Plays the human: waits for a pending request and decides it, hashing what it loaded.
async fn decide(root: &ValetkeyRoot, verdict: Verdict) -> String {
    for _ in 0..200 {
        if let Some(e) = write_store::list(root).unwrap().into_iter().next() {
            let r = e.request.unwrap();
            write_store::decide(
                root,
                &Decision {
                    id: r.id.clone(),
                    request_hash: r.hash(),
                    verdict,
                    at: "2026-10-09T10:00:00Z".into(),
                    tty: Some("/dev/ttys001".into()),
                },
            )
            .unwrap();
            return r.id;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no pending request appeared");
}

async fn wait_for_pending(root: &ValetkeyRoot) -> String {
    for _ in 0..200 {
        if let Some(e) = write_store::list(root).unwrap().into_iter().next() {
            return e.id;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no pending request appeared");
}

fn records(root: &ValetkeyRoot) -> Vec<AuditRecord> {
    audit::files(root)
        .iter()
        .flat_map(|(_, _, p)| audit::read_file(p).unwrap())
        .map(Result::unwrap)
        .collect()
}

fn outcomes(root: &ValetkeyRoot) -> Vec<Outcome> {
    records(root).iter().map(|r| r.outcome).collect()
}

#[tokio::test]
async fn an_approved_write_commits_and_is_audited() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    allow(&e, &config(&e, true));
    let b = broker(&e, Duration::from_secs(30));
    let s = connect(&e, &b).await;
    let root = e.root.clone();
    let approver = tokio::spawn(async move { decide(&root, Verdict::Approve).await });
    let (is_error, out) = call(&s, update("uno-secret-marker")).await;
    let id = approver.await.unwrap();
    assert!(!is_error, "{out}");
    assert_eq!(out["rows_affected"], 1);
    assert_eq!(out["approval"]["id"], id.as_str());
    assert_eq!(out["verified"]["user"], "vk_writer");
    assert_eq!(name_of(&e, 1).await.as_deref(), Some("uno-secret-marker"));
    assert!(write_store::list(&e.root).unwrap().is_empty(), "files removed");
    assert!(!e.root.write_approvals_dir().join(format!("{id}.json")).exists());

    let recs = records(&e.root);
    assert_eq!(
        recs.iter().map(|r| r.outcome).collect::<Vec<_>>(),
        [Outcome::Approved, Outcome::Ok]
    );
    let ok = &recs[1];
    assert_eq!(ok.approval.as_ref().unwrap().tty.as_deref(), Some("/dev/ttys001"));
    assert_eq!(ok.params, [Some("uno-secret-marker".into()), Some("1".into())]);
    assert_eq!(ok.rows_affected, Some(1));
    assert_eq!(ok.client_name.as_deref(), Some("claude-code"));

    let log = String::from_utf8(captured_log().lock().unwrap().clone()).unwrap();
    assert!(
        !log.contains("uno-secret-marker") && !log.contains("UPDATE items"),
        "{log}"
    );
    s.client.cancel().await.unwrap();
    let _ = s.server.await;
}

#[tokio::test]
async fn denied_timed_out_and_mismatched_writes_never_run() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    allow(&e, &config(&e, true));
    let b = broker(&e, Duration::from_secs(2));
    let s = connect(&e, &b).await;

    let root = e.root.clone();
    let approver = tokio::spawn(async move { decide(&root, Verdict::Deny).await });
    let (is_error, out) = call(&s, update("denied")).await;
    approver.await.unwrap();
    assert!(is_error && out.as_str().unwrap().contains("denied"), "{out}");

    let (is_error, out) = call(&s, update("timed-out")).await;
    assert!(is_error && out.as_str().unwrap().contains("no human approved"), "{out}");
    assert!(write_store::list(&e.root).unwrap().is_empty(), "withdrawn");

    // An approval with another request's hash.
    let root = e.root.clone();
    let approver = tokio::spawn(async move {
        let id = wait_for_pending(&root).await;
        write_store::decide(
            &root,
            &Decision {
                id,
                request_hash: "0".repeat(64),
                verdict: Verdict::Approve,
                at: String::new(),
                tty: None,
            },
        )
        .unwrap();
    });
    let (is_error, out) = call(&s, update("mismatch")).await;
    approver.await.unwrap();
    assert!(is_error && out.as_str().unwrap().contains("doesn't match"), "{out}");

    assert_eq!(name_of(&e, 1).await.as_deref(), Some("one"));
    assert_eq!(outcomes(&e.root), [Outcome::Denied, Outcome::Timeout, Outcome::Denied]);
    s.client.cancel().await.unwrap();
    let _ = s.server.await;
}

/// M3 review B7: one outstanding request per target, even for concurrent calls.
#[tokio::test]
async fn concurrent_writes_to_one_target_get_one_request() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    allow(&e, &config(&e, true));
    let b = broker(&e, Duration::from_secs(3));
    let s = Arc::new(connect(&e, &b).await);
    let calls: Vec<_> = (0..5)
        .map(|i| {
            let s = s.clone();
            tokio::spawn(async move { call(&s, update(&format!("c{i}"))).await })
        })
        .collect();
    let mut refused = 0;
    let mut pending_seen = 0;
    for _ in 0..20 {
        pending_seen = pending_seen.max(write_store::list(&e.root).unwrap().len());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for c in calls {
        let (is_error, out) = c.await.unwrap();
        assert!(is_error, "{out}");
        if out.as_str().unwrap().contains("one at a time") {
            refused += 1;
        }
    }
    assert_eq!(pending_seen, 1);
    assert_eq!(refused, 4);
    assert_eq!(name_of(&e, 1).await.as_deref(), Some("one"));
}

#[tokio::test]
async fn writes_need_allow_write_and_a_writable_target() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    allow(&e, &config(&e, true));
    let b = broker(&e, Duration::from_secs(2));
    let s = connect(&e, &b).await;
    let mut args = update("x");
    args["allow_write"] = json!(false);
    let (is_error, out) = call(&s, args).await;
    assert!(is_error && out.as_str().unwrap().contains("allow_write"), "{out}");

    allow(&e, &config(&e, false));
    let (is_error, out) = call(&s, update("x")).await;
    assert!(is_error && out.as_str().unwrap().contains("isn't writable"), "{out}");
    assert!(write_store::list(&e.root).unwrap().is_empty());
    assert_eq!(outcomes(&e.root), [Outcome::Refused, Outcome::Refused]);
}

/// M3 review B2: rmcp doesn't drop the handler on cancel; the broker must notice and withdraw, and
/// a later approval must run nothing.
#[tokio::test]
async fn a_cancelled_call_withdraws_its_request() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    allow(&e, &config(&e, true));
    let b = broker(&e, Duration::from_secs(30));
    let s = connect(&e, &b).await;
    let handle = s
        .client
        .send_cancellable_request(
            ClientRequest::CallToolRequest(CallToolRequest::new(params(update("cancelled")))),
            PeerRequestOptions::default(),
        )
        .await
        .unwrap();
    let id = wait_for_pending(&e.root).await;
    let pending = write_store::load(&e.root, &id).unwrap().request.unwrap();
    handle.cancel(Some("test".into())).await.unwrap();
    for _ in 0..100 {
        if write_store::list(&e.root).unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(write_store::list(&e.root).unwrap().is_empty(), "withdrawn");
    // A late approval of the withdrawn request authorizes nothing.
    let _ = write_store::decide(
        &e.root,
        &Decision {
            id: id.clone(),
            request_hash: pending.hash(),
            verdict: Verdict::Approve,
            at: String::new(),
            tty: None,
        },
    );
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(name_of(&e, 1).await.as_deref(), Some("one"));
    assert_eq!(outcomes(&e.root), [Outcome::Cancelled]);
    s.client.cancel().await.unwrap();
    let _ = s.server.await;
}

/// M3 review B6: `allow` while a write waits (here: writable turned off) denies it.
#[tokio::test]
async fn a_policy_change_during_the_wait_denies() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    allow(&e, &config(&e, true));
    let b = broker(&e, Duration::from_secs(30));
    let s = connect(&e, &b).await;
    let root = e.root.clone();
    let text = config(&e, false);
    let project = e.project.clone();
    let port = e.port;
    let approver = tokio::spawn(async move {
        wait_for_pending(&root).await;
        // The human re-approves the config with writable = false, then approves the write.
        std::fs::write(project.join("valetkey.toml"), &text).unwrap();
        let p = project::discover(&project).unwrap();
        let cx = NormalizeCx {
            root: &root,
            platform: Platform::current(),
        };
        let parsed = Registry::default().with(PostgresKind).parse(&text, &cx).unwrap();
        snapshot::store(&root, &p, &Snapshot::new(&p, parsed)).unwrap();
        let _ = port;
        decide(&root, Verdict::Approve).await
    });
    let (is_error, out) = call(&s, update("after-allow")).await;
    approver.await.unwrap();
    assert!(
        is_error && out.as_str().unwrap().contains("changed while it waited"),
        "{out}"
    );
    assert_eq!(name_of(&e, 1).await.as_deref(), Some("one"));
    assert_eq!(outcomes(&e.root), [Outcome::Denied]);
}

/// M3 review B2-r1: the client goes away right after the approval; the write still ends with an
/// outcome record because `drain` waits for it.
#[tokio::test]
async fn shutdown_after_approval_still_records_the_outcome() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    allow(&e, &config(&e, true));
    let b = broker(&e, Duration::from_secs(30));
    let s = connect(&e, &b).await;
    let root = e.root.clone();
    let args = update("late");
    let client = s.client;
    let call_task = tokio::spawn(async move {
        let _ = client.call_tool(params(args)).await;
        client
    });
    decide(&root, Verdict::Approve).await;
    for _ in 0..100 {
        if outcomes(&e.root).contains(&Outcome::Approved) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    call_task.abort();
    let _ = s.server.await;
    b.drain().await;
    let o = outcomes(&e.root);
    assert_eq!(o.len(), 2, "{o:?}");
    assert_eq!(o[0], Outcome::Approved);
    assert!(matches!(o[1], Outcome::Ok | Outcome::Error), "{o:?}");
    let committed = name_of(&e, 1).await.as_deref() == Some("late");
    assert_eq!(committed, o[1] == Outcome::Ok);
}

#[tokio::test]
async fn shutdown_withdraws_a_waiting_request() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    allow(&e, &config(&e, true));
    let b = broker(&e, Duration::from_secs(30));
    let s = connect(&e, &b).await;
    let client = s.client;
    let call_task = tokio::spawn(async move { client.call_tool(params(update("never"))).await.map(|_| ()) });
    wait_for_pending(&e.root).await;
    b.drain().await;
    assert!(write_store::list(&e.root).unwrap().is_empty(), "withdrawn");
    assert_eq!(outcomes(&e.root), [Outcome::Cancelled]);
    let _ = call_task.await;
    let _ = s.server.await;
    assert_eq!(name_of(&e, 1).await.as_deref(), Some("one"));
}

#[tokio::test]
async fn reads_are_audited_too() {
    if !docker_available() {
        return;
    }
    let e = env().await;
    allow(&e, &config(&e, false));
    let b = broker(&e, Duration::from_secs(2));
    let s = connect(&e, &b).await;
    let r = s
        .client
        .call_tool(
            CallToolRequestParams::new("sql_query").with_arguments(
                json!({ "target": "local-app", "sql": "SELECT name FROM items WHERE id = $1", "params": [2] })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .unwrap();
    let (is_error, out) = decode(r);
    assert!(!is_error, "{out}");
    let big = "x".repeat(70 * 1024);
    let r = s
        .client
        .call_tool(
            CallToolRequestParams::new("sql_query").with_arguments(
                json!({ "target": "local-app", "sql": big })
                    .as_object()
                    .unwrap()
                    .clone(),
            ),
        )
        .await
        .unwrap();
    assert!(decode(r).0, "over the statement limit");
    let recs = records(&e.root);
    assert_eq!(recs.len(), 2);
    assert_eq!((recs[0].outcome, recs[0].rows), (Outcome::Ok, Some(1)));
    assert_eq!(
        recs[0].statement.as_deref(),
        Some("SELECT name FROM items WHERE id = $1")
    );
    assert_eq!(recs[1].outcome, Outcome::Refused);
}
