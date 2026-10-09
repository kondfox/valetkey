//! The write path against real Postgres (testcontainers): the M3 plan review's findings as
//! regression tests. Locally they skip when Docker is unavailable; in CI on Linux they fail
//! instead.

use std::time::Duration;

use secrecy::SecretString;
use serde_json::{Value, json};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use valetkey_postgres::guard::GuardViolation;
use valetkey_postgres::read::{Endpoint, Limits, ReadError, ReadRequest, read};
use valetkey_postgres::write::{Prepared, WriteResult, WriteTarget, execute_write, prepare_write};

const WRITER_PW: &str = "writer-pw";

/// Docker that can run Linux containers (Windows runners have Docker, but only Windows containers).
fn docker_available() -> bool {
    let ok = std::process::Command::new("docker")
        .args(["info", "--format", "{{.OSType}}"])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "linux");
    if !ok && std::env::var_os("CI").is_some() && cfg!(target_os = "linux") {
        panic!("Docker is required for the Postgres tests in CI on Linux");
    }
    ok
}

struct Pg {
    _container: ContainerAsync<Postgres>,
    port: u16,
}

const SETUP: &str = "
    CREATE ROLE vk_writer LOGIN PASSWORD 'writer-pw';
    CREATE TABLE items(id int PRIMARY KEY, name text);
    INSERT INTO items VALUES (1, 'one'), (2, 'two');
    CREATE TABLE calls(n int);
    CREATE TABLE dates(d date);
    CREATE FUNCTION write_fn(n int) RETURNS int LANGUAGE sql AS 'INSERT INTO calls VALUES (n) RETURNING n';
    CREATE PROCEDURE commit_proc() LANGUAGE plpgsql AS $$ BEGIN INSERT INTO calls VALUES (-1); COMMIT; END $$;
    GRANT ALL ON items, calls, dates TO vk_writer;
    GRANT EXECUTE ON FUNCTION write_fn(int) TO vk_writer;
";

async fn start(args: &[&str]) -> Pg {
    let mut image = Postgres::default().with_password("pw").with_tag("17");
    if !args.is_empty() {
        let mut cmd = vec!["postgres".to_owned()];
        cmd.extend(args.iter().map(|a| (*a).to_owned()));
        image = image.with_cmd(cmd);
    }
    let container = image
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .await
        .expect("postgres starts");
    let mut port = None;
    for _ in 0..20 {
        if let Ok(p) = container.get_host_port_ipv4(5432).await {
            port = Some(p);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let pg = Pg {
        _container: container,
        port: port.expect("a mapped port"),
    };
    admin(&pg, SETUP).await;
    pg
}

async fn admin_client(pg: &Pg) -> tokio_postgres::Client {
    let (client, conn) = tokio_postgres::connect(
        &format!(
            "host=127.0.0.1 port={} user=postgres password=pw dbname=postgres",
            pg.port
        ),
        tokio_postgres::NoTls,
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    client
}

async fn admin(pg: &Pg, sql: &str) {
    admin_client(pg).await.batch_execute(sql).await.unwrap();
}

async fn scalar(pg: &Pg, sql: &str) -> i64 {
    admin_client(pg).await.query_one(sql, &[]).await.unwrap().get(0)
}

fn target<'a>(pg: &Pg, password: &'a SecretString, limits: Limits) -> WriteTarget<'a> {
    WriteTarget {
        endpoint: Endpoint::Tcp {
            host: "127.0.0.1".into(),
            port: pg.port,
        },
        database: "postgres",
        user: "vk_writer",
        password,
        run_checks: false,
        allow_prepared_transactions: false,
        extra_extensions: &[],
        allow_grant_drift: false,
        limits,
    }
}

/// Prepares and executes in one go, the way the broker does after an approval.
async fn write(pg: &Pg, sql: &str, params: &[Value], limits: Limits) -> Result<WriteResult, ReadError> {
    let pw = SecretString::from(WRITER_PW);
    let t = target(pg, &pw, limits);
    let prepared = prepare_write(&t, sql, params).await?;
    execute_write(&t, sql, params, &prepared).await
}

async fn prepare(pg: &Pg, sql: &str, params: &[Value]) -> Result<Prepared, ReadError> {
    let pw = SecretString::from(WRITER_PW);
    prepare_write(&target(pg, &pw, Limits::default()), sql, params).await
}

async fn execute(pg: &Pg, sql: &str, params: &[Value], prepared: &Prepared) -> Result<WriteResult, ReadError> {
    let pw = SecretString::from(WRITER_PW);
    execute_write(&target(pg, &pw, Limits::default()), sql, params, prepared).await
}

#[tokio::test]
async fn a_write_commits_with_typed_params_and_rows_affected() {
    if !docker_available() {
        return;
    }
    let pg = start(&[]).await;
    let sql = "UPDATE items SET name = $1 WHERE id = $2";
    let prepared = prepare(&pg, sql, &[json!("uno"), json!(1)]).await.unwrap();
    let types: Vec<(&str, u32)> = prepared
        .params
        .iter()
        .map(|p| (p.type_name.as_str(), p.type_oid))
        .collect();
    assert_eq!(types, [("pg_catalog.text", 25), ("pg_catalog.int4", 23)]);
    assert_eq!(prepared.params[1].text.as_deref(), Some("1"));
    assert_eq!(prepared.identity["database"], "postgres");
    assert_eq!(prepared.identity["user"], "vk_writer");
    assert!(prepared.identity["endpoint"].starts_with("tcp 127.0.0.1:"));
    assert_eq!(
        scalar(&pg, "SELECT count(*) FROM items WHERE name = 'uno'").await,
        0,
        "prepare writes nothing"
    );

    let r = execute(&pg, sql, &[json!("uno"), json!(1)], &prepared).await.unwrap();
    assert_eq!(r.rows_affected, Some(1));
    assert_eq!(r.verified.user, "vk_writer");
    assert_eq!(scalar(&pg, "SELECT count(*) FROM items WHERE name = 'uno'").await, 1);
}

/// M3 review B3: a row-limited portal would stop a writing SELECT partway and commit that part.
#[tokio::test]
async fn statements_always_run_to_completion_whatever_the_result_limits() {
    if !docker_available() {
        return;
    }
    let pg = start(&[]).await;
    let limits = Limits {
        max_rows: 5,
        ..Limits::default()
    };
    let r = write(&pg, "SELECT write_fn(g) FROM generate_series(1, 15) g", &[], limits)
        .await
        .unwrap();
    assert_eq!(r.row_count, 5);
    assert!(r.truncated);
    assert_eq!(r.rows_affected, Some(15));
    assert_eq!(
        scalar(&pg, "SELECT count(*) FROM calls").await,
        15,
        "every call committed"
    );

    let r = write(
        &pg,
        "INSERT INTO items SELECT g, 'n' || g FROM generate_series(10, 60) g RETURNING id, name",
        &[],
        limits,
    )
    .await
    .unwrap();
    assert_eq!((r.row_count, r.rows_affected, r.truncated), (5, Some(51), true));
    assert_eq!(scalar(&pg, "SELECT count(*) FROM items").await, 53);

    let small_bytes = Limits {
        max_bytes: 40,
        ..Limits::default()
    };
    let r = write(
        &pg,
        "UPDATE items SET name = name || '!' RETURNING name",
        &[],
        small_bytes,
    )
    .await
    .unwrap();
    assert!(r.truncated && r.row_count < 53, "{r:?}");
    assert_eq!(r.rows_affected, Some(53));
    assert_eq!(scalar(&pg, "SELECT count(*) FROM items WHERE name LIKE '%!'").await, 53);
}

/// The one exception: a single result message over the guard's cap cuts the connection, so the
/// write rolls back.
#[tokio::test]
async fn a_huge_returning_value_rolls_back() {
    if !docker_available() {
        return;
    }
    let pg = start(&[]).await;
    let limits = Limits {
        max_bytes: 1024,
        ..Limits::default()
    };
    let e = write(
        &pg,
        "INSERT INTO items VALUES (100, repeat('x', 200000)) RETURNING name",
        &[],
        limits,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(e, ReadError::Guard(GuardViolation::MessageTooLarge { .. })),
        "{e:?}"
    );
    assert_eq!(scalar(&pg, "SELECT count(*) FROM items WHERE id = 100").await, 0);
}

/// M3 review B4: role-level settings can't change how the approved text or parameters parse.
#[tokio::test]
async fn role_level_settings_cant_change_parsing() {
    if !docker_available() {
        return;
    }
    let pg = start(&[]).await;
    admin(
        &pg,
        "ALTER ROLE vk_writer SET standard_conforming_strings = off;
         ALTER ROLE vk_writer SET DateStyle = 'SQL, DMY';
         ALTER ROLE vk_writer SET TimeZone = 'Asia/Tokyo';
         ALTER ROLE vk_writer SET IntervalStyle = 'sql_standard';",
    )
    .await;
    let r = write(
        &pg,
        r"INSERT INTO items VALUES (50, 'a\'), (51, $1) RETURNING name",
        &[json!(r"b\n")],
        Limits::default(),
    )
    .await
    .unwrap();
    assert_eq!(r.rows, [[json!(r"a\")], [json!(r"b\n")]], "backslashes are literal");
    let r = write(
        &pg,
        "INSERT INTO dates VALUES ($1) RETURNING d::text",
        &[json!("01/02/2026")],
        Limits::default(),
    )
    .await
    .unwrap();
    assert_eq!(r.rows, [[json!("2026-01-02")]], "month first, ISO output");
    let p = prepare(&pg, "UPDATE items SET name = $1", &[json!("x")]).await.unwrap();
    assert_eq!(p.identity["setting TimeZone"], "UTC");
    assert_eq!(p.identity["setting standard_conforming_strings"], "on");

    // Reads get the same pinning.
    let pw = SecretString::from(WRITER_PW);
    let read_result = read(ReadRequest {
        endpoint: Endpoint::Tcp {
            host: "127.0.0.1".into(),
            port: pg.port,
        },
        database: "postgres",
        user: "vk_writer",
        password: &pw,
        run_checks: false,
        allow_prepared_transactions: false,
        extra_extensions: &[],
        allow_grant_drift: false,
        sql: r"SELECT 'c\'::text, $1::date::text",
        params: &[json!("03/04/2026")],
        limits: Limits::default(),
    })
    .await
    .unwrap();
    assert_eq!(read_result.rows, [[json!(r"c\"), json!("2026-03-04")]]);
}

/// M3 review B4/§6.10: anything that decides what runs or where must be the same after
/// reconnecting as when the human approved it.
#[tokio::test]
async fn changes_between_approval_and_execution_deny() {
    if !docker_available() {
        return;
    }
    let pg = start(&[]).await;
    let sql = "UPDATE items SET name = $1 WHERE id = 1";
    let prepared = prepare(&pg, sql, &[json!("x")]).await.unwrap();
    admin(&pg, "ALTER ROLE vk_writer SET search_path = pg_temp, public").await;
    let e = execute(&pg, sql, &[json!("x")], &prepared).await.unwrap_err();
    // The search path and the schemas it resolves to both changed; either names it.
    assert!(
        matches!(&e, ReadError::Changed(w) if w.contains("search_path") || w.contains("schemas")),
        "{e:?}"
    );
    admin(&pg, "ALTER ROLE vk_writer RESET search_path").await;

    let sql = "UPDATE items SET id = $1 WHERE id = 2";
    let prepared = prepare(&pg, sql, &[json!("7")]).await.unwrap();
    admin(&pg, "ALTER TABLE items ALTER COLUMN id TYPE bigint").await;
    let e = execute(&pg, sql, &[json!("7")], &prepared).await.unwrap_err();
    assert!(
        matches!(&e, ReadError::Changed(w) if w.contains("parameter types")),
        "{e:?}"
    );

    let e = execute(&pg, sql, &[json!("8")], &prepared).await.unwrap_err();
    assert!(matches!(e, ReadError::Changed(_)), "different values never pass: {e:?}");
    assert_eq!(scalar(&pg, "SELECT count(*) FROM items WHERE id IN (7, 8)").await, 0);
}

/// M3 review N1: what transaction control inside the statement really does.
#[tokio::test]
async fn transaction_control_in_the_statement() {
    if !docker_available() {
        return;
    }
    let pg = start(&[]).await;
    let l = Limits::default;
    // Ending the broker's transaction early is allowed and harmless: nothing follows it but the
    // broker's own COMMIT.
    for stmt in ["COMMIT", "ROLLBACK", "COMMIT AND CHAIN"] {
        write(&pg, stmt, &[], l())
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e:?}"));
    }
    // Committing from inside a DO block or a procedure fails inside a transaction block.
    for stmt in [
        "DO $$ BEGIN INSERT INTO calls VALUES (-2); COMMIT; END $$",
        "CALL commit_proc()",
    ] {
        let e = write(&pg, stmt, &[], l()).await.unwrap_err();
        assert!(matches!(e, ReadError::Server(_)), "{stmt}: {e:?}");
    }
    assert_eq!(scalar(&pg, "SELECT count(*) FROM calls").await, 0, "nothing committed");
    // COPY over the client protocol and statements that need no transaction block fail cleanly.
    for stmt in [
        "COPY items FROM STDIN",
        "COPY items TO STDOUT",
        "VACUUM items",
        "CREATE INDEX CONCURRENTLY i ON items(name)",
        "PREPARE TRANSACTION 'x'",
    ] {
        let r = tokio::time::timeout(Duration::from_secs(20), write(&pg, stmt, &[], l())).await;
        let e = r.unwrap_or_else(|_| panic!("{stmt} hung")).unwrap_err();
        let _ = e;
    }
    assert_eq!(scalar(&pg, "SELECT count(*) FROM pg_prepared_xacts").await, 0);
    // Multiple statements are still impossible.
    let e = write(&pg, "UPDATE items SET name = 'a'; DELETE FROM items", &[], l())
        .await
        .unwrap_err();
    assert!(matches!(e, ReadError::Server(_)), "{e:?}");
    assert_eq!(scalar(&pg, "SELECT count(*) FROM items").await, 2);
}

#[tokio::test]
async fn servers_allowing_prepared_transactions_are_refused_for_writes() {
    if !docker_available() {
        return;
    }
    let pg = start(&["-c", "max_prepared_transactions=5"]).await;
    let e = prepare(&pg, "UPDATE items SET name = 'x'", &[]).await.unwrap_err();
    assert!(matches!(e, ReadError::Refused(m) if m.contains("prepared transactions")));
}

#[tokio::test]
async fn syntax_errors_and_parameter_counts_fail_before_approval() {
    if !docker_available() {
        return;
    }
    let pg = start(&[]).await;
    assert!(matches!(
        prepare(&pg, "UPDAT items", &[]).await.unwrap_err(),
        ReadError::Server(_)
    ));
    assert!(matches!(
        prepare(&pg, "UPDATE items SET name = $1", &[]).await.unwrap_err(),
        ReadError::ParamCount { expected: 1, got: 0 }
    ));
}
