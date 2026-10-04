//! The read path against real Postgres (testcontainers). These are the M0 escapes and the M2
//! review findings as regression tests. Locally they skip when Docker is unavailable; in CI on
//! Linux they fail instead.

use std::time::Duration;

use secrecy::SecretString;
use serde_json::{Value, json};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt};
use testcontainers_modules::postgres::Postgres;
use valetkey_postgres::guard::GuardViolation;
use valetkey_postgres::read::{Endpoint, Limits, ReadError, ReadRequest, ReadResult, read};

const READER_PW: &str = "reader-pw";

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

async fn start(tag: &str, args: &[&str], host_auth: Option<&str>) -> Pg {
    let mut image = Postgres::default().with_password("pw").with_tag(tag);
    if !args.is_empty() {
        let mut cmd = vec!["postgres".to_owned()];
        cmd.extend(args.iter().map(|a| (*a).to_owned()));
        image = image.with_cmd(cmd);
    }
    if let Some(method) = host_auth {
        image = image.with_env_var("POSTGRES_HOST_AUTH_METHOD", method);
    }
    let container = image
        .with_startup_timeout(Duration::from_secs(120))
        .start()
        .await
        .expect("postgres starts");
    let port = mapped_port(&container).await;
    let pg = Pg {
        _container: container,
        port,
    };
    admin(&pg, SETUP).await;
    pg
}

const SETUP: &str = "
    CREATE ROLE vk_reader LOGIN PASSWORD 'reader-pw';
    CREATE TABLE items(id int PRIMARY KEY, name text);
    INSERT INTO items VALUES (1, 'one'), (2, 'two');
    GRANT SELECT ON items TO vk_reader;
";

async fn admin(pg: &Pg, sql: &str) {
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
    client.batch_execute(sql).await.unwrap();
}

async fn count_items(pg: &Pg) -> i64 {
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
        .query_one("SELECT count(*) FROM items", &[])
        .await
        .unwrap()
        .get(0)
}

async fn run_with(
    pg: &Pg,
    sql: &str,
    params: &[Value],
    protected: bool,
    limits: Limits,
    extra: &[String],
    drift: bool,
) -> Result<ReadResult, ReadError> {
    let password = SecretString::from(READER_PW);
    read(ReadRequest {
        endpoint: Endpoint::Tcp {
            host: "127.0.0.1".into(),
            port: pg.port,
        },
        database: "postgres",
        user: "vk_reader",
        password: &password,
        protected,
        extra_extensions: extra,
        allow_grant_drift: drift,
        sql,
        params,
        limits,
    })
    .await
}

async fn q(pg: &Pg, sql: &str) -> Result<ReadResult, ReadError> {
    run_with(pg, sql, &[], false, Limits::default(), &[], false).await
}

async fn protected(pg: &Pg) -> Result<ReadResult, ReadError> {
    run_with(pg, "SELECT 1", &[], true, Limits::default(), &[], false).await
}

#[tokio::test]
async fn reads_rows_and_every_mapped_type() {
    if !docker_available() {
        return;
    }
    let pg = start("17", &[], None).await;
    let r = q(&pg, "SELECT id, name FROM items ORDER BY id").await.unwrap();
    assert_eq!(r.verified.database, "postgres");
    assert_eq!(r.verified.user, "vk_reader");
    assert_eq!(
        r.columns.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ["id", "name"]
    );
    assert_eq!(r.rows, vec![vec![json!(1), json!("one")], vec![json!(2), json!("two")]]);
    assert!(!r.truncated);

    let r = q(
        &pg,
        "SELECT 9007199254740993::int8, 12345.6789::numeric, 'NaN'::numeric, 'NaN'::float8, '-Infinity'::float4,
                'infinity'::timestamp, '2024-02-29 12:34:56.789+00'::timestamptz, '2024-02-29'::date,
                '{\"a\":[1,2]}'::jsonb, ARRAY[[1,NULL],[3,4]], '\\x6869'::bytea, true,
                'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'::uuid, '127.0.0.1'::inet",
    )
    .await
    .unwrap();
    assert_eq!(
        r.rows[0],
        vec![
            json!("9007199254740993"),
            json!("12345.6789"),
            json!("NaN"),
            json!("NaN"),
            json!("-Infinity"),
            json!("infinity"),
            json!("2024-02-29T12:34:56.789Z"),
            json!("2024-02-29"),
            json!({"a": [1, 2]}),
            json!([[1, null], [3, 4]]),
            json!("aGk="),
            json!(true),
            json!("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
            r.rows[0][13].clone(),
        ]
    );
    assert_eq!(r.rows[0][13]["type"], "inet");
}

#[tokio::test]
async fn parameters_are_data_never_sql() {
    if !docker_available() {
        return;
    }
    let pg = start("17", &[], None).await;
    let evil = json!("1; DELETE FROM items; --");
    let r = run_with(
        &pg,
        "SELECT name FROM items WHERE name = $1 OR id = $2",
        &[evil, json!(2)],
        false,
        Limits::default(),
        &[],
        false,
    )
    .await
    .unwrap();
    assert_eq!(r.rows, vec![vec![json!("two")]]);
    let mismatch = run_with(&pg, "SELECT $1::int", &[], false, Limits::default(), &[], false)
        .await
        .unwrap_err();
    assert!(
        matches!(mismatch, ReadError::ParamCount { expected: 1, got: 0 }),
        "{mismatch:?}"
    );
    let nul = run_with(
        &pg,
        "SELECT $1::text",
        &[json!("a\u{0}b")],
        false,
        Limits::default(),
        &[],
        false,
    )
    .await
    .unwrap_err();
    assert!(matches!(nul, ReadError::Param(_)), "{nul:?}");
    assert_eq!(count_items(&pg).await, 2);
}

#[tokio::test]
async fn read_only_escapes_are_blocked() {
    if !docker_available() {
        return;
    }
    let pg = start("17", &[], None).await;
    for sql in [
        "INSERT INTO items VALUES (3, 'x')",
        "COMMIT; DELETE FROM items",
        "SET TRANSACTION READ WRITE",
        "DO $$ BEGIN DELETE FROM items; END $$",
        "DO $$ BEGIN COMMIT; END $$",
        "LOCK TABLE items IN ACCESS EXCLUSIVE MODE",
        "SELECT nextval('pg_catalog.pg_class_oid_index')",
    ] {
        let e = q(&pg, sql).await.unwrap_err();
        assert!(matches!(e, ReadError::Server(_)), "{sql}: {e:?}");
    }
    assert_eq!(count_items(&pg).await, 2, "nothing was written");
}

#[tokio::test]
async fn rows_bytes_and_time_are_bounded() {
    if !docker_available() {
        return;
    }
    let pg = start("17", &[], None).await;
    let limits = Limits {
        max_rows: 100,
        ..Limits::default()
    };
    let r = run_with(
        &pg,
        "SELECT g FROM generate_series(1, 10000000) g",
        &[],
        false,
        limits,
        &[],
        false,
    )
    .await
    .unwrap();
    assert_eq!(r.row_count, 100);
    assert!(r.truncated);

    let limits = Limits {
        max_bytes: 300_000,
        ..Limits::default()
    };
    let r = run_with(
        &pg,
        "SELECT repeat('x', 100000) FROM generate_series(1, 50)",
        &[],
        false,
        limits,
        &[],
        false,
    )
    .await
    .unwrap();
    assert!(r.truncated && r.row_count < 5, "{} rows", r.row_count);

    // One 50 MB value: refused from its message header, never buffered.
    let limits = Limits {
        max_bytes: 1_000_000,
        ..Limits::default()
    };
    let e = run_with(&pg, "SELECT repeat('x', 50000000)", &[], false, limits, &[], false)
        .await
        .unwrap_err();
    assert!(
        matches!(e, ReadError::Guard(GuardViolation::MessageTooLarge { .. })),
        "{e:?}"
    );

    let limits = Limits {
        statement_timeout: Duration::from_millis(500),
        ..Limits::default()
    };
    let e = run_with(&pg, "SELECT pg_sleep(5)", &[], false, limits, &[], false)
        .await
        .unwrap_err();
    assert!(
        matches!(e, ReadError::Server(ref m) if m.contains("statement timeout")),
        "{e:?}"
    );
}

#[tokio::test]
async fn a_hostile_search_path_cant_fake_the_identity() {
    if !docker_available() {
        return;
    }
    let pg = start("17", &[], None).await;
    admin(
        &pg,
        "CREATE SCHEMA evil;
         CREATE FUNCTION evil.current_database() RETURNS name LANGUAGE sql AS $$ SELECT 'other'::name $$;
         CREATE FUNCTION evil.current_setting(text) RETURNS text LANGUAGE sql AS $$ SELECT 'on' $$;
         GRANT USAGE ON SCHEMA evil TO vk_reader;
         ALTER ROLE vk_reader SET search_path = evil, pg_catalog, public;",
    )
    .await;
    let r = q(&pg, "SELECT current_database()").await.unwrap();
    assert_eq!(
        r.verified.database, "postgres",
        "the broker's identity query isn't shadowed"
    );
    assert_eq!(
        r.rows[0][0],
        json!("other"),
        "the agent's own query sees its search_path"
    );
}

#[tokio::test]
async fn servers_allowing_prepared_transactions_are_refused() {
    if !docker_available() {
        return;
    }
    let pg = start("17", &["-c", "max_prepared_transactions=5"], None).await;
    let e = q(&pg, "PREPARE TRANSACTION 'x'").await.unwrap_err();
    assert!(
        matches!(e, ReadError::Refused(ref m) if m.contains("max_prepared_transactions")),
        "{e:?}"
    );
}

#[tokio::test]
async fn only_scram_authentication_is_accepted() {
    if !docker_available() {
        return;
    }
    let cleartext = start("17", &[], Some("password")).await;
    let e = q(&cleartext, "SELECT 1").await.unwrap_err();
    assert!(matches!(e, ReadError::Guard(GuardViolation::AuthMethod(3))), "{e:?}");

    let md5 = start("17", &["-c", "password_encryption=md5"], Some("md5")).await;
    let e = q(&md5, "SELECT 1").await.unwrap_err();
    assert!(matches!(e, ReadError::Guard(GuardViolation::AuthMethod(5))), "{e:?}");

    let scram = start("17", &[], None).await;
    let wrong = {
        let password = SecretString::from("wrong");
        read(ReadRequest {
            endpoint: Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: scram.port,
            },
            database: "postgres",
            user: "vk_reader",
            password: &password,
            protected: false,
            extra_extensions: &[],
            allow_grant_drift: false,
            sql: "SELECT 1",
            params: &[],
            limits: Limits::default(),
        })
        .await
        .unwrap_err()
    };
    assert!(wrong.is_auth_failure(), "{wrong:?}");
}

/// Blocker B1: every role the login role can become is checked (PG15: membership; PG16+: SET).
#[tokio::test]
async fn protected_checks_cover_the_whole_role_closure() {
    if !docker_available() {
        return;
    }
    for tag in ["15", "16", "17"] {
        let pg = start(tag, &[], None).await;
        protected(&pg)
            .await
            .unwrap_or_else(|e| panic!("PG{tag}: a clean role passes: {e:?}"));

        admin(&pg, "CREATE ROLE file_readers NOLOGIN; GRANT pg_read_server_files TO file_readers; ALTER ROLE vk_reader NOINHERIT; GRANT file_readers TO vk_reader;").await;
        let e = protected(&pg).await.unwrap_err();
        assert!(
            matches!(e, ReadError::Refused(ref m) if m.contains("pg_read_server_files")),
            "PG{tag}: {e:?}"
        );

        admin(
            &pg,
            "REVOKE file_readers FROM vk_reader; CREATE ROLE boss SUPERUSER NOLOGIN; GRANT boss TO vk_reader;",
        )
        .await;
        let e = protected(&pg).await.unwrap_err();
        assert!(
            matches!(e, ReadError::Refused(ref m) if m.contains("superuser")),
            "PG{tag}: {e:?}"
        );
    }
}

#[tokio::test]
async fn protected_checks_find_extensions_functions_and_grant_drift() {
    if !docker_available() {
        return;
    }
    let pg = start("17", &[], None).await;

    admin(&pg, "CREATE EXTENSION dblink;").await;
    let e = protected(&pg).await.unwrap_err();
    assert!(matches!(e, ReadError::Refused(ref m) if m.contains("dblink")), "{e:?}");
    run_with(&pg, "SELECT 1", &[], true, Limits::default(), &["dblink".into()], false)
        .await
        .expect("explicitly allowed");
    admin(&pg, "DROP EXTENSION dblink;").await;

    admin(
        &pg,
        "CREATE FUNCTION run_as_owner() RETURNS int LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN 1; END $$;",
    )
    .await;
    let e = protected(&pg).await.unwrap_err();
    assert!(
        matches!(e, ReadError::Refused(ref m) if m.contains("run_as_owner")),
        "{e:?}"
    );
    admin(&pg, "DROP FUNCTION run_as_owner();").await;

    admin(&pg, "GRANT EXECUTE ON FUNCTION pg_read_file(text) TO vk_reader;").await;
    let e = protected(&pg).await.unwrap_err();
    assert!(
        matches!(e, ReadError::Refused(ref m) if m.contains("pg_read_file")),
        "{e:?}"
    );
    run_with(&pg, "SELECT 1", &[], true, Limits::default(), &[], true)
        .await
        .expect("allow_grant_drift skips query C");
}

/// The mapped port, retried briefly: right after start, Docker sometimes doesn't report the
/// mapping yet (`PortNotExposed`), especially with many containers starting at once.
async fn mapped_port<I: testcontainers::Image>(c: &ContainerAsync<I>) -> u16 {
    for attempt in 0.. {
        match c.get_host_port_ipv4(5432).await {
            Ok(port) => return port,
            Err(e) if attempt < 20 => {
                let _ = e;
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            Err(e) => panic!("no mapped port: {e}"),
        }
    }
    unreachable!()
}
