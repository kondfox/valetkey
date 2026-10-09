//! The read path (§6.9): one connection per call, every guard in order.
//!
//! 1. connect through the [`Guarded`] stream (auth allowlist, message-size cap), with startup
//!    options that make every transaction read-only and time-limited
//! 2. `START TRANSACTION READ ONLY`
//! 3. the identity query (schema-qualified, so a hostile `search_path` can't fake it). It must
//!    match the approved database and user, and it takes the snapshot that locks the transaction
//!    read-only (M0: otherwise `SET TRANSACTION READ WRITE` as the first statement escapes)
//! 4. a refusal when the server allows prepared transactions (they'd outlive the connection),
//!    and, for protected targets, the role-closure and catalog checks ([`crate::checks`])
//! 5. the user's statement through the extended protocol (one statement only), executed as a
//!    portal limited to `max_rows + 1` rows
//! 6. `ROLLBACK`, or, when anything went wrong or the byte limit tripped, dropping the
//!    connection (the server rolls back on disconnect)
//!
//! The whole call has a wall-clock timeout on top of `statement_timeout`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, NoTls, Transaction};

use valetkey_core::sanitize::for_display;

use crate::checks;
use crate::guard::{GuardViolation, Guarded};
use crate::values::{AnyValue, TextParam};

/// Where to connect.
#[derive(Debug, Clone)]
pub enum Endpoint {
    /// A unix socket file (`…/.s.PGSQL.5432`).
    Socket(PathBuf),
    /// Plain TCP: only for exposed secrets (enforced when the config is loaded).
    Tcp { host: String, port: u16 },
}

/// Bounds for one call.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_rows: u32,
    pub max_bytes: usize,
    pub statement_timeout: Duration,
    /// Connect + checks + statement + fetch. For writes, everything before `COMMIT`.
    pub call_timeout: Duration,
    pub connect_timeout: Duration,
    /// Writes: how long to wait for the answer to `COMMIT`. Past it the outcome is unknown.
    pub commit_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: 1000,
            max_bytes: 1024 * 1024,
            statement_timeout: Duration::from_secs(30),
            call_timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
            // Above `statement_timeout`, which also bounds `COMMIT` (deferred triggers).
            commit_timeout: Duration::from_secs(40),
        }
    }
}

/// Everything one read needs.
#[derive(Debug)]
pub struct ReadRequest<'a> {
    pub endpoint: Endpoint,
    pub database: &'a str,
    pub user: &'a str,
    pub password: &'a SecretString,
    /// Run the role-closure and catalog checks: for protected targets, and for targets the agent
    /// can only reach through valetkey (sockets).
    pub run_checks: bool,
    /// Whether this target may use a server that allows prepared transactions. Only exposed
    /// targets can set it (validated at config load); a HIGH change in `allow`.
    pub allow_prepared_transactions: bool,
    /// Extensions allowed beyond [`checks::DEFAULT_EXTENSIONS`].
    pub extra_extensions: &'a [String],
    /// Skip catalog query C (re-granted built-ins), for hardened databases. A HIGH change in `allow`.
    pub allow_grant_drift: bool,
    pub sql: &'a str,
    pub params: &'a [Value],
    pub limits: Limits,
}

/// One result column.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Column {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
}

/// What the agent gets back.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReadResult {
    /// The identity the server confirmed for this connection.
    pub verified: Verified,
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Value>>,
    pub row_count: usize,
    pub truncated: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Verified {
    pub database: String,
    pub user: String,
}

/// Why a read failed. `Display` is safe to show the agent: server errors are about the agent's
/// own statement; everything else is fixed text. [`ReadError::detail`] is for the log.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error("can't connect to the database (see the valetkey log)")]
    Connect(String),
    #[error("the connection was refused by valetkey: {0}")]
    Guard(GuardViolation),
    #[error("the database rejected the stored password; ask a human to check the secret")]
    AuthFailed(String),
    #[error(
        "refused: connected as {got_user} to {got_database}, but the approved target is {want_user} on {want_database}"
    )]
    Identity {
        got_database: String,
        got_user: String,
        want_database: String,
        want_user: String,
    },
    #[error("refused: {0}")]
    Refused(String),
    #[error("the statement expects {expected} parameters, got {got}")]
    ParamCount { expected: usize, got: usize },
    #[error("invalid parameter: {0}")]
    Param(String),
    #[error("{0}")]
    Server(String),
    #[error("the call took longer than {0:?} and was stopped")]
    Timeout(Duration),
    #[error("database error (see the valetkey log)")]
    Other(String),
    #[error("refused: {0} changed since the request was approved; nothing was written")]
    Changed(String),
    #[error("the outcome is unknown: the connection was lost during COMMIT; check the data before retrying")]
    CommitUnknown(String),
}

impl ReadError {
    /// Detail for the broker's log.
    pub fn detail(&self) -> String {
        match self {
            Self::Connect(d) | Self::AuthFailed(d) | Self::Other(d) | Self::CommitUnknown(d) => d.clone(),
            other => other.to_string(),
        }
    }

    /// Whether the stored secret was rejected (the broker drops it from its cache).
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Self::AuthFailed(_))
    }
}

/// Runs one read. See the module docs for the order of guards.
pub async fn read(req: ReadRequest<'_>) -> Result<ReadResult, ReadError> {
    let timeout = req.limits.call_timeout;
    tokio::time::timeout(timeout, read_inner(req))
        .await
        .unwrap_or(Err(ReadError::Timeout(timeout)))
}

async fn read_inner(req: ReadRequest<'_>) -> Result<ReadResult, ReadError> {
    let started = Instant::now();
    let report = Arc::new(OnceLock::new());
    let spec = ConnectSpec {
        endpoint: &req.endpoint,
        database: req.database,
        user: req.user,
        password: req.password,
        limits: req.limits,
        read_only: true,
    };
    let (mut client, connection) = connect(&spec, report.clone()).await?;
    // The connection task ends (and the server rolls back) when `client` and this handle drop.
    let connection = AbortOnDrop(tokio::spawn(connection));

    let result = run(&mut client, &req, &report).await;
    // Dropping the client and the connection ends the session; if `run` didn't roll back (an
    // error, or the byte limit), the server rolls back on disconnect.
    drop(client);
    drop(connection);
    result.map(|mut out| {
        out.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        out
    })
}

pub(crate) struct AbortOnDrop(pub(crate) tokio::task::JoinHandle<Result<(), tokio_postgres::Error>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) type Connection = tokio_postgres::Connection<Guarded<Box<dyn Stream>>, tokio_postgres::tls::NoTlsStream>;

pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// What a connection needs.
pub(crate) struct ConnectSpec<'a> {
    pub endpoint: &'a Endpoint,
    pub database: &'a str,
    pub user: &'a str,
    pub password: &'a SecretString,
    pub limits: Limits,
    /// Adds `default_transaction_read_only=on` to the startup options.
    pub read_only: bool,
}

/// Settings pinned at startup on every connection, because they change how the statement text
/// and text-format parameters are parsed (M3 review B4). Startup options override role- and
/// database-level defaults; [`identify`] reads them back and refuses if they didn't take.
const PINNED_SETTINGS: [(&str, &str, &str); 4] = [
    // (name in options, value sent, value read back)
    ("standard_conforming_strings", "on", "on"),
    ("DateStyle", "ISO,MDY", "ISO, MDY"),
    ("IntervalStyle", "postgres", "postgres"),
    ("TimeZone", "UTC", "UTC"),
];

pub(crate) async fn connect(
    spec: &ConnectSpec<'_>,
    report: Arc<OnceLock<GuardViolation>>,
) -> Result<(Client, Connection), ReadError> {
    let stream: Box<dyn Stream> = match spec.endpoint {
        #[cfg(unix)]
        Endpoint::Socket(path) => Box::new(
            tokio::net::UnixStream::connect(path)
                .await
                .map_err(|e| ReadError::Connect(format!("{}: {e}", path.display())))?,
        ),
        #[cfg(not(unix))]
        Endpoint::Socket(path) => {
            return Err(ReadError::Connect(format!(
                "{}: unix sockets need unix",
                path.display()
            )));
        }
        Endpoint::Tcp { host, port } => Box::new(
            tokio::net::TcpStream::connect((host.as_str(), *port))
                .await
                .map_err(|e| ReadError::Connect(format!("{host}:{port}: {e}")))?,
        ),
    };
    // Room for one row up to the byte limit plus protocol overhead.
    let max_message = u32::try_from(spec.limits.max_bytes.saturating_add(64 * 1024)).unwrap_or(u32::MAX);
    let guarded = Guarded::new(stream, max_message).reporting_to(report.clone());

    let statement_ms = spec.limits.statement_timeout.as_millis();
    let mut options = format!(
        "-c statement_timeout={statement_ms} -c lock_timeout=5000 -c idle_in_transaction_session_timeout={}",
        statement_ms + 5000
    );
    for (name, value, _) in PINNED_SETTINGS {
        options.push_str(&format!(" -c {name}={value}"));
    }
    if spec.read_only {
        options.push_str(" -c default_transaction_read_only=on");
    }
    // The driver keeps its own copy of the password; drop the config right after connecting.
    let connected = {
        let mut config = tokio_postgres::Config::new();
        config
            .user(spec.user)
            .dbname(spec.database)
            .password(spec.password.expose_secret())
            .options(options)
            .application_name("valetkey");
        tokio::time::timeout(spec.limits.connect_timeout, config.connect_raw(guarded, NoTls)).await
    };
    match connected {
        Ok(Ok(pair)) => Ok(pair),
        Ok(Err(e)) => Err(classify_connect_error(e, &report)),
        Err(_) => Err(ReadError::Connect(format!(
            "connect timed out after {:?}",
            spec.limits.connect_timeout
        ))),
    }
}

fn classify_connect_error(e: tokio_postgres::Error, report: &OnceLock<GuardViolation>) -> ReadError {
    if let Some(v) = report.get() {
        return ReadError::Guard(v.clone());
    }
    if let Some(db) = e.as_db_error() {
        let code = db.code().code();
        // 28P01 invalid_password, 28000 invalid_authorization_specification
        if code == "28P01" || code == "28000" {
            return ReadError::AuthFailed(db.message().to_owned());
        }
        return ReadError::Connect(format!("{code}: {}", db.message()));
    }
    ReadError::Connect(e.to_string())
}

async fn run(
    client: &mut Client,
    req: &ReadRequest<'_>,
    report: &OnceLock<GuardViolation>,
) -> Result<ReadResult, ReadError> {
    let err = |e: tokio_postgres::Error| query_error(e, report);
    let txn = client.build_transaction().read_only(true).start().await.map_err(err)?;

    let id = identify(&txn, &req.endpoint).await.map_err(err)?;
    id.check(req.database, req.user, true)?;
    let (database, user, max_prepared) = (id.database.clone(), id.user.clone(), id.max_prepared);

    // M2 finding: `PREPARE TRANSACTION` works inside a read-only transaction, and the prepared
    // transaction (with its locks) outlives the connection.
    if max_prepared > 0 && !req.allow_prepared_transactions {
        return Err(ReadError::Refused(format!(
            "the server allows prepared transactions (max_prepared_transactions = {max_prepared}), which let a read-only statement leave a transaction and its locks behind; set it to 0, or (exposed targets only) set allow_prepared_transactions = true"
        )));
    }

    if req.run_checks {
        checks::run(&txn, req.extra_extensions, req.allow_grant_drift)
            .await
            .map_err(|e| match e {
                checks::CheckError::Refused(why) => ReadError::Refused(for_display(&why)),
                checks::CheckError::Query(e) => err(e),
            })?;
    }

    let statement = txn.prepare(req.sql).await.map_err(err)?;
    if statement.params().len() != req.params.len() {
        return Err(ReadError::ParamCount {
            expected: statement.params().len(),
            got: req.params.len(),
        });
    }
    let params: Vec<TextParam> = req
        .params
        .iter()
        .map(TextParam::from_json)
        .collect::<Result<_, _>>()
        .map_err(ReadError::Param)?;
    let refs: Vec<&(dyn ToSql + Sync)> = params.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
    let portal = txn.bind(&statement, &refs).await.map_err(err)?;

    let columns: Vec<Column> = statement
        .columns()
        .iter()
        .map(|c| Column {
            name: c.name().to_owned(),
            type_name: c.type_().name().to_owned(),
        })
        .collect();
    let fetch_limit = i32::try_from(req.limits.max_rows.saturating_add(1)).unwrap_or(i32::MAX);
    let stream = txn.query_portal_raw(&portal, fetch_limit).await.map_err(err)?;
    // Boxed (not stack-pinned) so `drop(stream)` below really drops it before the rollback.
    let mut stream = Box::pin(stream);

    let mut rows = Vec::new();
    let mut bytes = 0usize;
    let mut truncated = false;
    let mut clean = true;
    use futures_util::StreamExt;
    while let Some(row) = stream.next().await {
        let row = row.map_err(err)?;
        if rows.len() as u32 >= req.limits.max_rows {
            truncated = true;
            break;
        }
        let values: Vec<Value> = (0..row.len())
            .map(|i| row.try_get::<_, AnyValue>(i).map(|v| v.0))
            .collect::<Result<_, _>>()
            .map_err(err)?;
        // Approximate: the JSON size of the values, counted without building the strings.
        bytes += values.iter().map(json_len).sum::<usize>();
        if bytes > req.limits.max_bytes {
            truncated = true;
            // Don't drain the rest: drop the connection instead.
            clean = false;
            break;
        }
        rows.push(values);
    }
    drop(stream);
    if clean {
        txn.rollback().await.map_err(err)?;
    } else {
        // Leave the transaction open: the caller drops the connection without draining the rest.
        std::mem::forget(txn);
    }
    let row_count = rows.len();
    Ok(ReadResult {
        verified: Verified { database, user },
        columns,
        rows,
        row_count,
        truncated,
        duration_ms: 0,
    })
}

/// What the server says about itself and the session, from inside the transaction.
#[derive(Debug, Clone)]
pub(crate) struct Identity {
    pub database: String,
    pub user: String,
    pub read_only: String,
    pub max_prepared: i32,
    /// Everything shown in a write request and compared after reconnecting.
    pub details: BTreeMap<String, String>,
    pinned: Vec<(&'static str, String)>,
}

impl Identity {
    /// The approved database and user, the expected read-only state, and the pinned settings.
    pub fn check(&self, database: &str, user: &str, read_only: bool) -> Result<(), ReadError> {
        let want_ro = if read_only { "on" } else { "off" };
        if self.database != database || self.user != user || self.read_only != want_ro {
            return Err(ReadError::Identity {
                got_database: self.database.clone(),
                got_user: self.user.clone(),
                want_database: database.to_owned(),
                want_user: user.to_owned(),
            });
        }
        for ((name, _, want), (_, got)) in PINNED_SETTINGS.iter().zip(&self.pinned) {
            if got != want {
                return Err(ReadError::Refused(format!(
                    "the session setting {name} is {} instead of {want}; valetkey pins it so statements and parameters parse as shown",
                    for_display(got)
                )));
            }
        }
        Ok(())
    }
}

/// The broker's identity query (schema-qualified, so a hostile `search_path` can't fake it). Run
/// first inside the transaction: it takes the snapshot that locks a read-only transaction.
pub(crate) async fn identify(txn: &Transaction<'_>, endpoint: &Endpoint) -> Result<Identity, tokio_postgres::Error> {
    let row = txn
        .query_one(
            "SELECT pg_catalog.current_database()::text, current_user::text,
                    pg_catalog.current_setting('transaction_read_only'),
                    pg_catalog.current_setting('max_prepared_transactions')::int,
                    pg_catalog.current_setting('search_path'),
                    pg_catalog.current_schemas(true)::text,
                    pg_catalog.inet_server_addr()::text,
                    pg_catalog.inet_server_port(),
                    pg_catalog.current_setting('server_version'),
                    pg_catalog.current_setting('standard_conforming_strings'),
                    pg_catalog.current_setting('DateStyle'),
                    pg_catalog.current_setting('IntervalStyle'),
                    pg_catalog.current_setting('TimeZone')",
            &[],
        )
        .await?;
    let database: String = row.get(0);
    let user: String = row.get(1);
    let server_addr: Option<String> = row.get(6);
    let server_port: Option<i32> = row.get(7);
    let pinned: Vec<(&'static str, String)> = PINNED_SETTINGS
        .iter()
        .enumerate()
        .map(|(i, (name, _, _))| (*name, row.get::<_, String>(9 + i)))
        .collect();
    let endpoint = match endpoint {
        Endpoint::Socket(p) => format!("socket {}", p.display()),
        Endpoint::Tcp { host, port } => format!("tcp {host}:{port}"),
    };
    let mut details = BTreeMap::from([
        ("database".to_owned(), database.clone()),
        ("user".to_owned(), user.clone()),
        ("endpoint".to_owned(), endpoint),
        // Null over unix sockets; compared including null-ness.
        (
            "server_addr".to_owned(),
            server_addr.unwrap_or_else(|| "(none: unix socket)".into()),
        ),
        (
            "server_port".to_owned(),
            server_port.map_or_else(|| "(none: unix socket)".into(), |p| p.to_string()),
        ),
        ("server_version".to_owned(), row.get(8)),
        ("search_path".to_owned(), row.get(4)),
        ("schemas".to_owned(), row.get(5)),
    ]);
    for (name, value) in &pinned {
        details.insert(format!("setting {name}"), value.clone());
    }
    Ok(Identity {
        database,
        user,
        read_only: row.get(2),
        max_prepared: row.get(3),
        details,
        pinned,
    })
}

/// The serialized JSON length of a value, counted by a writer that discards the bytes.
pub(crate) fn json_len(v: &Value) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut c = Count(0);
    let _ = serde_json::to_writer(&mut c, v);
    c.0
}

pub(crate) fn query_error(e: tokio_postgres::Error, report: &OnceLock<GuardViolation>) -> ReadError {
    if let Some(v) = report.get() {
        return ReadError::Guard(v.clone());
    }
    match e.as_db_error() {
        // About the agent's own statement (or a guard query it provoked): fine to show.
        // Object names and messages come from the database and may hold control or bidi characters.
        Some(db) => ReadError::Server(for_display(&format!("{} ({})", db.message(), db.code().code()))),
        None => ReadError::Other(e.to_string()),
    }
}
