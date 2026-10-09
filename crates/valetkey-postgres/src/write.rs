//! The write path (§6.9, §6.10): two connections per write, with a human's approval in between.
//!
//! **Before approval** ([`prepare_write`]): connect read-only, identify (database, user, endpoint,
//! server address and version, `search_path`, the pinned session settings), refuse servers that
//! allow prepared transactions, run the role-closure and catalog checks when the target needs
//! them, and `prepare` the statement, which rejects syntax errors and wrong parameter counts and
//! yields the server-inferred parameter types. `ROLLBACK`, disconnect. Nothing is held open while
//! the human decides.
//!
//! **After approval** ([`execute_write`]): reconnect, `START TRANSACTION READ WRITE`, identify
//! again and require every identity detail to equal the approved one, the checks again, prepare
//! again and require the same parameter types (by OID), then execute the one statement through the
//! extended protocol **without a row limit**, so the statement always runs to completion (a
//! row-limited portal would run a writing `SELECT` only partway and then commit that part). The
//! first `max_rows` result rows within `max_bytes` are kept; the rest are counted and discarded,
//! one message at a time. `rows_affected` comes from `CommandComplete`. Then `COMMIT`.
//!
//! Any error before `COMMIT` rolls back. A single result message over the connection guard's cap
//! cuts the connection, which also rolls back. A connection lost during `COMMIT` is reported as an
//! unknown outcome.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use futures_util::StreamExt;
use secrecy::SecretString;
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::types::ToSql;

use valetkey_core::sanitize::for_display;

use crate::checks;
use crate::guard::GuardViolation;
use crate::read::{
    AbortOnDrop, Column, ConnectSpec, Endpoint, Limits, ReadError, Verified, connect, identify, json_len, query_error,
};
use crate::values::{AnyValue, TextParam};

/// Where and how a write runs: the same target settings as a read.
#[derive(Debug)]
pub struct WriteTarget<'a> {
    pub endpoint: Endpoint,
    pub database: &'a str,
    pub user: &'a str,
    pub password: &'a SecretString,
    pub run_checks: bool,
    pub allow_prepared_transactions: bool,
    pub extra_extensions: &'a [String],
    pub allow_grant_drift: bool,
    pub limits: Limits,
}

/// A parameter as the server typed it and as it goes over the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedParam {
    /// Schema-qualified (`pg_catalog.int4`).
    pub type_name: String,
    pub type_oid: u32,
    /// `None` is SQL NULL.
    pub text: Option<String>,
}

/// What the pre-approval connection found: shown to the human and compared after reconnecting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub identity: BTreeMap<String, String>,
    pub params: Vec<TypedParam>,
}

/// What the agent gets back from a committed write.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct WriteResult {
    pub verified: Verified,
    /// `RETURNING` columns, if any.
    pub columns: Vec<Column>,
    pub rows: Vec<Vec<Value>>,
    pub row_count: usize,
    /// From the server's command tag (`UPDATE 3` → 3).
    pub rows_affected: Option<u64>,
    /// Result rows were dropped by the row or byte limit. The write itself is complete.
    pub truncated: bool,
    pub duration_ms: u64,
}

/// Connects, verifies and prepares; executes nothing. See the module docs.
pub async fn prepare_write(t: &WriteTarget<'_>, sql: &str, params: &[Value]) -> Result<Prepared, ReadError> {
    let timeout = t.limits.call_timeout;
    tokio::time::timeout(timeout, prepare_inner(t, sql, params))
        .await
        .unwrap_or(Err(ReadError::Timeout(timeout)))
}

async fn prepare_inner(t: &WriteTarget<'_>, sql: &str, params: &[Value]) -> Result<Prepared, ReadError> {
    let report = Arc::new(OnceLock::new());
    let (mut client, connection) = connect(&spec(t, true), report.clone()).await?;
    let _connection = AbortOnDrop(tokio::spawn(connection));
    let err = |e: tokio_postgres::Error| query_error(e, &report);

    let txn = client.build_transaction().read_only(true).start().await.map_err(err)?;
    let id = identify(&txn, &t.endpoint).await.map_err(err)?;
    id.check(t.database, t.user, true)?;
    guard_server(&txn, t, id.max_prepared, &report).await?;
    let statement = txn.prepare(sql).await.map_err(err)?;
    let typed = typed_params(statement.params(), params)?;
    txn.rollback().await.map_err(err)?;
    Ok(Prepared {
        identity: id.details,
        params: typed,
    })
}

/// Reconnects, re-verifies against `approved`, executes and commits. See the module docs.
///
/// The call timeout covers everything **before** `COMMIT` (M3 code review C1): once `COMMIT` is
/// sent, the write may have happened, so a timeout there is reported as an unknown outcome, never
/// as an error. `COMMIT` has its own bound, [`Limits::commit_timeout`].
pub async fn execute_write(
    t: &WriteTarget<'_>,
    sql: &str,
    params: &[Value],
    approved: &Prepared,
) -> Result<WriteResult, ReadError> {
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + t.limits.call_timeout;
    let timed_out = |_| ReadError::Timeout(t.limits.call_timeout);
    let report = Arc::new(OnceLock::new());
    let (mut client, connection) = tokio::time::timeout_at(deadline, connect(&spec(t, false), report.clone()))
        .await
        .map_err(timed_out)??;
    let _connection = AbortOnDrop(tokio::spawn(connection));
    let err = |e: tokio_postgres::Error| query_error(e, &report);

    // Dropping `txn` on any early return rolls back.
    let txn = tokio::time::timeout_at(deadline, client.build_transaction().read_only(false).start())
        .await
        .map_err(timed_out)?
        .map_err(err)?;
    let ran = tokio::time::timeout_at(deadline, run_statement(&txn, t, sql, params, approved, &report))
        .await
        .map_err(timed_out)??;

    match tokio::time::timeout(t.limits.commit_timeout, txn.commit()).await {
        Ok(Ok(())) => {}
        // The server answered: COMMIT failed (e.g. a deferred constraint) and rolled back.
        Ok(Err(e)) if e.as_db_error().is_some() => return Err(err(e)),
        Ok(Err(e)) => return Err(ReadError::CommitUnknown(e.to_string())),
        Err(_) => {
            return Err(ReadError::CommitUnknown(format!(
                "no answer to COMMIT within {:?}",
                t.limits.commit_timeout
            )));
        }
    }
    let row_count = ran.rows.len();
    Ok(WriteResult {
        verified: Verified {
            database: ran.database,
            user: ran.user,
        },
        columns: ran.columns,
        rows: ran.rows,
        row_count,
        rows_affected: ran.rows_affected,
        truncated: ran.truncated,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

/// What the statement produced, before `COMMIT`.
struct Ran {
    database: String,
    user: String,
    columns: Vec<Column>,
    rows: Vec<Vec<Value>>,
    rows_affected: Option<u64>,
    truncated: bool,
}

/// Identity and checks again, then the statement, to completion. Nothing is committed here.
async fn run_statement(
    txn: &tokio_postgres::Transaction<'_>,
    t: &WriteTarget<'_>,
    sql: &str,
    params: &[Value],
    approved: &Prepared,
    report: &OnceLock<GuardViolation>,
) -> Result<Ran, ReadError> {
    let err = |e: tokio_postgres::Error| query_error(e, report);
    let id = identify(txn, &t.endpoint).await.map_err(err)?;
    id.check(t.database, t.user, false)?;
    if let Some(what) = first_difference(&approved.identity, &id.details) {
        return Err(ReadError::Changed(what));
    }
    guard_server(txn, t, id.max_prepared, report).await?;

    let statement = txn.prepare(sql).await.map_err(err)?;
    let typed = typed_params(statement.params(), params)?;
    if typed != approved.params {
        return Err(ReadError::Changed("the parameter types".into()));
    }
    let text: Vec<TextParam> = typed.iter().map(|p| TextParam(p.text.clone())).collect();
    let refs: Vec<&(dyn ToSql + Sync)> = text.iter().map(|p| p as &(dyn ToSql + Sync)).collect();
    let columns: Vec<Column> = statement
        .columns()
        .iter()
        .map(|c| Column {
            name: c.name().to_owned(),
            type_name: c.type_().name().to_owned(),
        })
        .collect();

    // No row limit: the statement runs to completion. Keep what fits, count the rest.
    let stream = txn.query_raw(&statement, refs).await.map_err(err)?;
    let mut stream = Box::pin(stream);
    let mut rows = Vec::new();
    let mut bytes = 0usize;
    let mut truncated = false;
    while let Some(row) = stream.next().await {
        let row = row.map_err(err)?;
        if truncated || rows.len() as u32 >= t.limits.max_rows {
            truncated = true;
            continue;
        }
        let values: Vec<Value> = (0..row.len())
            .map(|i| row.try_get::<_, AnyValue>(i).map(|v| v.0))
            .collect::<Result<_, _>>()
            .map_err(err)?;
        let size: usize = values.iter().map(json_len).sum();
        if bytes + size > t.limits.max_bytes {
            truncated = true;
            continue;
        }
        bytes += size;
        rows.push(values);
    }
    let rows_affected = stream.rows_affected();
    Ok(Ran {
        database: id.database,
        user: id.user,
        columns,
        rows,
        rows_affected,
        truncated,
    })
}

fn spec<'a>(t: &'a WriteTarget<'a>, read_only: bool) -> ConnectSpec<'a> {
    ConnectSpec {
        endpoint: &t.endpoint,
        database: t.database,
        user: t.user,
        password: t.password,
        limits: t.limits,
        read_only,
    }
}

/// The prepared-transactions refusal and, when the target needs them, the role-closure and catalog
/// checks: the same rules as reads.
async fn guard_server(
    txn: &tokio_postgres::Transaction<'_>,
    t: &WriteTarget<'_>,
    max_prepared: i32,
    report: &OnceLock<GuardViolation>,
) -> Result<(), ReadError> {
    // A `PREPARE TRANSACTION` would leave the transaction and its locks behind (M2 finding).
    if max_prepared > 0 && !t.allow_prepared_transactions {
        return Err(ReadError::Refused(format!(
            "the server allows prepared transactions (max_prepared_transactions = {max_prepared}), which let a statement leave a transaction and its locks behind; set it to 0, or (exposed targets only) set allow_prepared_transactions = true"
        )));
    }
    if t.run_checks {
        checks::run(txn, t.extra_extensions, t.allow_grant_drift)
            .await
            .map_err(|e| match e {
                checks::CheckError::Refused(why) => ReadError::Refused(for_display(&why)),
                checks::CheckError::Query(e) => query_error(e, report),
            })?;
    }
    Ok(())
}

/// Pairs the server-inferred types with the agent's values, converted exactly as they'll be sent.
fn typed_params(types: &[tokio_postgres::types::Type], params: &[Value]) -> Result<Vec<TypedParam>, ReadError> {
    if types.len() != params.len() {
        return Err(ReadError::ParamCount {
            expected: types.len(),
            got: params.len(),
        });
    }
    types
        .iter()
        .zip(params)
        .map(|(ty, v)| {
            let text = TextParam::from_json(v).map_err(ReadError::Param)?.0;
            Ok(TypedParam {
                type_name: format!("{}.{}", ty.schema(), ty.name()),
                type_oid: ty.oid(),
                text,
            })
        })
        .collect()
}

/// The first identity detail that differs, by name.
fn first_difference(approved: &BTreeMap<String, String>, now: &BTreeMap<String, String>) -> Option<String> {
    if approved == now {
        return None;
    }
    let keys: std::collections::BTreeSet<&String> = approved.keys().chain(now.keys()).collect();
    keys.into_iter()
        .find(|k| approved.get(*k) != now.get(*k))
        .map(|k| format!("the server's {}", for_display(k)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_differences_are_named() {
        let a: BTreeMap<String, String> = [
            ("database".into(), "app".into()),
            ("search_path".into(), "public".into()),
        ]
        .into();
        let mut b = a.clone();
        assert_eq!(first_difference(&a, &b), None);
        b.insert("search_path".into(), "evil, public".into());
        assert_eq!(first_difference(&a, &b).as_deref(), Some("the server's search_path"));
        b = a.clone();
        b.insert("server_addr".into(), "10.0.0.9".into());
        assert_eq!(first_difference(&a, &b).as_deref(), Some("the server's server_addr"));
    }
}
