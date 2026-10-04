//! Checks for protected targets, run inside the read-only transaction before the agent's
//! statement (§6.9). Every name is schema-qualified, so a role-level `search_path` can't shadow
//! the functions and catalogs used here.
//!
//! **Role closure (M2 review, blocker B1).** A single statement can switch roles with
//! `set_config('role', …)`, and SPI-running built-ins such as `query_to_xml` then run with the new
//! role: verified on PG16 and PG17, including through a NOINHERIT membership. So every check
//! covers each role the login role can `SET ROLE` to (transitively; on PG16+ only grants with the
//! SET option), not just the login role.

use std::collections::BTreeSet;

use tokio_postgres::Transaction;

/// Extensions allowed on a protected target by default (M0: no network, no file I/O, no
/// background workers).
pub const DEFAULT_EXTENSIONS: &[&str] = &[
    "plpgsql",
    "pgcrypto",
    "pg_stat_statements",
    "uuid-ossp",
    "citext",
    "hstore",
    "pg_trgm",
    "btree_gin",
    "btree_gist",
    "unaccent",
    "fuzzystrmatch",
    "intarray",
    "ltree",
    "cube",
    "earthdistance",
    "tablefunc",
    "vector",
    "postgis",
];

/// Roles that grant server-side file or program access.
const DANGEROUS_ROLES: &[&str] = &[
    "pg_execute_server_program",
    "pg_write_server_files",
    "pg_read_server_files",
];

#[derive(Debug)]
pub enum CheckError {
    /// A check found something; the text names the object (catalog data, not a secret).
    Refused(String),
    Query(tokio_postgres::Error),
}

impl From<tokio_postgres::Error> for CheckError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::Query(e)
    }
}

/// Runs every check; the first finding refuses.
pub async fn run(
    txn: &Transaction<'_>,
    extra_extensions: &[String],
    allow_grant_drift: bool,
) -> Result<(), CheckError> {
    let closure = role_closure(txn).await?;
    let oids: Vec<String> = closure.iter().map(|(oid, _)| oid.to_string()).collect();
    let oid_array = format!("{{{}}}", oids.join(","));
    let names: BTreeSet<&str> = closure.iter().map(|(_, n)| n.as_str()).collect();

    // Superusers and the server-file/program roles anywhere in the closure.
    let supers = txn
        .query(
            "SELECT r.rolname::text FROM pg_catalog.pg_roles r WHERE r.oid::text = ANY($1::text[]) AND r.rolsuper",
            &[&crate::values::TextParam(Some(text_array(&oids)))],
        )
        .await?;
    if let Some(row) = supers.first() {
        let name: String = row.get(0);
        return Err(CheckError::Refused(format!(
            "the login role can become the superuser `{name}`"
        )));
    }
    if let Some(bad) = DANGEROUS_ROLES.iter().find(|r| names.contains(**r)) {
        return Err(CheckError::Refused(format!(
            "the login role can become `{bad}`, which reads or writes server files or runs programs even in a read-only transaction"
        )));
    }

    // Query A: extensions.
    let mut allowed: Vec<String> = DEFAULT_EXTENSIONS.iter().map(|s| (*s).to_owned()).collect();
    allowed.extend(extra_extensions.iter().cloned());
    let allow_param = crate::values::TextParam(Some(text_array(&allowed)));
    let extra = txn
        .query(
            "SELECT e.extname::text FROM pg_catalog.pg_extension e WHERE e.extname::text <> ALL ($1::text[]) ORDER BY 1",
            &[&allow_param],
        )
        .await?;
    if !extra.is_empty() {
        let list: Vec<String> = extra.iter().map(|r| r.get(0)).collect();
        return Err(CheckError::Refused(format!(
            "extensions that can escape read-only are installed: {}. Allow them per target with `extensions.allow` if you accept that",
            list.join(", ")
        )));
    }

    // Query B: executable dangerous functions, for every role in the closure.
    let roles_param = crate::values::TextParam(Some(oid_array.clone()));
    let dangerous = txn
        .query(
            "SELECT DISTINCT p.oid::pg_catalog.regprocedure::text
             FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_language l ON l.oid = p.prolang
             LEFT JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid = p.oid
                  AND d.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass AND d.deptype = 'e'
             LEFT JOIN pg_catalog.pg_extension e ON e.oid = d.refobjid
             CROSS JOIN pg_catalog.unnest($1::pg_catalog.oid[]) AS r(oid)
             WHERE p.oid >= 16384
               AND (e.extname IS NULL OR e.extname::text <> ALL ($2::text[]))
               AND pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE')
               AND (NOT l.lanpltrusted
                    OR (p.prosecdef AND EXISTS (
                         SELECT 1 FROM pg_catalog.pg_roles o WHERE o.oid = p.proowner
                           AND (o.rolsuper
                                OR pg_catalog.pg_has_role(o.oid, 'pg_execute_server_program', 'USAGE')
                                OR pg_catalog.pg_has_role(o.oid, 'pg_write_server_files', 'USAGE')
                                OR pg_catalog.pg_has_role(o.oid, 'pg_read_server_files', 'USAGE')
                                OR pg_catalog.pg_has_role(o.oid, 'pg_signal_backend', 'USAGE')))))
             ORDER BY 1 LIMIT 5",
            &[&roles_param, &allow_param],
        )
        .await?;
    if !dangerous.is_empty() {
        let list: Vec<String> = dangerous.iter().map(|r| r.get(0)).collect();
        return Err(CheckError::Refused(format!(
            "the login role (or a role it can become) can run functions that escape read-only: {}",
            list.join(", ")
        )));
    }

    // Query C: built-ins re-granted after initdb (pg_read_file, lo_export, …).
    if !allow_grant_drift {
        let drift = txn
            .query(
                "SELECT DISTINCT p.oid::pg_catalog.regprocedure::text
                 FROM pg_catalog.pg_proc p
                 LEFT JOIN pg_catalog.pg_init_privs ip ON ip.classoid = 'pg_catalog.pg_proc'::pg_catalog.regclass
                      AND ip.objoid = p.oid AND ip.objsubid = 0
                 CROSS JOIN pg_catalog.unnest($1::pg_catalog.oid[]) AS r(oid)
                 WHERE p.oid < 16384 AND p.proacl IS DISTINCT FROM ip.initprivs
                   AND pg_catalog.has_function_privilege(r.oid, p.oid, 'EXECUTE')
                 ORDER BY 1 LIMIT 5",
                &[&roles_param],
            )
            .await?;
        if !drift.is_empty() {
            let list: Vec<String> = drift.iter().map(|r| r.get(0)).collect();
            return Err(CheckError::Refused(format!(
                "built-in functions were granted beyond their defaults: {}. If that's deliberate hardening, set `allow_grant_drift = true` on the target",
                list.join(", ")
            )));
        }
    }
    Ok(())
}

/// Every role the session user can `SET ROLE` to, including itself: transitive membership; on
/// PG16+ only through grants with the SET option.
async fn role_closure(txn: &Transaction<'_>) -> Result<Vec<(u32, String)>, tokio_postgres::Error> {
    let version: i32 = txn
        .query_one("SELECT pg_catalog.current_setting('server_version_num')::int", &[])
        .await?
        .get(0);
    let set_option = if version >= 160_000 { "AND m.set_option" } else { "" };
    let sql = format!(
        "WITH RECURSIVE closure(oid) AS (
             SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = session_user
             UNION
             SELECT m.roleid FROM pg_catalog.pg_auth_members m JOIN closure c ON m.member = c.oid WHERE true {set_option}
         )
         SELECT r.oid, r.rolname::text FROM closure c JOIN pg_catalog.pg_roles r ON r.oid = c.oid ORDER BY 2"
    );
    let rows = txn.query(&sql, &[]).await?;
    Ok(rows
        .iter()
        .map(|r| (r.get::<_, u32>(0), r.get::<_, String>(1)))
        .collect())
}

/// A Postgres text-array literal with every element quoted.
fn text_array(items: &[String]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!("{{{}}}", quoted.join(","))
}

#[cfg(test)]
mod tests {
    #[test]
    fn text_arrays_quote_everything() {
        assert_eq!(
            super::text_array(&["a".into(), "b\"c".into(), "d,e".into()]),
            r#"{"a","b\"c","d,e"}"#
        );
    }
}
