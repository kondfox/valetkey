# Postgres

What a "read" can still do on Postgres, and the guards that stop it. Every row was reproduced on
2026-10-04 against official `postgres` 15.19, 16.15, 17.11 and 18.6 images (plus custom 16/17
images with plpython3u, plperlu, `http`, `pg_background` 2.0 and `pg_net` 0.20.4), as a
non-superuser with `default_transaction_read_only=on` inside `BEGIN READ ONLY`, unless noted.
Driver: `tokio-postgres` 0.7.18. Design: `docs/design.md §6.9`; why: [[2026-10-04-postgres-read-only-guards]].

## Escapes that work despite read-only

| Escape | PG | Stopped by |
|---|---|---|
| `COPY … TO PROGRAM` (role in `pg_execute_server_program`) runs OS commands as `postgres` | 15–17 | refuse the role |
| `COPY … TO '<file>'` (`pg_write_server_files`) | 15–17 | refuse the role |
| `pg_read_file` / `lo_export` after an explicit `GRANT EXECUTE` | 17 | query C (re-granted built-ins) |
| `dblink_exec` / `dblink(… INSERT …)` writes and commits remotely | 16–18 | extension allow-list |
| `postgres_fdw` SELECT on a remote view that calls a writing function: commits on local `COMMIT` | 16–18 | `ROLLBACK` + allow-list |
| `pg_background_run('INSERT …')`: blocked by the startup GUC, but one statement with `set_config('default_transaction_read_only','off',true)` bypasses it | 16–17 | allow-list |
| `http_get(…)` makes outbound requests (exfiltration) | 16–17 | allow-list |
| plpython3u / plperlu `SECURITY DEFINER` function callable via `PUBLIC` runs OS commands | 16–17 | query B |
| User-created `LANGUAGE internal` `SECURITY DEFINER` wrapper over `pg_read_file_all` | 16–17 | query B (no blanket `internal` exclusion) |
| Superuser-owned **plpgsql** `SECURITY DEFINER` running `COPY … TO PROGRAM` | 16–17 | query B (privileged definer) |
| `SET TRANSACTION READ WRITE` as the **first** statement after `BEGIN READ ONLY`, then a write | 15–17 | broker query runs first and takes the snapshot |
| `DO $$ SET default_transaction_read_only=off; COMMIT; INSERT … $$` with only the startup GUC | 15–17 | `BEGIN READ ONLY` (both guards) |
| `pg_cancel_backend`/`pg_terminate_backend` on **another session of the same role** | 16–17 | dedicated role per target |

## Found in M2 (2026-10-05, postgres:15/16/17)

- **Role switching inside one statement.** A role with only a NOINHERIT membership in a role that
  can read table `t` ran `SELECT set_config('role', 'that_role', true), query_to_xml('select * from
  t', …)` in a read-only transaction and got the rows. The outer statement's permission checks
  happen before `set_config` runs; SPI-running built-ins check later, as the new role. Hence the
  role closure in [[2026-10-04-postgres-read-only-guards]].
- **`PREPARE TRANSACTION` works in a read-only transaction** when `max_prepared_transactions > 0`.
  The prepared transaction, and an advisory transaction lock taken before it, survive the
  disconnect.
- `LOCK TABLE … ACCESS EXCLUSIVE` and `nextval` fail in read-only; covered by the regression
  tests.

Regression tests: `crates/valetkey-postgres/tests/read.rs` (every escape above and in the M0
table).

## Blocked by read-only (verified)

`COPY FROM` (program or file), `pg_read_file` without a grant, `lo_import`, `postgres_fdw INSERT`,
`pg_net` (it queues through an INSERT), `plpy.execute('INSERT …')`, `nextval`/`setval`, `DO` with
`SET TRANSACTION READ WRITE` first, `DO $$ COMMIT $$` inside `BEGIN READ ONLY`, multiple statements
through the extended protocol (`cannot insert multiple commands into a prepared statement`),
`pg_terminate_backend` on other roles without `pg_signal_backend`.

Allowed but harmless under the design: advisory locks (released when the per-call connection
closes), `pg_notify` (discarded by `ROLLBACK`).

## Catalog queries (run as the target role; `$1` = extension allow-list, `text[]`)

```sql
-- A. Installed extensions that aren't allow-listed
SELECT extname FROM pg_extension WHERE extname <> ALL ($1::text[]);

-- B. Executable dangerous functions
SELECT p.oid::regprocedure AS func, l.lanname, p.prosecdef, pg_get_userbyid(p.proowner) AS owner, e.extname,
       CASE WHEN NOT l.lanpltrusted THEN 'untrusted-language' ELSE 'privileged-definer' END AS reason
FROM pg_proc p
JOIN pg_language l ON l.oid = p.prolang
LEFT JOIN pg_depend d ON d.classid = 'pg_proc'::regclass AND d.objid = p.oid
                     AND d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e'
LEFT JOIN pg_extension e ON e.oid = d.refobjid
WHERE p.oid >= 16384                                   -- skip built-ins; no blanket 'internal' exclusion
  AND (e.extname IS NULL OR e.extname <> ALL ($1::text[]))
  AND has_function_privilege(current_user, p.oid, 'EXECUTE')
  AND ( NOT l.lanpltrusted
        OR ( p.prosecdef AND EXISTS (
               SELECT 1 FROM pg_roles o WHERE o.oid = p.proowner
                 AND ( o.rolsuper
                       OR pg_has_role(o.oid, 'pg_execute_server_program', 'USAGE')
                       OR pg_has_role(o.oid, 'pg_write_server_files', 'USAGE')
                       OR pg_has_role(o.oid, 'pg_read_server_files', 'USAGE')
                       OR pg_has_role(o.oid, 'pg_signal_backend', 'USAGE')))) );

-- C. Built-ins whose grants changed after initdb (pg_read_file, lo_export, …)
SELECT p.oid::regprocedure FROM pg_proc p
LEFT JOIN pg_init_privs ip ON ip.classoid = 'pg_proc'::regclass AND ip.objoid = p.oid AND ip.objsubid = 0
WHERE p.oid < 16384 AND p.proacl IS DISTINCT FROM ip.initprivs
  AND has_function_privilege(current_user, p.oid, 'EXECUTE');
```

Plus the role checks: `rolsuper`, and membership (`pg_has_role(current_user, …, 'USAGE')`) in
`pg_execute_server_program`, `pg_write_server_files`, `pg_read_server_files`.

On PG16/17 with allow-list `{plpgsql, pgcrypto, pg_stat_statements}`, query B flagged every planted
function (plpython3u, plperlu, C, `internal` wrapper, privileged plpgsql definer) and no built-in or
pgcrypto function. Without pgcrypto on the list it flags pgcrypto's 36 C functions. Query C flagged
`lo_export` and `pg_read_file` for the roles they'd been granted to, and nothing for others.

## Driver details (M2, `crates/valetkey-postgres/src/`)

- `guard.rs` wraps the socket. During authentication it allows only codes 0, 10, 11 and 12
  (OK, SASL); everything else is refused before a password is sent. For the whole connection it
  caps every message at `max_bytes + 64 KiB`, from the 5-byte header.
- `read.rs`: `START TRANSACTION READ ONLY`, then the identity query (`pg_catalog.current_database()`,
  `current_user`, `transaction_read_only`, `max_prepared_transactions`), then the checks, then
  `prepare` (one statement) + `bind` + `query_portal_raw(max_rows + 1)`, then `ROLLBACK`.
- `values.rs`: parameters as text format (`ToSql::encode_format` = Text); results decoded per
  type, with int8 and numeric as strings and a capped hex fallback.

## Password auth (tokio-postgres 0.7.18)

- There's no client option to refuse cleartext or MD5. `connect_raw.rs` `authenticate()`
  (lines ~159–216) answers both unconditionally. A tcpdump showed the cleartext password sent for a
  `pg_hba` `password` user.
- `channel_binding = require` refuses cleartext and MD5, but without TLS it also refuses SCRAM
  (`server did not use channel binding`), so it's useless on unix sockets.
- **Auth guard** (prototype, tested): wrap the stream passed to `Config::connect_raw`; read the
  first backend message (`'R'`, length, code); refuse code 3 (cleartext) and 5 (MD5) before
  `tokio-postgres` replies. Cleartext attempt: zero password bytes on the wire; SCRAM connects.
  For TLS, wrap the post-TLS stream through a `TlsConnect` adapter (not prototyped).
  `connect_raw` skips multi-host and `connect_timeout`, so the caller adds its own timeout.
- The password lives in `Config` as `Option<Vec<u8>>`, cloned with `Config`, no zeroize; SCRAM keeps
  a normalized copy.

## Sources

- Spike branch `spike/m0`, `spike/postgres/` (SQL tests, Dockerfile, `q2auth/` prototype), commit
  `f917930`
- `tokio-postgres` 0.7.18 / `postgres-protocol` 0.6.12 source: `src/config.rs:72-80,218-301,736-749`,
  `src/connect_raw.rs:159-225`
