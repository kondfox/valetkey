# Postgres reads are guarded at protocol, transaction and role level; protected targets refuse risky roles

Date: 2026-10-04 · Status: Active

## Context
`sql_query` must not change data, or have side effects beyond what the role allows. Escapes found
across the prototype's review and this project's review:
- multi-statement `COMMIT; DELETE …`
- `SET TRANSACTION READ WRITE`
- `dblink` and `postgres_fdw`
- other extensions (`pg_background`, `pg_net`, `http`, `aws_lambda`)
- `COPY … TO PROGRAM` for members of `pg_execute_server_program`
- `EXECUTE` on functions written in untrusted languages

## Decision
`design.md §6.9`:
- `tokio-postgres`, using the extended protocol only (single statement)
- `BEGIN READ ONLY`, plus `default_transaction_read_only=on` and timeouts
- streaming rows with a cap
- identity verified after connecting
- For protected targets, refuse to connect when:
  - the role is a superuser
  - the role is a member of `pg_execute_server_program`, `pg_write_server_files` or
    `pg_read_server_files`
  - the role can `EXECUTE` untrusted-language functions (excluding `internal`, built-ins and
    allow-listed extension members)
  - an installed extension isn't on the allow-list (`extensions.allow` to opt in)

## Why
- Each layer stops a different class: the protocol stops statement smuggling, the transaction
  stops plain writes, the role checks stop server-side escapes.
- Only a least-privilege role closes the rest (advisory locks, `pg_terminate_backend`), so the docs
  recommend one per target.
- `sqlx` hides the protocol and portal control this needs.

## Consequences
- The guards are proven only against a real Postgres (testcontainers), never a mock.
- M0 items 24 and 31 verify the `COPY` and untrusted-function behaviour.

## Sources
- `docs/design.md` §6.9; `docs/threat-model.md` A10, A11, A13 (commit `6181a1d`)
