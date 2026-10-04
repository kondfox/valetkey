# MCP tools `sql_query` and `sql_describe`

Read-only access to an approved Postgres target. Each call goes session → policy → secret → read
path ([[architecture]]).

- **`sql_query(target, sql, params?)`** runs one statement in a read-only transaction that is
  always rolled back. Parameters (`$1`, …) are JSON strings, numbers, booleans or null, sent as
  text-format data, never as SQL.
- **`sql_describe(target, table?)`**: without `table`, the tables and views the role can see;
  with `table` (`name` or `schema.name`), its columns. The name is bound as a parameter.

**Result:**
```
{ target, fence?, verified: { database, user }, columns: [{ name, type }],
  rows: [[…]], row_count, truncated, duration_ms }
```
- `int8` and `numeric` come back as strings, NaN and infinities as strings, `bytea` as base64, and
  arrays nested.
- `fence` appears when a protected target is used without one (`require_fence = false`).

**Checks** (role closure, extensions, dangerous functions, re-granted built-ins) run for protected
targets and for every socket target. Exposed TCP targets skip them
([[exposed-tcp-targets-skip-checks]]).

**What a read can see** is the union of what every role in the login role's closure can read: one
statement can switch roles. Give each target a dedicated role with no memberships beyond what it
needs.

**Per-target limits** (settings, low risk in `allow`):
- `max_rows` (1000, at most 10000)
- `max_bytes` (1 MiB, at most 16 MiB; approximate: counts the values' JSON, not names or framing)
- `statement_timeout_ms` (30 s, at most 300 s)

The whole call also has a wall-clock limit.

**Refusals** come back as tool errors:
- unknown target (the valid ids are listed)
- wrong kind
- unverified project dir, a loose valetkey root, or no fence (protected targets)
- prepared transactions allowed on the server
- the role-closure and catalog checks

Postgres's own error messages about the agent's statement are passed through. Everything else is
fixed text.

**Logging:** `mcp.log` gets the tool, target, a statement hash, the row count, the duration and the
outcome. Never statement text, parameters or secrets (tested with the production filter).

Entry points: `crates/valetkey-mcp/src/lib.rs` (tools), `policy.rs`, `session.rs`;
`crates/valetkey-postgres/src/read.rs`. Tests: `crates/valetkey-mcp/tests/sql.rs`,
`crates/valetkey-postgres/tests/read.rs`.
