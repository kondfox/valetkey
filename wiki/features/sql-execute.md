# MCP tool `sql_execute`

Runs one writing statement on a `writable` Postgres target, once a human approves that exact
statement in a terminal with `valetkey approve <id>` ([[valetkey-approve]]). Why it works this way:
[[2026-10-04-out-of-band-write-approval]], [[2026-10-09-m3-scope]].

**Arguments:** `target`, `sql` (one statement), `params` (like [[sql-tools]]), and `allow_write`,
which must be `true`.

**What happens** (`crates/valetkey-mcp/src/writes.rs:156`):
1. **Slot.** The target's one write slot for this session is reserved before anything awaits.
   While a request waits, further writes to that target are refused, naming the pending id.
2. **Policy.** Session and policy run, the target must be `writable`, and the secret is fetched.
3. **Prepare.** A read-only connection identifies the server and runs the same checks as reads,
   then prepares the statement and rolls back
   (`crates/valetkey-postgres/src/write.rs:88`). Syntax errors and wrong parameter counts fail
   here, before a human is asked.
4. **Publish.** The request is written to `~/.valetkey/pending/<id>.json`, and the client is shown
   "run `valetkey approve <id>`": as progress messages every 15 s, and as one display-only
   elicitation.
5. **Wait.** The broker waits up to 5 minutes for `~/.valetkey/write-approvals/<id>.json`
   (`writes.rs:446`). If the client cancels or disconnects, the request is withdrawn.
6. **Re-check.** The decision must carry this request's hash and an unused nonce (`writes.rs:501`).
   Then session and policy run again (`writes.rs:525`).
7. **Audit.** The `approved` audit record is written; if it can't be, nothing runs.
8. **Execute.** The write runs on a new connection (`write.rs:119`): identity and parameter types
   must equal the approved ones, the statement runs to completion, then `COMMIT`.

**Result:**
```
{ target, fence?, approval: { id }, verified: { database, user }, columns, rows, row_count,
  rows_affected, truncated, duration_ms }
```
`rows` holds `RETURNING` rows, up to the target's `max_rows` and `max_bytes`. `truncated` refers to
the result only: the write itself always completed.

**Refusals and denials** come back as tool errors:
- refusals: `allow_write` missing, target not writable, a request already pending, the read
  path's refusals
- denials: denied by the human, approval mismatch, timeout, cancelled, policy or identity changed
  during the wait

**Transaction control inside the statement** (verified on Postgres 17, `tests/write.rs`):
- `COMMIT`, `ROLLBACK` and `COMMIT AND CHAIN` end the broker's transaction early. That's harmless,
  because only the broker's own `COMMIT` follows.
- `DO … COMMIT` and a `CALL` of a committing procedure fail: they can't commit inside a
  transaction block.
- These fail cleanly and change nothing: `COPY … FROM STDIN` / `TO STDOUT`, `VACUUM`,
  `CREATE INDEX CONCURRENTLY`, `PREPARE TRANSACTION`, and anything else that can't run in a
  transaction block.

The call reports `ok` even when the statement ended the transaction itself (`ROLLBACK` as the
statement writes nothing). valetkey can't see the transaction status through the driver, so it
doesn't try to annotate this.

**Limits:**
- A single result value bigger than the connection guard's cap (`max_bytes + 64 KiB`) cuts the
  connection, so the write rolls back.
- The call's time limit covers everything before `COMMIT`. `COMMIT` has its own bound
  (`statement_timeout` + 10 s). A lost connection, or no answer within that bound, is reported as
  an unknown outcome (audited `unknown`): the write may have committed.
  `tests/write.rs` (`a_commit_without_an_answer_is_reported_as_unknown`) proves it.

**Shutdown:** the broker sweeps orphaned requests at startup. When it ends, `Broker::drain` withdraws
waiting requests and waits for running writes, so every approved write gets an outcome record. The
wait is bounded by the longest an approved write can take: roots + secret fetch + call +
`COMMIT` + margin.

Tests: `crates/valetkey-mcp/tests/writes.rs`, `crates/valetkey-postgres/tests/write.rs`.
