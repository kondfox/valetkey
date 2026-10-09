# The audit log and `valetkey log`

Every call to `sql_query`, `sql_describe` and `sql_execute`, refusals included, appends one JSON
line to `~/.valetkey/audit/<YYYY-MM>.<N>.jsonl` (`docs/design.md §6.7` step 7;
`crates/valetkey-core/src/audit.rs:95`).

**A record holds:**
- time, tool and outcome
- target, project key and root
- client name and version (client-supplied), broker pid and session id
- statement text and its blake3 hash, parameters as sent
- rows or rows affected, and whether the result was truncated
- the reason for a refusal or error
- the approval (id, request hash, time, terminal)
- duration

Never a secret.

**Outcomes:** `ok`, `refused`, `error`, `denied`, `timeout`, `cancelled`, `approved` and `unknown`.
- A write logs `approved` **before** it executes and its outcome after. An `approved` record with no
  outcome record means the broker died in between; `valetkey log` shows it as `unknown`.
- `unknown` on its own means the connection was lost during `COMMIT`.

**Writing:**
- One `write_all` per record, holding an exclusive `flock`, so concurrent brokers never interleave
  records. A test runs 8 threads × 10 records of 200 KiB each. The lock is waited for at most
  2 s, so a stuck holder can't hang the broker; the record then counts as not written.
- **Records stay bounded.** Accepted input is already capped (statement 64 KiB, parameters
  64 KiB). A call refused for its size keeps only the statement's hash, length and first KiB.
  Target ids are cut at 128 characters.
- Files are 0600 in a 0700 directory, opened without following links.
- A file rolls over to `N+1` past 64 MiB. **Auditing never stops on its own**: a stopping cap
  would let the agent switch it off by padding its calls ([[2026-10-09-m3-scope]]).

**When it can't be written:**
- Writes don't run.
- Reads still run, with `AUDIT LOG NOT WRITTEN` in `mcp.log`.
- `valetkey doctor` reports an unwritable audit dir, and warns past 1 GiB
  (`crates/valetkey-cli/src/commands/doctor.rs:206`).

**Who can read it:** the agent can't write it (the §6.5 deny-write on the root). It's also meant to
be deny-read, because it holds every project's statements, but that row only exists once M4
generates the fence. Until then it's readable.

**`valetkey log [--follow]`** prints one sanitized line per record: time, outcome, tool, target,
approval id, row count, statement hash and the start of the statement
(`crates/valetkey-cli/src/commands/log.rs:49`). `--follow` polls for new records.
