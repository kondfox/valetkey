# `valetkey approve [ID] [--full]`

A human decides on a pending write from [[sql-execute]], in a **normal terminal**. It refuses to
run unless stdin and stdout are TTYs, and inside the agent's sandbox it can't write its decision.

- **No id:** lists pending requests with their id, age, project, target, client (client-supplied,
  sanitized and capped) and state (`orphaned`, `expired`)
  (`crates/valetkey-cli/src/commands/approve.rs:58`).
- **With an id** (`approve.rs:101`), it refuses a request that is:
  - malformed or unreadable
  - expired
  - orphaned: no broker holds its lock any more (the agent session was killed). It's removed.

  Otherwise it shows the statement and parameters in a numbered gutter
  (`crates/valetkey-core/src/write_request.rs:144`), then a summary right above the prompt: target,
  identity, sizes, hash, expiry (`write_request.rs:219`).
- **To approve, type the request id.** `n` denies, so the broker stops waiting at once. Anything
  else, `yes` included, leaves the request waiting. There's no `--yes`, and there never will be.
- **Truncated?** A statement over 8 KiB or 200 lines, or a parameter over 256 characters, is shown
  truncated. Approving it then needs `--full`.
- **What gets written:** `~/.valetkey/write-approvals/<id>.json`, published atomically and never
  replacing an existing one (`crates/valetkey-core/src/write_store.rs:294`). It holds the hash of
  the request **as shown**, the verdict, the time and the terminal (`ttyname`).

**Why approving what you see is enough:** the broker executes only its in-memory request, and only
when the decision's hash matches it. If someone rewrote the pending file, the human approved
something else, and the broker denies.

**Display rules:**
- Control characters, ANSI escapes, bidi overrides and zero-width characters are escaped visibly.
- Tabs show as `→`, newlines stay line breaks, and more than two blank lines collapse into a
  marker.
- Lines with non-ASCII characters get `⚠` in the gutter.
- SQL `NULL` is shown distinct from the string `'null'`.

The `allow` diff keeps its own rules (`sanitize::for_display`).

Tests: `approve.rs` (unit), `crates/valetkey-core/src/write_request.rs`, `write_store.rs`.
