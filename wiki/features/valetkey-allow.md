# `valetkey allow`

A human reviews what `valetkey.toml` lets the agent use, and approves it. Until then, and after
any meaningful edit, the broker serves nothing ([[2026-10-04-human-approved-config-snapshot]]).

- Runs only with an **interactive terminal** on stdin and stdout, so it can't be scripted through a
  pipe. Inside the agent's sandbox it would fail anyway: the valetkey root is write-denied.
- Reads the file **once**, validates it, and stores exactly what it showed. Approval needs the
  word `yes`.
- Shows each target (kind, exposure, writable, connection, secret reference) and a per-change
  diff labelled `HIGH` or `low` by effect (`valetkey-core/src/diff.rs`). Every displayed string is
  sanitized (`valetkey-core/src/sanitize.rs`), and non-ASCII target names are flagged.
- Comment- and whitespace-only edits don't change the canonical hash, so they need no
  re-approval.

Entry point: `crates/valetkey-cli/src/commands/allow.rs`. Snapshot store:
`~/.valetkey/projects/<project-key>/snapshot.json` (`valetkey-core/src/snapshot.rs`).
