# All valetkey state lives under one short root, `~/.valetkey/`

Date: 2026-10-04 · Status: Active

## Context
The design used the per-OS data dirs (`directories` crate). M0 found two problems:
- **Socket paths:** `~/Library/Application Support/valetkey/sockets/<instance>/.s.PGSQL.5432` is
  far over the 103-byte macOS limit (107 on Linux) ([[cloud-sql-auth-proxy]]).
- **Symlinks:** deny-write rules protect a symlink differently on macOS and Linux. Only denying the
  **parent directory** protects it on both ([[claude-code-sandbox]]).

## Options considered
- Keep the per-OS dirs, and add a separate short sockets dir and per-entry deny rules.
- **One fixed root**: `~/.valetkey/` (`%USERPROFILE%\.valetkey\` on Windows).

## Decision
One root, containing `bin/`, `projects/<project-key>/` (config snapshots), `pending/`,
`write-approvals/`, `sockets/<alias>/`, `secrets/`, audit and logs, and the user-level
`config.toml`. **The root is resolved from the OS user database, never from `HOME`**: a settings
`env` block can set `HOME` for the broker (M0, [[claude-code-client]]). The fence:
- denies writes to the whole root
- denies reads of `secrets/`
- denies unix-socket connects to `sockets/`

Targets name a socket by a short alias, and the proxy is started with
`?unix-socket-path=<absolute root>/sockets/<alias>` (`doctor` prints the exact command).

## Why
- Socket paths stay short.
- One parent-dir deny covers every entry, including symlinks, on both platforms.
- The fence rules become simple enough to check by eye.

## Consequences
- valetkey doesn't follow platform conventions for data dirs (like `~/.ssh`, `~/.aws`, `~/.cargo`).
- `validate` still checks the full socket path length per platform.

## Sources
- `docs/design.md §3`, `§6.2`, `§6.5`; [[2026-10-04-m0-go-no-go]]
