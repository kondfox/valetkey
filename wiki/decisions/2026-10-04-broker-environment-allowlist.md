# The broker allowlists its environment and uses a fixed PATH

Date: 2026-10-04 · Status: Active

## Context
M0 showed that a project's `.claude/settings.json` `env` block reaches every MCP server, user-scope
ones included: `PATH`, `SSL_CERT_FILE`, `NODE_OPTIONS`, proxy variables ([[claude-code-client]]).
The broker runs outside the sandbox and resolves vendor CLIs (`gcloud`, …) through the environment.
On Linux, `SSL_CERT_FILE` would also *replace* the TLS trust store ([[rustls-platform-verifier]]).

## Options considered
- Clear a denylist of known-dangerous variables (TLS, proxies).
- **Keep an allowlist**, and take paths and trust settings only from user-level valetkey config.

## Decision
`docs/design.md §6.8`:
- At startup the broker keeps only locale and `CLAUDE_PROJECT_DIR` (cross-checked against the
  client's MCP roots). `HOME` and the user come from the OS user database. Credential-location
  variables are set from the values stored in `~/.valetkey/config.toml`, never inherited.
- `PATH` is replaced by a fixed one: system dirs plus vendor CLI absolute paths, which a human's
  `valetkey doctor` resolved and stored in `~/.valetkey/config.toml`. `doctor` refuses paths in
  any agent-writable dir and shows each one for confirmation.
- TLS and proxy settings come from that user-level config only.

## Why
A denylist misses whatever nobody thought of (`NODE_OPTIONS` reached the server in M0). The broker
is the one process that holds secrets, so its inputs should be the smallest set it needs.

## Consequences
- Corporate proxies and CAs need a one-time entry in the user-level config.
- `detect` also flags an `env` block that sets `PATH`, because hooks and Claude Code's own `git`
  calls use it.

## Sources
- [[claude-code-client]], [[rustls-platform-verifier]]; [[2026-10-04-m0-go-no-go]]
