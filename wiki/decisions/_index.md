# Decisions

One page per design, architecture, tooling or process decision: `YYYY-MM-DD-<slug>.md`, following
the skeleton in [[CLAUDE]]. **Why** is the section that matters most. A page that's replaced moves
to *Superseded* and links to its successor.

## Active

- [[2026-10-04-credential-broker-pattern]]: isolation = broker + immutable binary + fence
- [[2026-10-04-name-valetkey]]: the name, and why
- [[2026-10-04-rust-single-binary]]: Rust, one static binary per OS
- [[2026-10-04-mcp-interface-per-agent-fence]]: MCP interface; fence profiles per agent, Claude Code first
- [[2026-10-04-human-approved-config-snapshot]]: `valetkey allow`; the broker serves approved snapshots only
- [[2026-10-04-secret-exposure-classification]]: exposed vs protected secrets drive every rule
- [[2026-10-04-vendor-clis-for-secret-sources]]: vendor CLIs, not SDKs
- [[2026-10-04-windows-via-wsl2]]: WSL2 for the full guarantee; native Windows unfenced
- [[2026-10-04-no-tunnel-management-in-v1]]: humans start proxies in v1
- [[2026-10-04-public-github-repo]]: public GitHub, MIT OR Apache-2.0
- [[2026-10-04-binary-provenance-and-registration]]: minisign; only the installed copy installs
- [[2026-10-04-fail-closed-fence-capabilities]]: unverified capability → unfenced
- [[2026-10-04-write-approval-scope]]: when a write needs a human
- [[2026-10-04-postgres-read-only-guards]]: protocol, transaction and role guards
- [[2026-10-04-commit-message-convention]]: Conventional Commits + gitmoji after the colon
- [[2026-10-04-m0-go-no-go]]: M0 results; what held, what missed, what changed
- [[2026-10-04-out-of-band-write-approval]]: `valetkey approve <id>`; elicitation is display-only
- [[2026-10-04-local-secret-store]]: `local://` file store; keyring exposed on macOS
- [[2026-10-04-valetkey-root-dir]]: one short root, `~/.valetkey/`
- [[2026-10-04-broker-environment-allowlist]]: the broker ignores injected env; fixed `PATH`
- [[2026-10-04-dev-root-only-in-debug-builds]]: `VALETKEY_DEV_ROOT` exists only in debug builds
- [[2026-10-04-toolchain-and-msrv]]: Rust 1.99.0 pinned, MSRV 1.88
- [[2026-10-05-m2-scope]]: two PRs; TLS in M3; protected targets unfenced until M4

## Superseded

(none)
