# The broker process keeps its inherited environment

Status: Open · Since: 2026-10-09 (found in the M3 plan review, B8) · Pay down in: M3b

**The debt.** `docs/design.md §6.8` and threat-model A7f say the broker keeps only an environment
allowlist. Today only the processes the runner starts get a clean environment
(`crates/valetkey-secrets/src/runner.rs`, `env_clear()`). The broker itself keeps everything it
inherited (`crates/valetkey-cli/src/commands/mcp.rs`), and a project's settings `env` block reaches
every MCP server ([[claude-code-client]]).

**Why it matters in M3b.** On Linux, `rustls-platform-verifier` loads roots through
`rustls-native-certs`, which reads `SSL_CERT_FILE` and `SSL_CERT_DIR` from the process environment.
If set, they *replace* the system store ([[rustls-platform-verifier]]). An injected variable would
then decide which servers the broker trusts. M3a opens no TLS connections (TLS fields are still
rejected when the config loads), so nothing depends on it yet.

**Paying it down.** In `main`, before the tokio runtime starts (still single-threaded), reduce the
environment to the §6.8 allowlist. Alternatively, build the verifier from explicitly loaded roots.
Test: a broker started with `SSL_CERT_FILE` pointing at a test CA still rejects that CA's
certificate.
