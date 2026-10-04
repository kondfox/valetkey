# rmcp (Rust MCP SDK)

valetkey's MCP server is built on `rmcp`. Verified by reading the 3.5.0 source on 2026-10-04.

## What we rely on

- **clientInfo**: `context.peer.peer_info()` → `InitializeRequestParams.client_info` (`name`,
  `version`, …) (`src/service.rs:1029-1031`, `src/model.rs:1081,1525-1535`). Used to pick the fence
  profile; Claude Code sends `name = "claude-code"` ([[claude-code-client]]).
- **stdio transport** is just `(tokio::io::stdin(), tokio::io::stdout())`
  (`src/transport/io.rs:4-6`); no library code writes to stdout outside tests. valetkey must log to
  a file or stderr, never stdout.
- **Elicitation** (used only to *display* approval instructions,
  [[2026-10-04-out-of-band-write-approval]]): `peer.elicit::<T>()` / `create_elicitation()`, feature
  `elicitation` (off by default) (`src/service/server.rs:896-911,1143-1149`). Capability check:
  `peer.supported_elicitation_modes()`. The raw `create_elicitation` doesn't check the capability.

## Quirks

- For clients on protocol ≥ `2026-07-28`, elicitation and roots requests must be sent from inside a
  request handler's scope (task-local; doesn't survive `tokio::spawn`)
  (`src/service/server.rs:54-77`, `src/service.rs:250-252,871-885`).
- **Roots are deprecated** (`list_roots` deprecated since 1.8.0, SEP-2577). valetkey finds the
  project through `CLAUDE_PROJECT_DIR` first.
- If the app installs a `tracing_subscriber::fmt` layer with the default writer, logs go to stdout
  and corrupt the protocol (**UNVERIFIED** default; configure the writer explicitly).

## Sources

- `rmcp` 3.5.0 crate source (crates.io), read 2026-10-04
