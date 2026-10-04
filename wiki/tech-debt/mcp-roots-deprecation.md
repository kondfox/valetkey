# The project-dir cross-check relies on deprecated MCP roots

Status: Open · Since: 2026-10-04 (M1)

**The debt.** The broker trusts `CLAUDE_PROJECT_DIR` only when it matches the client's first MCP
root (`docs/design.md §6.1`), because a settings `env` block can set the variable. MCP roots are
deprecated by SEP-2577, and `rmcp` 3.5 marks every roots API deprecated
([[rmcp]]). Claude Code 2.1.289 still sends them ([[claude-code-client]]).

**What happens if a client drops roots.** The check fails closed: `dir_verified` becomes false,
and protected targets are refused. Nothing leaks, but valetkey stops working for protected targets
on that client.

**Paying it down.** Find a replacement signal before roots disappear: e.g. whatever replaces
roots in the MCP spec, or a client-attested project directory. Re-check on every Claude Code and
`rmcp` upgrade.

Code: `crates/valetkey-mcp/src/lib.rs` (`first_root`, under `#[allow(deprecated)]`).
