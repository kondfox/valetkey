# The broker speaks MCP; isolation comes from a per-agent fence profile, Claude Code first

Date: 2026-10-04 · Status: Active

## Context
The tool should be independent of any one agent, and work with Claude Code, Cursor, Codex and
others.

## Options considered
- An agent-specific integration (a Claude Code plugin only)
- **MCP for the interface**, plus agent-specific fence profiles

## Decision
The broker is an MCP stdio server, which any MCP client can call. The fence is an agent-specific
**profile** (generate, detect, probe; `design.md §6.5`). Claude Code is the first profile. A client
without a profile runs in *unfenced mode*: only secrets the agent could read anyway are served
([[2026-10-04-secret-exposure-classification]]).

## Why
- MCP makes the **interface** agent-independent, but not the **isolation**. Isolation is each
  agent's own sandbox config, and those differ.
- Claude Code has an OS-enforced sandbox (Seatbelt on macOS, bubblewrap on Linux and WSL2) that can
  be configured from checked-in settings.

## Consequences
- The MCP server is registered at user scope, by absolute path, by `valetkey install`. There's no
  checked-in `.mcp.json` the agent could repoint (`design.md §6.3`).
- Adding Cursor or Codex support means writing a new fence profile, not changing the broker.

## Sources
- `docs/design.md` §1, §6.3–§6.5 (commit `6181a1d`)
- Design sessions on 2026-10-04 (private transcripts; summarized here).
