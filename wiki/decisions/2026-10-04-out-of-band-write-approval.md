# Writes are approved with `valetkey approve <id>` in a terminal, not through MCP elicitation

Date: 2026-10-04 · Status: Active

## Context
The design approved each protected write through MCP elicitation. M0 showed that a project-settings
`Elicitation` hook auto-accepted the request before any human saw it, even in an untrusted folder,
and the docs say an `ElicitationResult` hook can rewrite a human's answer. Hooks passed with
`--settings` or by SDK hosts can't even be detected ([[claude-code-client]]). Under the go/no-go
table, writes would have had to be refused on Claude Code altogether.

## Options considered
1. **Out of band:** the broker waits for a human to run `valetkey approve <id>` in a normal
   terminal.
2. An OS-native dialog from the broker (`osascript`, `zenity`): more convenient, but nothing
   reliable on WSL2 or headless machines, and an agent with computer-use tools could click it.
3. Both, with more code paths to secure.

## Decision
Option 1, chosen by the maintainer on 2026-10-04 (`docs/design.md §6.10`):
- The broker writes the fully rendered request and its hash to `~/.valetkey/pending/<id>.json`.
  The hash binds project, target, verified identity, statement, parameters, a nonce and an expiry.
  IDs are a counter plus a random suffix and are never reused.
- It tells the agent, and shows the human through elicitation **as display only**: "run
  `valetkey approve <id>`". An elicitation response never approves anything.
- `valetkey approve <id>` shows the request and, on confirmation of that one ID, writes
  `~/.valetkey/write-approvals/<id>` with the hash.
- The broker closes its connection while waiting, then reconnects, re-verifies the identity and
  executes only on a matching hash and an unused, unexpired nonce. It denies on timeout (default
  5 min), mismatch or error.
- One outstanding request per target per session, so the agent can't flood the human.

## Why
- The approval is a file in a dir the agent can't write: OS-level deny for its shell, a
  permission deny for its file tools. A `valetkey approve` run inside the sandbox fails, and so
  does a human's `! valetkey approve` in Claude Code. The agent can't add hooks, because settings
  and agent config are write-protected.
- It needs no GUI and works the same on macOS, Linux and WSL2.
- It's agent-independent: any MCP client gets the same guarantee.

## Consequences
- Each protected write costs the human a terminal step. Writes to targets the agent could reach
  on its own stay prompt-free ([[2026-10-04-write-approval-scope]]).
- `detect` flags hook commands that mention `valetkey`, as a hint only (easy to evade).
- `rmcp`'s elicitation feature is used only for display ([[rmcp]]).

## Sources
- [[claude-code-client]] (elicitation tests); [[2026-10-04-m0-go-no-go]]
