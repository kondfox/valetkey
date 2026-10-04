# The project is named valetkey

Date: 2026-10-04 · Status: Active

## Context
The tool generalizes an earlier project-specific "agent gateway" prototype into something any
project can use, for any kind of resource. The name shouldn't mention a database or a specific
agent.

## Options considered
`valetkey`, `keyward`, `agentgate`, `escrow`, `keyless`. Also `glovebox` and `valet`, both already
taken on crates.io (`valet` would also clash with Laravel Valet).

## Decision
`valetkey`.

## Why
- A car's valet key lets the attendant drive but not open the trunk: scoped use without the master
  key. The name is the security model.
- "Valet Key" is also an established cloud design pattern for scoped access tokens, so the name
  explains itself to people who know the pattern.
- The name was free on crates.io (checked 2026-10-04). The CLI reads well: `valetkey init`,
  `valetkey allow`, `valetkey doctor`.

## Consequences
- Binary, crate prefix (`valetkey-*`) and the MCP server name are all `valetkey`. The server name
  matters for shadowing detection (`design.md §6.3`).

## Sources
- crates.io API, checked 2026-10-04
- Design sessions on 2026-10-04 (private transcripts; summarized here).
