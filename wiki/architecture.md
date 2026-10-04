# Architecture

valetkey lets an AI agent **use** a credential without being able to **read** it. The full spec is
`docs/design.md`. This page is the short version, plus the rationale links.

## Three parts, three trust zones

```
 agent's sandbox (fence)          agent client             outside the sandbox
┌──────────────────────┐   ┌─────────────────────┐   ┌──────────────────────────┐
│ shell, child procs   │   │ Claude Code         │   │ valetkey mcp  (broker)   │
│ ✘ secret stores      │──▶│ file tools: perm.   │──▶│ ✔ fetches secret at call │
│ ✘ broker / approvals │   │ rules; MCP client   │   │ ✔ approved snapshot only │
│ ✘ protected sockets  │   └─────────────────────┘   │ ✔ protected channel only │
└──────────────────────┘                             └────────────┬─────────────┘
                                                                  ▼
                                                     database / API / vault CLI
```

1. **Broker:** `valetkey mcp`, started by the client outside the sandbox. It exposes only scoped
   tools (`sql_query`, `sql_execute`, `http_request`, …).
2. **Immutable binary:** a signed release, copied by `valetkey install` into a write-denied dir and
   registered by absolute path. See [[2026-10-04-binary-provenance-and-registration]].
3. **Fence:** the agent's OS sandbox plus permission rules, generated from the project's config.
   See [[2026-10-04-mcp-interface-per-agent-fence]] and
   [[2026-10-04-fail-closed-fence-capabilities]].

Why all three are needed: [[2026-10-04-credential-broker-pattern]].

## A tool call, end to end

`design.md §6.7`:
1. Load the approved snapshot ([[2026-10-04-human-approved-config-snapshot]])
2. Apply policy: exposure, `writable`, fence state ([[2026-10-04-secret-exposure-classification]])
3. Approval, for writes that need it ([[2026-10-04-write-approval-scope]])
4. Fetch the secret ([[2026-10-04-vendor-clis-for-secret-sources]])
5. Execute under limits ([[2026-10-04-postgres-read-only-guards]])
6. Serialize and audit

## Code layout

Planned Cargo workspace: `design.md §4`. **No code exists yet.** When M1 lands, this page gets the
worked end-to-end example the seed requires: one MCP call traced through
`valetkey-mcp` → `valetkey-core` → `valetkey-secrets` → `valetkey-postgres`, with `file:line`
links. That example becomes the template for new adapters and sources.
