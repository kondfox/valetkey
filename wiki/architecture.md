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
2. **Immutable binary:** a signed release, copied by `valetkey install` into the write-denied
   valetkey root (`~/.valetkey/bin/`, [[2026-10-04-valetkey-root-dir]]) and registered by
   absolute path. See [[2026-10-04-binary-provenance-and-registration]].
3. **Fence:** the agent's OS sandbox plus permission rules, generated from the project's config.
   See [[2026-10-04-mcp-interface-per-agent-fence]] and
   [[2026-10-04-fail-closed-fence-capabilities]].

Why all three are needed: [[2026-10-04-credential-broker-pattern]].

## A tool call, end to end

`design.md §6.7`:
1. Load the approved snapshot ([[2026-10-04-human-approved-config-snapshot]])
2. Apply policy: exposure, `writable`, fence state ([[2026-10-04-secret-exposure-classification]])
3. Approval, for writes that need it: `valetkey approve <id>` in a terminal
   ([[2026-10-04-write-approval-scope]], [[2026-10-04-out-of-band-write-approval]])
4. Fetch the secret ([[2026-10-04-vendor-clis-for-secret-sources]])
5. Execute under limits ([[2026-10-04-postgres-read-only-guards]])
6. Serialize and audit

## Code layout

Cargo workspace (`docs/design.md §4`). Crates appear with the milestone that needs them:

| Crate | Holds | May import |
|---|---|---|
| `valetkey-core` | config model, secret references, project identity, snapshots, diff, sanitizing | no vendor libraries |
| `valetkey-postgres` | the Postgres target kind (M1: config only; driver in M2) | `tokio-postgres` (M2), only here |
| `valetkey-mcp` | the broker (MCP server) | `rmcp`, only here |
| `valetkey-cli` | the `valetkey` binary; the **only** composition root | everything |

`deny.toml` enforces the "only here" column with `cargo-deny` ban wrappers.

## Worked example: one `valetkey_targets` call

The template for every later tool. Lines are as of the M1 commit.

1. **Startup.** Claude Code runs `valetkey mcp`. `commands/mcp.rs:13` resolves the valetkey root from
   the OS user database (`valetkey-core/src/paths.rs:34`, never `HOME`). It logs to
   `~/.valetkey/logs/mcp.log`, because stdout belongs to MCP (`mcp.rs:34`). It captures
   `CLAUDE_PROJECT_DIR` as **untrusted** (`mcp.rs:18`). It wires the composition root, the target
   kinds the build supports, in `main.rs:35`, and serves (`mcp.rs:28`).
2. **Tool call.** `valetkey-mcp/src/lib.rs:72` receives `valetkey_targets` with the client's
   `Peer`.
3. **Project directory, cross-checked.** `targets_report` (`lib.rs:131`) asks the client for its
   MCP roots (`first_root`, `lib.rs:304`) and compares the first one with `CLAUDE_PROJECT_DIR`
   (`lib.rs:135`). A mismatch, or no roots, means *unverified*, and protected targets are refused.
4. **Project.** `project::discover` (`valetkey-core/src/project.rs:66`) walks up to the first
   `valetkey.toml`, refusing symlinks on the way, and derives the project key
   (`project.rs:19`).
5. **Approval.** `approval_state` (`lib.rs:247`) reads the working file without following links
   (`valetkey-core/src/safe_read.rs`) and parses it through the registry (`config.rs:184`; each
   kind normalizes its own table, e.g. `valetkey-postgres/src/lib.rs:50`). It then loads the
   snapshot, which checks its own consistency (`snapshot.rs:66`), and compares canonical hashes
   (`snapshot.rs:140`, `config.rs:144`). Only an approved, unchanged snapshot is served. Read and
   parse errors go to the log, never to the agent.
6. **Answer.** Each approved target is reported with its exposure, recomputed per call
   (`secret_ref.rs:63`), and why it isn't usable yet. Nothing secret is ever read.

A new tool follows the same path. Step 6 is replaced by the adapter call, and the snapshot is the
only config it may use.
