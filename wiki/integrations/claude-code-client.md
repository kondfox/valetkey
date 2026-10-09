# Claude Code as MCP client

How Claude Code starts and talks to valetkey's MCP server, and the hooks and config files around
it. Verified 2026-10-04 with headless runs (`claude -p`) of Claude Code 2.1.289 on macOS, using a
dummy MCP server that logged its environment and the client's messages. Project, `--mcp-config`
and plugin scopes were tested; **user and local scope were not** (testing them would have meant
changing the real user config).

## What we rely on

| Claim | Verified |
|---|---|
| MCP stdio servers run **outside** the sandbox (the dummy read deny-read decoys) | experiment |
| `CLAUDE_PROJECT_DIR` is set for stdio servers and equals the **realpath of the launch dir**, not the repo root. Launched in a subdir → that subdir; in a git worktree → the worktree | experiment |
| `clientInfo` = `{"name":"claude-code","title":"Claude Code","version":"2.1.289"}`, protocol `2025-11-25`, capabilities `roots` (listChanged) and `elicitation` (`form`, `url`) | experiment |
| Roots: first = realpath of the launch dir, then `--add-dir` dirs, then the logical (symlinked) path | experiment |
| A settings `env` block (project/local) reaches hooks **and every MCP server**, including `--mcp-config` ones: `PATH`, `SSL_CERT_FILE`, `NODE_OPTIONS`, proxies | experiment |
| Hooks run **unsandboxed**, with Claude Code's environment | experiment; docs (hooks) |
| Claude Code's own `git` calls (`status`, `log`, `ls-files`, `config`, `remote`, `check-ignore`) run unsandboxed and look `git` up through `PATH`; a fake `git` in a project dir on `PATH` ran with full access | experiment |

| **2.1.294** first sends a `server/discover` request with `io.modelcontextprotocol/protocolVersion` `2026-07-28` in `_meta`. A server that answers it with an empty result gets the usual `initialize` at protocol `2025-11-25` | experiment, 2026-10-08 (dummy stdio server, macOS) |

**Long tool calls** (relevant to [[sql-execute]], which waits up to 5 minutes):
- Docs, read 2026-10-08 (code.claude.com/docs/en/mcp and env-vars): stdio servers get a 30-minute
  idle window, reset by progress notifications (`CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT`). The hard
  per-call limit is about 28 hours (`MCP_TOOL_TIMEOUT`).
- Interactively, a call running over 2 minutes moves to a background task. An open elicitation
  dialog keeps it in the foreground.
- **UNVERIFIED on the real client.** The `claude -p` run on 2026-10-08 couldn't start (expired
  login). Unverified: the timeout, what Esc sends, and how the display-only elicitation looks.

## Quirks

- **Shadowing is silent.** Same server name in `.mcp.json` and `--mcp-config`: only the
  `--mcp-config` one starts, with no warning. A plugin server with the same name but a different
  command starts **alongside**, renamed `plugin:<plugin>:<name>`; with an identical command it's
  suppressed (debug log only). Docs give precedence local > project > user > plugin.
- **Elicitation can be answered by a hook.** In `-p` with no hook, an elicitation is answered
  `cancel`. A project-settings `Elicitation` hook auto-accepted with arbitrary content, even in an
  untrusted folder. Docs: `ElicitationResult` hooks can rewrite a human's answer. The same hook in
  skill frontmatter registered but didn't fire (don't rely on that). Interactive UX: **UNTESTED**.
  This is why valetkey approves writes out of band: [[2026-10-04-out-of-band-write-approval]].
- **Skill frontmatter** (`.claude/skills/*/SKILL.md`): `hooks` were registered with no trust prompt
  in an untrusted folder and ran unsandboxed. `allowed-tools: Write` let the Write tool write
  outside the project without a prompt; `allowed-tools` can pre-approve MCP tools.
- **Subagent frontmatter** (`.claude/agents/*.md`): `permissionMode: acceptEdits` was honoured (the
  subagent wrote where the main session couldn't). Its `hooks` and inline `mcpServers` were skipped
  in an untrusted folder; per the docs they run once the folder is trusted (**UNTESTED**).
- File tools in `-p`: default mode denies writes; protected paths (`.claude/skills|agents|commands`,
  `settings.local.json`, `.envrc`, `.git/hooks`) are refused as `safetyCheck` even in
  `acceptEdits`.
- The statusLine didn't run in `-p` (docs: it runs unsandboxed).

## Sources

- M0 Claude Code experiments, 2026-10-04 (decoy secrets only; harness not kept in the repo)
- Claude Code docs: sandboxing, hooks, mcp, skills, sub-agents, worktrees (read 2026-10-04)
- [[2026-10-04-m0-go-no-go]]
