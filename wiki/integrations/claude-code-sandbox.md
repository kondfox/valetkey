# Claude Code sandbox

Claude Code runs the agent's Bash commands (and everything they start) inside an OS sandbox:
Seatbelt on macOS, bubblewrap plus seccomp on Linux and WSL2. It's built on the open-source
`@anthropic-ai/sandbox-runtime` (CLI `srt`), so `srt` reproduces it for testing; Claude Code adds
its own write protections on top. Everything below was verified on 2026-10-04 with sandbox runtime
0.0.78 and Claude Code 2.1.289, on macOS 26.2/26.6 (arm64) and Ubuntu 24.04 (bubblewrap 0.9.0).

## What we rely on

| Claim | Verified |
|---|---|
| Deny-read applies to every child process (`cat`, `python3`, `node`, `cp`, nested shells, symlink and hardlink aliases) | spike probes, macOS + Linux |
| Unix-socket connects are denied by default. macOS allows per-path exceptions (`allowUnixSockets`; symlinks and `..` resolved). Linux ignores `allowUnixSockets`: seccomp blocks every `socket(AF_UNIX)` unless `allowAllUnixSockets` is set | spike probes |
| **`allowAllUnixSockets` on Linux is a full escape**: it opens the session D-Bus, and `busctl … StartTransientUnit` ran a payload outside the sandbox | spike probes, CI run 37221248457 |
| Abstract unix sockets stay unreachable on Linux even with `allowAllUnixSockets` (separate network namespace) | spike probes |
| macOS: `launchctl submit`/`bootstrap`, `open x.command` and `osascript` to Terminal / System Events are blocked (`allowAppleEvents` off by default) | spike probes (osascript locally only: CI can't grant TCC consent) |
| With `network.allowedDomains` set, raw IPs and `169.254.169.254` are blocked; HTTP through the proxy gets 403. **Without** `allowedDomains`, library embedders get unrestricted network (the Linux CI runner reached Azure's metadata endpoint) | spike probes |
| localhost TCP: Linux has its own network namespace, so host loopback is unreachable and in-sandbox listeners can't be reached from the host (no port squatting). macOS blocks raw loopback connects and binds by default; **`allowLocalBinding` opens every loopback port** and lets the host reach an in-sandbox listener. Per-port access works through the proxy (`allowedDomains: ["127.0.0.1:<port>"]`) | spike probes |
| Deny-write on symlinks: macOS matches the literal path (deny the link and the write-through to the target still succeeds); Linux matches the resolved path (the link itself can always be replaced). **Denying the parent directory** protects both, on both platforms | spike probes |
| Claude Code's default write scope for sandboxed commands: project dir, its sandbox temp dir (`/tmp/claude-<uid>`, shared by all sessions of that user), added dirs, `allowWrite`. Standalone `srt` defaults differ (`/tmp/claude`, `~/.npm/_logs`, `~/.claude/debug`) | Claude Code experiments + spike probes; home dir outside the project not measured |
| Claude Code write-protects by default: `.claude/settings*.json`, `.claude/{skills,agents,commands,hooks}/**`, `.mcp.json`, `.git/config`, `.git/hooks/*`, `.vscode/**`. **Not** protected: `.envrc`, `.gitignore`, `.husky*` | Claude Code experiments |
| The sandbox governs the shell only. Read/Edit/Write tools follow **permission rules**: `denyRead` doesn't stop the Read tool; a `Read(...)` deny rule does | Claude Code experiments; docs (sandboxing) |

## Quirks

- **macOS keychain is readable.** The Seatbelt profile always allows the Mach service
  `com.apple.SecurityServer`, and a sandboxed `security find-generic-password -w` read a test item.
  There's no setting that removes a Mach service (`allowMachLookup` only adds). `denyRead:
  ["~/Library/Keychains"]` blocks file-based keychains but breaks every keychain user in the
  sandbox (`gh`, git credential helpers). Data-protection keychain items: **UNTESTED**. See
  [[2026-10-04-local-secret-store]].
- Ubuntu 24.04 restricts unprivileged user namespaces, so bubblewrap fails until
  `sysctl kernel.apparmor_restrict_unprivileged_userns=0` ([[github-actions]]).
- On Linux, `srt` can't create `/tmp/claude` itself; the embedder must create it. `mkdir -p
  .git/hooks` succeeds if `.git` didn't exist when the sandbox started.
- The `srt` CLI refuses a config without `network.allowedDomains`; the library accepts it and
  allows all network.
- A repo's `.claude/settings.json` can enable `allowAllUnixSockets` and `allowLocalBinding` unless
  managed settings forbid it (docs). valetkey's `detect` treats both as described in
  `docs/design.md §6.4`.

**UNTESTED:** Podman socket, Docker with a live daemon on Linux, a real Secret Service
(gnome-keyring) on Linux.

## Sources

- Spike branch `spike/m0` (`spike/sandbox-probes/`, ~120 cases, decoy secrets only), commit
  `a0f1593`; CI run https://github.com/kondfox/valetkey/actions/runs/37221248457
- Claude Code sandboxing docs (code.claude.com/docs/en/sandboxing), read 2026-10-04
- [[2026-10-04-m0-go-no-go]]
