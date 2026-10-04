# valetkey threat model

Status: updated with M0 results (2026-10-04). See [design.md](design.md) for the mechanisms referenced here.

## Assets

- Credentials for deployed resources: database passwords, API tokens, OAuth keys, and the
  developer's cloud login (gcloud ADC, AWS SSO cache, …) that can fetch them.
- The integrity of deployed data, where writes are allowed.

## Adversary

The AI agent, assumed hostile. It may be prompt-injected through a file, web page, issue or query
result, or simply wrong. It can:
- run arbitrary commands inside its sandbox, as the developer's OS user
- read and edit the repository, through its shell and its file tools
- call every MCP tool it's offered, with any arguments
- bind local TCP ports and start long-running processes
- reach the network domains on the allowlist

Out of scope: a compromised developer machine, a malicious human developer, a compromised
valetkey release, the agent client itself being compromised.

## Trust zones

| Zone | Runs | Can read secrets? |
|---|---|---|
| Agent sandbox | the agent's shell and everything it starts | **no**: the fence |
| Agent client | e.g. Claude Code; file tools are governed by its permission rules | not via its tools: deny rules |
| Broker | `valetkey mcp`, started by the client, outside the sandbox | yes, at call time |
| Human terminal | `valetkey allow`, `install`, `self-update`, proxies | yes |

## Attacks and mitigations

| # | Attack | Mitigation |
|---|---|---|
| A1 | Read the cloud login or vault cache files directly (`cat`, `node -e`, `python`) | Fence deny-read, derived from each `SecretSource::fence()`. Enforced by the OS for every child process. |
| A1b | Read the same files with the agent's file tools, which the OS sandbox doesn't govern | A permission `Read`/`Edit` deny for every OS-denied path (design §6.5) |
| A2 | Ask the vendor CLI for the secret (`gcloud secrets versions access`) | Same: the CLI has no readable credentials inside the sandbox |
| A3 | Read a keyring item (`security find-generic-password`, Secret Service over D-Bus) | macOS: **not blockable** without breaking other tools (M0 read a test item from the sandbox), so `keyring` counts as exposed there, and protected local secrets use `local://` (a deny-read file store). Linux: D-Bus blocked while unix sockets are fully denied. |
| A3b | Read a credential file in a non-default location (`GOOGLE_APPLICATION_CREDENTIALS`, `AWS_SHARED_CREDENTIALS_FILE`, a key inside the repo) or fetch a token from an instance-metadata endpoint | Credential locations resolved from the human's environment; `doctor` fails on credential files the fence leaves readable; metadata addresses always blocked |
| A4 | Mount the secrets through a container (`docker run -v ~/.config/gcloud:/x`) | Unix-socket connects denied by default, so the Docker and Podman sockets are unreachable |
| A4b | Run a command outside the sandbox through another local service (VM runtimes, tmux/screen servers, IDE helpers, launchd/systemd-user, Apple Events, Jupyter, VS Code server, sshd on localhost) | Default-deny for unix sockets; Mach/D-Bus job services blocked; executor token dirs and `~/.ssh` deny-read; localhost TCP limited to dev ports, or protected targets refused while a known executor listens. **Fail closed:** a block M0 can't confirm makes the platform unfenced (design §11). |
| A5 | Edit broker source so planted code runs with credentials | The broker is a release binary outside every repo, in a write-denied dir. Repo code never runs in the broker. |
| A6 | Replace or patch the installed binary | Install dir write-denied. `self-update` verifies signatures and is run by a human. |
| A7 | Repoint the MCP registration at its own script | Registration at user scope with a stable absolute path. Agent config is write-denied by the OS sandbox and by permission rules. No `PATH` lookup. |
| A7b | Shadow the registered server with another server of the same name (`.mcp.json`, `--mcp-config`, local scope, plugin) | `.mcp.json` and agent config are write-protected. A shadowed broker never starts, so detection runs in the plugin's `SessionStart` hook and `doctor`, not in the broker. Plugin copies run alongside under renamed tool names; `doctor` flags them. |
| A7c | Add hooks or MCP servers through project settings; they run outside the sandbox | Every agent config file that can define hooks, servers or permissions (design §6.5) is write-denied at the OS level too, not only by permission rules |
| A7d | Define hooks or permissions in editable agent config (skill or agent frontmatter) | Every file that can define hooks is OS write-denied (mandatory, design §6.5). The `detect` scan is a secondary check only. |
| A7e | Put a fake command on a `PATH` dir that unsandboxed code searches: hooks, the statusLine, and Claude Code's own `git` calls (M0: a fake `git` ran with full access) | The plugin hook uses an absolute path; a client `PATH` containing agent-writable dirs, or `PATH` set in a settings `env` block, counts as unfenced |
| A7f | Change the broker's environment through a settings `env` block (`PATH`, `SSL_CERT_FILE`, `NODE_OPTIONS`, proxies), which reaches every MCP server | The broker keeps an environment allowlist, uses a fixed `PATH` with absolute CLI paths, and takes TLS/proxy settings only from user-level valetkey config |
| A7g | Point the broker somewhere else through a settings `env` block: `HOME` (moving `~/.valetkey/` out of the fence) or `CLAUDE_PROJECT_DIR` (another project's snapshot) | The valetkey root comes from the OS user database, never `HOME`. `CLAUDE_PROJECT_DIR` must match the client's first MCP root. Either variable in a settings `env` block → protected targets refused. |
| A7h | Get a **debug build** registered as the broker, then move its root with `VALETKEY_DEV_ROOT` through a settings `env` block | Only debug builds read the variable; releases (what installers ship and `install` registers) ignore it. `doctor` warns when it runs as a debug build. |
| A8 | Edit `valetkey.toml` to add a target that leaks the secret | The broker serves only a human-approved snapshot (`~/.valetkey/projects/<project-key>/`), bound to the canonical project root. The whole valetkey root is write-denied. |
| A8b | Make the unfenced broker read a fenced file for it (env-file path with `..`, an absolute path, a symlink, or `~` through a spoofed `HOME`) | env-file paths confined to the project root, symlinks refused, `~` from the OS user database; resolved paths shown in `allow` |
| A8c | Swap `valetkey.toml` for a symlink, hard link or FIFO between the broker's checks and its read, so the broker reads (and echoes) a fenced file or hangs | Opened without following links or blocking; checked on the handle (regular, own user, one link, size cap); parse errors never reach the agent |
| A9a | Connect straight to the protected proxy socket, which may authenticate by itself (IAM auth, a tunnel to a trust-auth database) | Connects to the sockets dir denied; self-authenticating channels refused until that deny is verified; `doctor` warns about TCP listeners for the same instance |
| A9b | Squat a local port with a certificate issued by a locally held trusted CA key (mkcert), or move a target's DNS onto a local address | Protected secrets to local addresses (loopback and this machine's interfaces, checked on the resolved address at each connect) go only through the sockets dir; local CA keys deny-read; optional pinning |
| A9 | Squat a local port and play a fake server to capture a password | Protected secrets travel only over write-denied unix sockets or verified TLS, **whatever the host**. Plain TCP only for exposed secrets. Cleartext/MD5 auth refused (M0 item 2). |
| A10 | Write through a "read": `COMMIT; DELETE …`; `SET TRANSACTION READ WRITE` as the first statement; `DO $$ … COMMIT … $$` | Extended protocol only (single statement); `BEGIN READ ONLY` **and** `default_transaction_read_only=on`; the broker's own identity query runs first inside the transaction, which locks it read-only; reads always `ROLLBACK`. Each escape reproduced and blocked against real Postgres in M0. |
| A11 | Escape read-only through extensions (`dblink`, `postgres_fdw` remote views, `pg_background`, `http`, …), `COPY … TO PROGRAM`/`TO file`, untrusted-language or privileged `SECURITY DEFINER` functions (including user-made `internal` wrappers), re-granted built-ins (`pg_read_file`, `lo_export`), or a superuser role | Protected targets refused unless: every extension is allow-listed; the role holds none of the server-file/program roles; catalog queries B and C find no executable dangerous function. All confirmed as real escapes in M0. |
| A12 | Write without consent (`allow_write: true` is set by the agent) | `writable` target flag plus out-of-band human approval (`valetkey approve` in a terminal). Skipped only for targets the agent could reach without valetkey anyway. |
| A12b | Mislead the human in the approval prompt (a long statement whose tail is hidden, a persuasive "reason") | The broker builds the whole prompt: verified identity, full statement or a marked truncation plus hash, no agent free text. Timeout means deny. |
| A12c | Auto-approve through the client: an `Elicitation` hook accepting the request, or an `ElicitationResult` hook rewriting the human's answer (both work, M0) | Elicitation is display-only. Approval is a file in `~/.valetkey/write-approvals/`, bound by hash to one exact request (project-key, target, identity, statement, parameters, nonce, expiry), which the agent can't write from its shell or file tools, and settings that could add hooks are write-protected. |
| A12d | Flood the human with pending write requests until one gets approved by mistake | One outstanding request per target per session; `approve` shows project, target, session and age, and confirms one ID at a time |
| A13 | Exhaust memory or hold locks | Streamed row cap, byte cap, `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout` |
| A14 | Extract a secret from error messages or logs | `SecretString` everywhere; stderr redacted and capped; secrets never logged or audited |
| A15 | Weaken its own fence (edit `.claude/settings.json`, retry unsandboxed), or fake the `doctor --fence` output | OS and permission write-denies on agent config; unsandboxed commands disabled; the probe is never used as a gate. Managed settings make this hard rather than best-effort. |
| A16 | Use an unfenced client or platform to reach protected targets | Unfenced mode (`require_fence = true` by default) |
| A17 | Hang the broker through an interactive CLI prompt | Non-interactive flags, timeouts, kill on drop |
| A17b | Make a vendor CLI misbehave from the broker: an injected env var, a planted `gcloud` or Python on `PATH`, a hanging or output-flooding child, a grandchild that outlives the call | Fixed environment (nothing inherited), tool and interpreter paths only from human-approved `setup` (trust-checked), argv only, stdin closed, timeout and drop kill the whole process group, stdout over its cap kills the process (no truncated secrets) |
| A17c | Reuse a cached secret after the approval changed, or skip policy through the cache | The cache key includes the config hash; the broker checks policy before every cache lookup; failures aren't cached |
| A18 | Tamper with the audit log | Audit and log dirs write-denied (OS and permission rules) |
| A19 | Plant code that a human's credentialed terminal runs later (git hooks including `core.hooksPath`/husky, `.git/config`, worktree and submodule git dirs, `.envrc`, mise, venv `activate`, VS Code tasks, the valetkey Homebrew tap) | Resolved and detected paths write-denied (OS and permission rules); the sandbox write scope is limited to the project and temp. The rest of the class is a residual risk, below. |
| A19b | Plant a fake `valetkey` earlier on the human's `PATH`, so `install` copies it into the protected dir | Only the installed copy installs new binaries (`<installed>/valetkey install --from`), after a signature check; hints always use the absolute path; first install is trust-on-first-use |
| A19c | Swap `valetkey.toml` between the human reading the `allow` diff and confirming | `allow` stores exactly the config it displayed and never re-reads |
| A20 | Hide a change from the human with control characters, ANSI escapes or bidi overrides in the approval prompt or the `allow` diff | All displayed text sanitized; non-ASCII identifiers flagged |

## Residual risks (accepted, documented)

- **Readable local secrets.** Anything the project leaves readable, such as `.env` files, stays
  readable. valetkey protects only what the fence denies.
- **Role privileges.** Reads run with the configured role's privileges. A read-only transaction
  can still take advisory locks (released when the per-call connection closes) and call
  `pg_cancel_backend`/`pg_terminate_backend` against **any session of the same role** (M0). Only a
  dedicated role per target, never shared with the application, closes this. `doctor` warns when
  other sessions use the role. (`pg_notify` is discarded by the `ROLLBACK`; sequences are blocked.)
- **Hidden extension members.** A superuser of the target database can `ALTER EXTENSION … ADD
  FUNCTION` to hide a dangerous function inside an allow-listed extension. The target's admin is
  trusted.
- **Shared sandbox temp dir.** Every Claude Code session of the same user shares the sandbox temp
  dir, so one session's agent can change another session's scratch files.
- **macOS keychain.** Secrets the developer keeps in the macOS keychain (including those of other
  tools) are readable from the sandbox. valetkey doesn't use the keychain for protected secrets,
  but can't protect other tools' items.
- **Copies inside libraries.** The database driver keeps the password in an ordinary buffer for
  the length of a connect. The broker keeps that window short; it can't zeroize the library's
  copies.
- **Detection blind spots.** `detect` reads settings files. It can't see command-line flags or
  environment overrides the session was started with.
- **Denial of service.** The agent can stop a human-started proxy, or toggle `valetkey.toml` so
  every call fails. Either interrupts access but exposes no secret.
- **Code the human runs later.** Package scripts, Makefiles, editor tasks, test files: anything
  in the repo that a human executes in a terminal that can read secrets. valetkey write-protects
  the paths that run *automatically* (A19). For the rest: review agent changes before running
  repo scripts in a credentialed shell.
- **Project-local `PATH` entries.** If a project dir is on the human's `PATH`, every command the
  human types can run planted code. `doctor` flags this; valetkey can't prevent it.
- **First install** is trust-on-first-use.
- **Unknown local executors on TCP.** valetkey recognizes known command executors (Jupyter, VS
  Code server, sshd). An unrecognized local service that runs commands remains a risk when the
  sandbox can't limit localhost TCP. `doctor` lists every listener it finds.
- **Hook environment.** If Claude Code runs hooks with a different `PATH` than the broker sees,
  the broker can only rely on the plugin hook's report, which is a hint.
- **Fence correctness depends on the agent client.** Without managed settings, a mistake in
  project or user settings can weaken the fence. Unfenced mode catches the common cases, not all
  of them.
- **Data exposure.** Query results reach the agent by design. Limit what each target's role can
  see.
- **Native Windows** has no sandbox. Deployed targets require WSL2.
