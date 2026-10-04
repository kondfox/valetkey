# valetkey threat model

Status: draft, pre-M0. See [design.md](design.md) for the mechanisms referenced here.

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
| A3 | Read a keyring item (`security find-generic-password`, Secret Service over D-Bus) | Fence blocks keychain IPC. Where M0 can't confirm this, `keyring` counts as exposed on that platform (design §6.0). |
| A3b | Read a credential file in a non-default location (`GOOGLE_APPLICATION_CREDENTIALS`, `AWS_SHARED_CREDENTIALS_FILE`, a key inside the repo) or fetch a token from an instance-metadata endpoint | Credential locations resolved from the human's environment; `doctor` fails on credential files the fence leaves readable; metadata addresses always blocked |
| A4 | Mount the secrets through a container (`docker run -v ~/.config/gcloud:/x`) | Unix-socket connects denied by default, so the Docker and Podman sockets are unreachable |
| A4b | Run a command outside the sandbox through another local service (VM runtimes, tmux/screen servers, IDE helpers, launchd/systemd-user, Apple Events, Jupyter, VS Code server, sshd on localhost) | Default-deny for unix sockets; Mach/D-Bus job services blocked; executor token dirs and `~/.ssh` deny-read; localhost TCP limited to dev ports, or protected targets refused while a known executor listens. **Fail closed:** a block M0 can't confirm makes the platform unfenced (design §11). |
| A5 | Edit broker source so planted code runs with credentials | The broker is a release binary outside every repo, in a write-denied dir. Repo code never runs in the broker. |
| A6 | Replace or patch the installed binary | Install dir write-denied. `self-update` verifies signatures and is run by a human. |
| A7 | Repoint the MCP registration at its own script | Registration at user scope with a stable absolute path. Agent config is write-denied by the OS sandbox and by permission rules. No `PATH` lookup. |
| A7b | Shadow the user-scope server with a project-scoped server of the same name | `detect` flags it; protected targets are refused while it exists |
| A7c | Add hooks or MCP servers through project settings; they run outside the sandbox | Every agent config file that can define hooks, servers or permissions (design §6.5) is write-denied at the OS level too, not only by permission rules |
| A7d | Define hooks or permissions in editable agent config (skill or agent frontmatter) | Every file that can define hooks is OS write-denied (mandatory, design §6.5). The `detect` scan is a secondary check only. |
| A7e | Put a fake command on a `PATH` dir that unsandboxed hooks or the statusLine search (`node_modules/.bin`, direnv `PATH_add`) | The plugin hook uses an absolute path; a client `PATH` containing agent-writable dirs counts as unfenced |
| A8 | Edit `valetkey.toml` to add a target that leaks the secret | The broker serves only a human-approved snapshot, bound to the canonical project root. The approvals dir is write-denied. |
| A8b | Make the unfenced broker read a fenced file for it (env-file path with `..`, an absolute path, a symlink, or `~` through a spoofed `HOME`) | env-file paths confined to the project root, symlinks refused, `~` from the OS user database; resolved paths shown in `allow` |
| A9a | Connect straight to the protected proxy socket, which may authenticate by itself (IAM auth, a tunnel to a trust-auth database) | Connects to the sockets dir denied; self-authenticating channels refused until that deny is verified; `doctor` warns about TCP listeners for the same instance |
| A9b | Squat a local port with a certificate issued by a locally held trusted CA key (mkcert), or move a target's DNS onto a local address | Protected secrets to local addresses (loopback and this machine's interfaces, checked on the resolved address at each connect) go only through the sockets dir; local CA keys deny-read; optional pinning |
| A9 | Squat a local port and play a fake server to capture a password | Protected secrets travel only over write-denied unix sockets or verified TLS, **whatever the host**. Plain TCP only for exposed secrets. Cleartext/MD5 auth refused (M0 item 2). |
| A10 | Write through a "read" (`COMMIT; DELETE …`, `SET TRANSACTION READ WRITE`) | Extended protocol only (single statement), `BEGIN READ ONLY`, `default_transaction_read_only=on`. Tested against real Postgres. |
| A11 | Escape read-only through extensions (`dblink`, `postgres_fdw`, `pg_background`, `pg_net`, …), `COPY … TO PROGRAM`, untrusted-language functions, or a superuser role | Protected targets refused unless every extension is allow-listed and the role holds none of those privileges |
| A12 | Write without consent (`allow_write: true` is set by the agent) | `writable` target flag plus per-call human approval through elicitation. Skipped only for targets the agent could reach without valetkey anyway. |
| A12b | Mislead the human in the approval prompt (a long statement whose tail is hidden, a persuasive "reason") | The broker builds the whole prompt: verified identity, full statement or a marked truncation plus hash, no agent free text. Timeout means deny. |
| A13 | Exhaust memory or hold locks | Streamed row cap, byte cap, `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout` |
| A14 | Extract a secret from error messages or logs | `SecretString` everywhere; stderr redacted and capped; secrets never logged or audited |
| A15 | Weaken its own fence (edit `.claude/settings.json`, retry unsandboxed), or fake the `doctor --fence` output | OS and permission write-denies on agent config; unsandboxed commands disabled; the probe is never used as a gate. Managed settings make this hard rather than best-effort. |
| A16 | Use an unfenced client or platform to reach protected targets | Unfenced mode (`require_fence = true` by default) |
| A17 | Hang the broker through an interactive CLI prompt | Non-interactive flags, timeouts, kill on drop |
| A18 | Tamper with the audit log | Audit and log dirs write-denied (OS and permission rules) |
| A19 | Plant code that a human's credentialed terminal runs later (git hooks including `core.hooksPath`/husky, `.git/config`, worktree and submodule git dirs, `.envrc`, mise, venv `activate`, VS Code tasks, the valetkey Homebrew tap) | Resolved and detected paths write-denied (OS and permission rules); the sandbox write scope is limited to the project and temp. The rest of the class is a residual risk, below. |
| A19b | Plant a fake `valetkey` earlier on the human's `PATH`, so `install` copies it into the protected dir | Only the installed copy installs new binaries (`<installed>/valetkey install --from`), after a signature check; hints always use the absolute path; first install is trust-on-first-use |
| A19c | Swap `valetkey.toml` between the human reading the `allow` diff and confirming | `allow` stores exactly the config it displayed and never re-reads |
| A20 | Hide a change from the human with control characters, ANSI escapes or bidi overrides in the approval prompt or the `allow` diff | All displayed text sanitized; non-ASCII identifiers flagged |

## Residual risks (accepted, documented)

- **Readable local secrets.** Anything the project leaves readable, such as `.env` files, stays
  readable. valetkey protects only what the fence denies.
- **Role privileges.** Reads run with the configured role's privileges. A read-only transaction
  can still take advisory locks, call `pg_terminate_backend`/`pg_cancel_backend` (with enough
  privilege), `pg_notify`, or advance sequences. Only a least-privilege role per target closes
  this; `doctor` warns about powerful roles.
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
