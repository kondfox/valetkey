# valetkey design

Status: draft, pre-M0. Companion document: [threat-model.md](threat-model.md).

## 1. What valetkey is

valetkey lets an AI coding agent **use** credentials without being able to **read** them.

A valet key lets a parking attendant drive your car, but it won't open the trunk or the glovebox.
valetkey gives an agent the same kind of narrow capability: "run a read-only query on the staging
database" or "GET this Salesforce endpoint", but never the password or token behind it.

A tool can't hide secrets from an agent that has a shell and runs as the same OS user. Isolation
takes three parts, and valetkey provides or configures all three:

1. **Broker.** `valetkey mcp` is an MCP stdio server. The agent's client starts it **outside**
   the agent's sandbox. It fetches secrets at call time and exposes only scoped operations.
2. **Immutable binary.** A signed release binary installed outside every repository, in a location
   the agent can't write. Repo code the agent edits never runs with credentials.
3. **Fence.** The agent's own OS-enforced sandbox (Claude Code: Seatbelt on macOS, bubblewrap on
   Linux/WSL2). It's configured so the agent can't read secret stores, alter the broker or its
   approvals, or impersonate a server the broker talks to. `valetkey init` generates this config.

The broker is agent-agnostic, because any MCP client can call it. The fence is agent-specific.
Claude Code is the first fence profile. Clients without a profile get **unfenced mode** (§6.4).

### Non-goals (v1)

- Starting proxies or tunnels (Cloud SQL Auth Proxy, SSH, `kubectl port-forward`). A human starts
  them. `valetkey up` is planned for v2, and v1 keeps the seam open (§7).
- Protecting secrets the project already leaves readable, such as local `.env` files. valetkey
  documents this risk; it doesn't solve it.
- Being a secret manager. valetkey stores nothing except the optional OS-keyring entries a human
  puts there.

## 2. Usage

### 2.1 Roles

| Who | When | Does |
|---|---|---|
| Every developer | once per machine | install the binary; `valetkey install` |
| Project lead | once per project | `valetkey init`, commit the result |
| Every developer | once per clone, and after config changes | `valetkey doctor`, `valetkey allow` |
| The agent | constantly | calls MCP tools only |
| A human | occasionally | `allow`, `secret set`, `status`, `log`, `self-update` |

### 2.2 Install (once per machine)

```sh
brew install kondfox/tap/valetkey                                          # macOS / Linux / WSL2
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/kondfox/valetkey/releases/latest/download/valetkey-installer.sh | sh
powershell -c "irm https://github.com/kondfox/valetkey/releases/latest/download/valetkey-installer.ps1 | iex"   # Windows
```

Then, once:

```sh
valetkey install
```

This registers the MCP server at **user scope** in each supported agent, using the binary's
absolute path. No checked-in `.mcp.json` entry is needed (§6.3).

Updates: `valetkey self-update`, run by a human. It checks the release signature (§8). Homebrew installs update with `brew upgrade` instead.

### 2.3 Project setup (once per project)

`valetkey init` runs a wizard (agent profiles, targets) and writes two files, both safe to commit:

**`valetkey.toml`**: non-secret policy.

```toml
min_version   = "0.1"
require_fence = true            # default: protected secrets (§6.0) need a fenced agent

[targets.local-app]
kind     = "postgres"
host     = "localhost"
port     = 5432
database = "app"
user     = "app"
secret   = "env-file://.env#POSTGRES_PASSWORD"
writable = true

[targets.staging-app]
kind     = "postgres"
socket   = "~/.local/share/valetkey/sockets/acme-stage:europe-west1:core"
database = "app-staging"
user     = "app-staging"
secret   = "gcp-sm://acme-stage/DB_PASSWORD"
writable = true

[targets.crm-sandbox]
kind     = "http"
base_url = "https://acme--dev.my.example-crm.com"
auth     = { type = "bearer", token = "keyring://valetkey/crm-sandbox" }
allow    = ["GET /api/v1/query*", "GET /api/v1/objects/*"]
```

`secret` is always a **reference**, `<scheme>://…`. It's never a value. When `init` finds
passwords in `.env` files, it offers to move them into the OS keyring (`keyring://`), which makes
them protected (§6.0). Schemes: `env-file`,
`keyring`, `gcp-sm` (v1), then `aws-sm`, `azure-kv`, `op` (1Password).

**`.claude/settings.json`**: the fence, merged into any existing settings (§6.5). It's derived
from the secret sources the targets use, so nobody maintains the deny list by hand.
`valetkey init --update` re-derives it after the targets change.

### 2.4 Joining a project

```sh
git clone … && cd project
valetkey doctor
```

```
✔ valetkey 0.1.3 (project needs ≥ 0.1)
✔ Claude Code fence present, sandbox available (macOS Seatbelt)
✘ valetkey.toml not approved on this machine → run: valetkey allow
✔ gcp-sm: gcloud logged in
⚠ staging-app: socket missing → start your Cloud SQL proxy with --unix-socket (see docs)
✔ local-app: reachable
```

`valetkey allow` prints a summary of the targets and their write flags (a diff after the first
time) and asks for confirmation. Nothing is served until a human approves the config (§6.1).

### 2.5 Agent tools

| Tool | Behaviour |
|---|---|
| `valetkey_targets` | target ids, kinds, writable flags, and why a target is unavailable (e.g. unfenced mode) |
| `sql_query(target, sql, params?)` | read-only transaction; row, byte and time caps |
| `sql_describe(target, table?)` | schema introspection; the table name is bound as a parameter, never interpolated |
| `sql_execute(target, sql, params?, allow_write: true)` | writable targets only; **a human approves each call** unless the agent could reach the target without valetkey anyway (§6.10) |
| `http_request(target, method, path, body?)` | only paths matching `allow`; auth injected by the broker |

Each tool's JSON schema lists only the targets of its kind, so the agent picks from a closed set.
Every result carries metadata: the target, the **verified identity** of the far side (e.g.
`current_database()`), the row count, whether the result was truncated, and the duration.

### 2.6 Occasional human commands

```
valetkey status            targets, fence state, approval state
valetkey secret set ID     store a secret in the OS keyring (for projects without a vault)
valetkey log [--follow]    audit log of tool calls
valetkey doctor --fence    probe the fence from inside the agent's sandbox (§6.6)
valetkey self-update
```

### 2.7 Platform support

| Platform | Broker | Fence | Result |
|---|---|---|---|
| macOS | ✔ | Seatbelt | full guarantee |
| Linux | ✔ | bubblewrap (`doctor` checks `bwrap`, `socat`) | full guarantee |
| Windows, agent inside WSL2 | ✔ (Linux build) | bubblewrap | full guarantee. Recommended on Windows. |
| Windows native | ✔ | none exists | unfenced mode |
| MCP client without a fence profile | ✔ | unknown | unfenced mode |

"Full guarantee" is conditional on the M0 go/no-go table (§11). A capability that M0 can't
confirm on a platform downgrades that platform as the table says.

Optional organization-wide hardening: Claude Code managed settings can lock the fence (e.g.
`sandbox.filesystem.allowManagedReadPathsOnly`, no unsandboxed commands). Recommended, not
required.

## 3. Tech stack

| Concern | Choice |
|---|---|
| Language | Rust stable, edition 2024, pinned in `rust-toolchain.toml` |
| Async | `tokio` |
| MCP | `rmcp` (official Rust SDK), stdio transport; tool schemas via `schemars` |
| CLI | `clap` (derive), `inquire` for the `init` wizard |
| Config | `serde` + `toml`; JSON Schema generated from the types and published for editor support |
| Approval hashes | `blake3` |
| Paths | `directories` (per-OS config/data/state dirs) |
| Secrets in memory | `secrecy` (`SecretString`, zeroized; no `Debug`/`Serialize` leaks) |
| Logging / audit | `tracing` to a file; audit log as JSON lines. **stdout belongs to MCP.** |
| TLS | `rustls` + `rustls-platform-verifier` (OS trust store, works with corporate CAs) |
| Postgres | `tokio-postgres` (needs extended-protocol, portal and auth control that `sqlx` hides) |
| HTTP | `reqwest` (rustls) |
| Later adapters | `mysql_async`, `tiberius`, `redis`, `mongodb` |
| Secret sources | the vendor CLIs the developer already uses (`gcloud`, `aws`, `az`, `op`) through a hardened process runner; native `keyring` and `dotenvy` |
| Release | `dist` (cargo-dist) on GitHub Actions: builds, installers, Homebrew tap, checksums; minisign signatures for `self-update` |
| Supply chain | `cargo-deny` (advisories, licences, sources) in CI |

Why vendor CLIs instead of SDKs: they reuse the developer's existing login (SSO, MFA, `aws sso
login`), add no auth code to valetkey, and keep the binary small. Each source sits behind a trait,
so an SDK-based backend can be added later without changes elsewhere.

All adapters are compiled into the single shipped binary. Cargo features exist for development
builds only.

## 4. Workspace layout

```
crates/
  valetkey-core/       config model, target registry, policy, approvals, audit, traits
                       (no vendor crates; enforced by cargo-deny bans)
  valetkey-secrets/    process runner; sources: env-file, keyring, gcp-sm (later aws-sm, azure-kv, op)
  valetkey-postgres/   Postgres adapter          (later: -http, -mysql, -mssql, -redis, -mongo)
  valetkey-fence/      fence profiles: claude-code (generate, detect, probe)
  valetkey-mcp/        rmcp server; builds tool schemas from the approved config
  valetkey-cli/        the `valetkey` binary: commands + the single composition root
schema/valetkey.schema.json   generated; CI fails if it's stale
tests/fence/                  probe scenarios
docs/
```

Dependency rule: only an adapter or source crate imports its vendor library. `core` depends on
nothing vendor-specific. `cli` is the only crate that wires concrete implementations together.

## 5. Extension points

```rust
// valetkey-core
pub trait SecretSource: Send + Sync {
    fn scheme(&self) -> &'static str;                         // "gcp-sm"
    async fn fetch(&self, r: &SecretRef) -> Result<SecretString, SourceError>;
    fn fence(&self) -> FenceRules;                            // e.g. deny-read ~/.config/gcloud
}

pub trait Adapter: Send + Sync {
    const KIND: &'static str;                                 // "postgres"
    type Target: DeserializeOwned + JsonSchema;               // its section of valetkey.toml
    fn validate(&self, id: &TargetId, t: &Self::Target) -> Vec<Problem>;
    fn tools(&self, targets: &[TargetId]) -> Vec<ToolDef>;
    async fn call(&self, t: &Self::Target, tool: &str, args: Value, cx: &CallCx)
        -> Result<ToolOutput, CallError>;
}
```

`CallCx` holds everything an adapter may use and nothing more:
- a lazy secret resolver for this target only
- the approval requester
- limits
- the audit sink
- the secret's exposure (exposed or protected, §6.0)

Adding a vendor means one adapter crate plus its config section. Adding a vault means one
`SecretSource`. The broker, policy, approvals and fence code don't change.

## 6. Key mechanisms

### 6.0 Secret exposure: the classification everything else uses

Every secret reference has an **exposure**, decided by its source and fixed when the config is
loaded:

- **exposed**: the agent can already read the secret inside the fence. Today that's only
  `env-file://` files inside the project root. valetkey adds no protection to these, and doesn't
  pretend to.
- **protected**: every other source (`gcp-sm`, `aws-sm`, `azure-kv`, `op`, …), **provided the
  fence verifiably blocks that source on the current platform**.

`keyring` is the conditional case: it's protected only on platforms where M0 confirms that the
sandbox blocks keychain IPC (Mach services on macOS, the Secret Service over D-Bus on Linux).
Elsewhere it counts as exposed. In general, exposure = f(source, platform, verified fence
capability), and the table lives in `valetkey-fence`.

Channel rules (§6.2), unfenced mode (§6.4) and the residual risks all key off exposure. They
don't depend on the hostname: a `keyring://` password for a database on `localhost` is protected
and gets the same treatment as a production password.

### 6.1 Approvals (`valetkey allow`)

`valetkey.toml` lives in the repo, so the agent can edit it. Without approvals, the agent could
add a target that sends a protected secret to a server it controls.

**Project identity.**
- The start directory is client-supplied: `CLAUDE_PROJECT_DIR`, else the first MCP root. With
  more than one root, valetkey uses the first one and names it in `valetkey_targets`.
- valetkey walks upward from the start directory and stops at the **first** `valetkey.toml` it
  finds. That directory is the project root. In a monorepo, a nested `valetkey.toml` therefore
  wins over an outer one; there's no merging.
- The root is canonicalized with `realpath`. Symlinks above the root are fine (macOS `/var`,
  `/tmp`, relocated home directories). valetkey refuses to load only when `valetkey.toml` itself,
  or a component between the start directory and the root, is a symlink. Case is folded according
  to the volume the root sits on, not the OS.
- `project-key = blake3(canonical root)`. Each clone and each git worktree is a separate project
  and is approved separately.

**Snapshot.**
- `allow` parses the file into the typed config, resolves defaults and every path (§6.2.1), and
  serializes the result deterministically: sorted keys, normalized values, schema version. That
  canonical form and its blake3 hash are stored in
  `<config_dir>/valetkey/approvals/<project-key>/`, together with the canonical root.
- Comment and whitespace edits don't change the hash, so they never force a re-approval.
- The broker serves the **snapshot**, never the working file, so there's no check-then-use race.
  On each call it re-reads the working file, canonicalizes it, and compares hashes. On a mismatch,
  every tool returns "config changed; a human must run `valetkey allow`". It also checks that the
  root it resolved matches the snapshot's.
- The approvals dir is write-denied by the OS fence **and** by permission rules (§6.5), so the
  agent can't approve on its own.

**No race.** `allow` reads the file once, parses it, shows the diff, and on confirmation stores
exactly the parsed config it showed. It never re-reads the file after confirmation, so swapping
the file mid-prompt changes nothing.

**UX.**
- `allow` shows a per-target diff against the previous snapshot.
- Each change gets a risk label based on its effect, not on the target's exposure. **High
  risk:** a new protected target; any change to a host, socket, TLS setting or secret reference;
  `writable` turned on; `require_fence` turned off. **Low risk:** limits, descriptions, and
  removing a target. That keeps the prompt fast to read without hiding a dangerous change.
- Identifiers, hosts and paths in the diff are sanitized as described in §6.10.
- The agent can make every call fail by toggling the file back and forth. That's a denial of
  service only, and it's documented.

### 6.2 Protected channels

A protected secret is sent only over a channel the agent can't impersonate **or use directly**:
- a unix socket inside `<data_dir>/valetkey/sockets/`. The fence denies the agent both creating
  files there and **connecting** to the sockets there. Otherwise the agent could use a proxy that
  authenticates by itself (Cloud SQL IAM auth, an SSH or `kubectl` tunnel to a trust-auth
  database) with no password and no approval. Or:
- TLS with full certificate and hostname verification, **only to addresses the agent can't
  bind**. "Local" means loopback plus every address of this machine's own interfaces (LAN, Docker
  and VPN bridges). It's checked against the **resolved address at every connect**, not the
  hostname at load time, so a DNS change can't move a target onto a local address. The broker
  resolves once, checks that address, and connects to **exactly that address**, keeping the
  hostname for SNI and certificate verification. The driver never re-resolves. Interface
  addresses are enumerated per connect, because VPNs come and go. For local
  addresses, a protected secret must go through the sockets dir. Remote private addresses (a
  staging DB over VPN) keep TLS. Developer machines often hold a private key for a CA the OS trusts (mkcert, some
  corporate dev tooling). If the agent can read that key, it can issue a valid certificate for
  a port it squats.
- Optional per-target CA or certificate pinning (`tls.pin`).
- `doctor` finds local CA keys (mkcert's `CAROOT`, known corporate tool paths) and adds them to
  the fence's deny-read list.

Two more rules:
- The docs tell humans to start proxies on the protected socket **only**. `doctor` warns when a
  TCP listener for the same instance also exists.
- Targets whose channel authenticates by itself (no `secret`, e.g. IAM auto-auth) are refused
  until M0 confirms that the sandbox can deny unix-socket connects.

Plain TCP is allowed only for targets whose secret is **exposed**, whatever the host.
`Adapter::validate` enforces this when the config is loaded. This defeats port squatting: a
sandboxed agent can bind local TCP ports (its dev servers need that), and could otherwise play a
fake server that asks for the password in clear text.

On macOS, socket paths are limited to 104 bytes, and `validate` checks this.

#### 6.2.1 Path resolution

The broker runs outside the fence, so a path it resolves for the agent must never let it read a
file the fence denies to the agent (the confused-deputy problem).

- `env-file://` paths are relative to the canonical project root. Absolute paths, `..` and `~` are
  rejected. The file is opened without following symlinks, and the opened path must stay under the
  root.
- `~` in socket paths expands from the broker's own home directory (from the OS user database),
  never from client-supplied environment variables.
- Every resolved path is stored in the snapshot and shown by `allow`.
- `doctor` warns when a value in an env-file equals a protected secret. The broker compares
  hashes, never the values themselves. A leftover copy of the staging password in `.env` silently
  turns a protected target into an exposed one.

### 6.3 Registration

- `valetkey install`, run by a human, **copies the running binary** into valetkey's own install
  dir (`<data_dir>/valetkey/bin/`) and registers that path at user scope (Claude Code:
  `~/.claude.json`). There's no `PATH` lookup and no checked-in `.mcp.json` the agent could
  repoint.
- valetkey doesn't rely on Homebrew's or an installer's paths, which may be symlinks in
  user-writable directories. Homebrew and the installers only deliver the binary.
- After `brew upgrade`, `doctor` notices that the delivered binary is newer than the installed
  copy, and tells the human to re-run `valetkey install`.
- **Humans run valetkey through `PATH`, which the agent may be able to influence.** So:
  - **Only the installed copy may verify and install a new binary**:
    `<installed>/valetkey install --from <path>`. A binary found through `PATH` could be fake and
    would simply skip any check it ran itself. The installed copy checks the minisign signature
    (every release asset, Homebrew bottles included, ships a `.minisig`) against its own keys.
  - The very first install is trust-on-first-use. The docs say so, and say to install from a fresh
    terminal, not from a shell the agent has touched.
  - `install` prints a shell alias pointing at the installed copy. Every hint valetkey prints (in
    `doctor`, refusals, the docs) uses the absolute path.
  - `doctor` warns when `command -v valetkey` resolves to anything other than the installed copy.
    That check is only meaningful when `doctor` itself is run by absolute path, and the docs say
    so.
- The broker locates the project per call (§6.1), so one registration serves every project.
- **Shadowing.** Another server named `valetkey` could take the registered one's place. `detect`
  and `doctor` treat any other definition of that name as shadowing, wherever it comes from:
  project scope (`.mcp.json`), local scope (in `~/.claude.json`), plugins, or managed MCP config.
  While one exists, the broker refuses protected targets. Precedence rules are checked in M0.

### 6.4 Unfenced mode

Targets with a **protected** secret are refused when `require_fence = true` (the default) and any
of these holds:
- the MCP client (from `clientInfo` at `initialize`) has no fence profile
- the platform is native Windows
- the profile's `detect` finds the sandbox disabled, required rules missing, or a shadowing server
  in the effective settings (managed → user → project → local)

The refusal names the exact missing rule and the command that fixes it (`valetkey init --update`).
Otherwise developers would simply set `require_fence = false`.

Detection is a safety net against misconfiguration, not a security boundary. It can't see
command-line flags or environment overrides the session was started with (a residual risk). The
fence itself is the boundary.

### 6.5 Claude Code fence profile

The agent has two ways to touch files, and they're governed separately:
- its **shell** is limited by the OS sandbox (Seatbelt or bubblewrap)
- its **file tools** (Read, Edit, Write) are limited by Claude Code permission rules

So every protected path gets **both** an OS rule and a permission rule. `generate` merges these
(set-union; it never removes user rules):

| Paths | OS sandbox | Permission rules |
|---|---|---|
| Every credential location a used `SecretSource` resolves (below), and `~/.ssh` | deny-read | deny `Read` and `Edit` |
| valetkey install, approvals, sockets, audit and log dirs | deny-write | deny `Edit` |
| valetkey sockets dir | deny unix-socket connect | — |
| Agent config that can define hooks, MCP servers, permission modes or allowed tools: `.claude/settings*.json`, `.claude/hooks/**`, `.mcp.json`, `~/.claude.json`, `~/.claude/settings*.json`, `~/.claude/plugins/**`, plus every other such file M0 finds (e.g. skill or agent frontmatter, if it can carry hooks or permissions) | deny-write | deny `Edit` |
| Git: the **resolved** git dir's `config` and `config.worktree`, and the **effective** hooks path (`git rev-parse --git-dir --git-path hooks`; covers worktrees, submodules, and `core.hooksPath` such as husky's `.husky/`) | deny-write | deny `Edit` |
| Other files that run automatically, detected per project: `.envrc`, mise/asdf config, venv `activate` scripts, `.vscode/tasks.json` and `.vscode/settings.json`; the Homebrew tap clone for valetkey | deny-write | deny `Edit` |
| Outside the project: shell startup files, `~/.gitconfig`, `~/.ssh/**`, user bin dirs on `PATH` | (outside the write scope, below) | deny `Edit` |
| Local CA private keys (mkcert `CAROOT`, …) | deny-read | deny `Read` and `Edit` |

**Required write scope.** The fence is only sound if the OS sandbox lets the agent's shell write to
the project dir and temp dirs and **nothing else**. `detect` checks this; a wider write scope
counts as unfenced. The permission denies for files outside the project exist because a file-tool
edit there needs only one click from a human.

**Agent config that can run code is always OS write-denied.** If M0 finds that skill or agent
frontmatter (or any other editable file) can define hooks that run outside the sandbox, those
directories join the deny-write rows, whatever the usability cost. Detection alone can't stop a
planted hook from running. The `detect` scan of editable config stays as a secondary check: any
match counts as unfenced.

**`PATH` outside the sandbox.** Hooks, the statusLine and plugin hooks run unsandboxed and resolve
commands through the client's inherited `PATH`.
- The plugin's `SessionStart` hook calls the installed copy by absolute path.
- `detect` treats a client `PATH` that contains any dir inside the project, or any other
  agent-writable dir (`node_modules/.bin`, `.`, a direnv `PATH_add bin`), as unfenced.
- Dirs that `.envrc` or mise add to `PATH` join the auto-run deny rows.
- `doctor` flags project-local `PATH` entries in the human's shell.
- The broker sees the environment it was spawned with. If hooks and the statusLine run with a
  different `PATH` (M0 item 29), the plugin's `SessionStart` hook reports its `PATH` to the broker
  as a hint only. Any mismatch the broker can't see is a documented residual risk.

**Temp dirs.** The agent can write to them, and they're shared with other tools. The unix-socket
default-deny covers sockets there. Human tooling must not execute files from temp dirs.

Repos that use husky or similar keep working: their hook files simply become write-protected, so
humans edit them and the agent can't.

**Credential locations are resolved, not assumed.** `SecretSource::fence()` reads them at `init`
and `doctor` time from the human's environment: `GOOGLE_APPLICATION_CREDENTIALS`,
`CLOUDSDK_CONFIG`, `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`, `credential_process`
helpers, and so on. The process runner's environment allowlist uses the same values. `doctor`
**fails** when a credential file sits inside the project root or anywhere else the fence leaves
readable.

The agent config rows are deliberately narrow. Project commands, skills, agents and memory stay
editable, because a deny on all of `.claude/**` would block real work and teams would delete it.

Plus:
- `sandbox.enabled = true`, `sandbox.failIfUnavailable = true`, unsandboxed commands not allowed
- **Unix-socket connects denied by default**, with an explicit allowlist. This blocks the Docker
  and Podman sockets (a container can mount any host path) and other local command runners:
  Colima, Lima and OrbStack VMs, tmux and screen servers, IDE helpers.
- Mach and D-Bus services that start jobs outside the sandbox (launchd, systemd-user, Apple
  Events to terminal apps) blocked. **If M0 can't confirm the block on a platform, that platform
  is unfenced for protected targets** (§11, go/no-go table).
- Local command executors on TCP (Jupyter, VS Code server, sshd, …):
  - localhost TCP is limited to declared dev ports, if the sandbox supports it (M0)
  - otherwise the fence deny-reads their runtime token dirs (Jupyter `runtime`, VS Code server
    data, `~/.ssh`), **and** the broker refuses protected targets while it detects a known
    executor listening on localhost. The refusal names the process.
- a network allowlist seeded from the project's needs. It **always** excludes link-local
  instance-metadata addresses (`169.254.169.254`, `fd00:ec2::254`), which hand out cloud tokens
  without any file.

Agent config needs the OS rule because project settings can define hooks and MCP servers, which
run outside the sandbox. The git and `.envrc` rows exist because code the agent plants there would
run later in a terminal that *can* read secrets. That class of attack can't be closed completely
(package scripts, Makefiles and editor tasks are also code a human runs). The threat model lists
it, with guidance.

The exact keys are verified in M0, and the generator is tested against them.

**Fail closed.** Every fence capability this design relies on is listed in the M0 go/no-go table
(§11). A capability that M0 can't confirm on a platform never becomes an "accepted residual"
quietly. The table states the consequence: the platform counts as unfenced, a source counts as
exposed, or the gap is accepted and documented explicitly.

### 6.6 Fence probe

`valetkey doctor --fence` runs **from the agent's sandboxed shell**. It attempts each forbidden
action and passes only if all of them fail:
- read each declared secret path
- invoke each source's CLI secret command
- write the binary
- write the approvals, audit and log dirs
- create a socket in the sockets dir
- write agent config files, `.git/hooks`, `.git/config`, `.envrc`
- connect to a socket in the sockets dir
- reach the Docker and Podman sockets, and every other unix socket not on the allowlist
- reach the instance-metadata addresses
- start a job through launchd/systemd-user or Apple Events (where the platform allows the check)

A shell can't test the file tools. `doctor --fence` therefore also prints a short checklist for a
human: ask the agent to Read a secret path and to Edit the approvals file, and confirm both are
denied.

**The probe is a diagnostic for humans, not a gate.** It runs inside the hostile sandbox, so its
output can be faked. No broker decision ever depends on it, or on the `SessionStart` hook. CI
runs it on macOS and Linux runners, where the agent isn't present.

### 6.7 Call lifecycle

1. Load the approved snapshot; refuse if missing or stale.
2. Resolve the target; apply policy: kind, `writable`, `allow_write`, fence state for protected
   targets.
3. Writes: request human approval through MCP elicitation (§6.10). If the client doesn't support
   it, refuse (configurable later to rely on the client's own permission prompt).
4. Resolve the secret: in-memory cache keyed by (project-key, target id, resolved ref), short TTL,
   cleared when the snapshot changes, no retries.
5. Execute through the adapter under limits.
6. Serialize typed values: bigint/numeric as strings, bytea as base64, timestamps as RFC 3339.
7. Append an audit record: time, client, target, tool, statement text and hash, rows, outcome,
   approver. Never a secret.

### 6.8 Process runner

- argument array only, never a shell
- environment reduced to an allowlist
- timeout, with the child killed on drop
- non-interactive flags forced (e.g. `gcloud --quiet`)
- a missing executable surfaces as a typed error
- stderr captured, length-capped and redacted before it reaches the agent

### 6.9 Postgres adapter

- One connection per call; no pool in v1.
- Startup parameters: `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`,
  and `default_transaction_read_only=on` for reads.
- Reads: `BEGIN READ ONLY`, **extended protocol only**, so multiple statements are rejected and
  `COMMIT; DELETE …` can't escape. Rows stream through a portal and stop at `max_rows + 1`, which
  bounds memory.
- After connecting: check that `current_database()` and `current_user` match the config.
- Protected targets: the broker refuses to connect when
  - the role is a superuser
  - the role is a member of `pg_execute_server_program`, `pg_write_server_files` or
    `pg_read_server_files` (`COPY … TO PROGRAM` / `TO file` is a single statement and may run in
    a read-only transaction; M0 verifies this)
  - the role has `EXECUTE` on any function whose language isn't trusted (`lanpltrusted = false`:
    plpython3u, plperlu, C) and which doesn't belong to an allow-listed extension. Such functions,
    often `SECURITY DEFINER` and executable by `PUBLIC`, run arbitrary code even from a read-only
    transaction. The query excludes language `internal`, built-in objects (OID < 16384), and
    members of allow-listed extensions (`pg_depend`, `deptype = 'e'`). `plpgsql` is on the default
    extension allow-list.
  - an installed extension isn't on the **allow-list** of known-safe extensions. Extensions such as
    `dblink`, `postgres_fdw`, `pg_background`, `pg_net`, `http`, `aws_lambda` and `aws_s3` run work
    in another transaction or make outbound calls, which escapes read-only. A target can opt in to
    more extensions with `extensions.allow`. That's a high-risk change in `allow`.
  - the server asks for a cleartext or MD5 password, if `tokio-postgres` allows refusing it (M0)
- `doctor` warns about members of `pg_signal_backend` and other roles that can do more than
  read.
- Even read-only transactions can still have side effects: advisory locks,
  `pg_terminate_backend`/`pg_cancel_backend`, `pg_notify`, and `nextval`/`setval`. Integration
  tests show which of these each guard stops. Only the role's privileges stop the rest, so the
  docs recommend a least-privilege role per target.
- `tokio-postgres` keeps the password in its `Config` as an ordinary buffer, which `secrecy`
  can't cover. The broker builds the `Config` just before connecting and drops it right after.
  Copies inside the library are a documented residual risk.

### 6.10 Write approval prompt

Per-call approval is skipped only for targets that are **agent-usable without valetkey**: the
secret is exposed **and** the channel is plain TCP to a host the sandbox's network rules let the
agent reach. In that case a prompt protects nothing and only trains people to click through, so
writes are audited instead. A target can still opt in with `confirm_writes = true`.

Every other writable target needs approval, including an exposed secret that the agent can only
*use* through the broker (behind the sockets dir, or a host outside the network allowlist).

The flag is **recomputed on every call** from the current effective network settings. If it can't
be determined, approval is required. `allow` shows the value at approval time, labelled as such.

The human approves exactly what the prompt shows, so the agent mustn't be able to shape it.

- Order: connect → verify identity → prompt → execute, on the same connection. The connection's
  `idle_in_transaction_session_timeout` is sized for human response time. If it expires, the
  broker reconnects and verifies identity again before executing.
- The broker builds the whole prompt: target id, verified identity (database, user, host or
  socket), the full statement text with its hash, and the parameters.
- Everything shown is sanitized: control characters, ANSI escapes, bidi overrides and zero-width
  characters are escaped visibly, and non-ASCII identifiers are flagged. The `allow` diff uses
  the same rules.
- The prompt contains no free text from the agent (no "reason" field).
- A statement too long to show in full is marked as truncated, and its hash is shown.
- Timeout, cancellation or an error counts as a denial.
- M0 checks whether any client setting can auto-accept elicitations. If one can, `detect` treats
  that setting as "unfenced for writes".

### 6.11 Trait objects

- `SecretSource` is used as `dyn` in a registry keyed by scheme. Its async method returns a boxed
  future, because `async fn` in traits isn't dyn-compatible.
- `Adapter` stays typed (associated `Target` type). A blanket `ErasedAdapter` wrapper deserializes
  the target section and stores it behind `dyn`. The `cli` crate registers each adapter once.

### 6.12 HTTP adapter requirements (M7)

Recorded now so the `allow` syntax doesn't need to change later:
- Normalize paths before matching: percent-decode once, collapse duplicate slashes, reject `..`.
  Method matching is case-insensitive.
- The query string is matched only when the pattern includes `?`.
- Redirects are never followed across origins. Auth is never resent after a redirect.
- Responses are size-capped, and auth headers are stripped from any echoed request.

## 7. v2 seam: `valetkey up`

v1 assumes a human has started any proxy, with its sockets in valetkey's sockets dir. A later
`Tunnel` trait (`cloud-sql`, `ssh`, `kubectl`) can let valetkey start them itself, keyed from the
same targets, without changing adapters: they only see a socket path.

## 8. Distribution

- GitHub Releases built by `dist`: macOS (arm64, x86_64), Linux (x86_64, aarch64; musl static,
  which also covers WSL2), Windows (x86_64).
- Shell and PowerShell installers, the Homebrew tap `kondfox/homebrew-tap`, and checksums.
- **Update verification uses one mechanism: minisign.** Every release asset gets a minisign
  signature. The public key is built into the binary, and `self-update` refuses any asset that
  doesn't verify. GitHub artifact attestations may be published as well, for humans who want to
  check with `gh attestation verify`, but no code path depends on them.
- **Key rotation:** the binary embeds a versioned list of trusted keys. A release can add the next
  key before the old one is retired. If a key is compromised, a release signed by a surviving key
  removes it, and the docs tell users to reinstall from a fresh download.
- Installers and Homebrew only deliver the binary. `valetkey install` copies it into valetkey's
  own write-protected dir and registers that copy (§6.3).
- Homebrew installs: `self-update` detects them and refuses, pointing to `brew upgrade` plus
  `valetkey install`. Homebrew downloads aren't minisign-checked. Their integrity rests on the
  tap repository and Homebrew's checksums. The fence write-protects the local tap clone (§6.5).
- A Claude Code plugin, published in an organization's own marketplace (outside this repo),
  contributes:
  - a skill: how to use the valetkey tools
  - a `SessionStart` hook: `valetkey doctor --quiet`

  It doesn't ship the binary.
- The repo may move to an organization later. GitHub redirects transferred repos, but the
  Homebrew tap name changes (M0 checks tap migration). The old path must never be reused.

## 9. Testing

- **Unit:** policy, approvals, config validation and fence generation, with fake sources and
  adapters. No I/O.
- **Integration:** `testcontainers` against real databases. The read-only guard is proven only
  against a real Postgres, never a mock.
- **MCP end-to-end:** spawn the real binary and drive it with `rmcp`'s client.
- **Fence:** the probe (§6.6) on macOS and Linux GitHub runners.
- CI gates: `fmt`, `clippy -D warnings`, tests, `cargo-deny`, schema freshness, and a build on
  the declared MSRV (`rust-version` in `Cargo.toml`), so dependency upgrades can't raise it
  silently.

## 10. Milestones

| | Milestone | Done when |
|---|---|---|
| M0 | Spike, no product code | every item in §11 answered and recorded in `docs/spike.md` |
| M1 | Skeleton | workspace, CI, config + schema, basic `init`/`allow`/`doctor`, MCP server with `valetkey_targets` |
| M2 | Postgres read path | `env-file`, `keyring` and `gcp-sm` sources; `sql_query`, `sql_describe`; guard integration tests |
| M3 | Write path | `sql_execute`, elicitation approval, audit log |
| M4 | Fence | Claude Code profile: generate, detect, probe; unfenced mode; fence CI on macOS and Linux |
| M5 | v0.1 release | `dist` pipeline, installers, Homebrew tap, `self-update`, plugin |
| M6 | Pilot | first real project adopts valetkey; its targets and fence checks become the acceptance test |
| M7+ | Roadmap | `http` adapter, `aws-sm`/`azure-kv`/`op` sources, MySQL/MS SQL, Redis/Mongo, `valetkey up` |

## 11. M0 spike questions

1. Does Claude Code support MCP elicitation, and does `rmcp` expose it? What does the user see?
2. Can `tokio-postgres` refuse cleartext/MD5 auth? If not, how small is the patch?
3. Exact Claude Code sandbox and permission keys today. Can `detect` read the effective settings
   layers reliably?
4. Does the sandbox block keychain access: macOS `security` / Mach lookups, Linux Secret Service
   over D-Bus? Otherwise `keyring://` secrets aren't protected.
5. Does the Claude Code sandbox runtime run in GitHub Actions without a model (macOS Seatbelt;
   Linux bubblewrap with user namespaces)?
6. Is `CLAUDE_PROJECT_DIR` set for user-scope MCP servers? What does the client report in
   `clientInfo`?
7. Cloud SQL Auth Proxy `--unix-socket` layout and path lengths on macOS.
8. `dist`: Homebrew tap publishing, installer layout (a dedicated install dir), and how to attach
   minisign signatures to release assets. The Homebrew formula must also install the `.minisig`
   next to the binary (e.g. `share/valetkey/`), so `install --from` can verify it.
9. Homebrew tap migration after a repo transfer. The actual Homebrew path layout (`opt`, `Cellar`,
   symlinks) on macOS and Linux.
10. Do Claude Code's file tools honour sandbox filesystem denies, or only permission rules?
    (Either way, valetkey emits both; this sets how the fence probe is documented.)
11. Does the sandbox already write-protect `.claude/` and the settings files at the OS level?
12. Which wins when user-scope and project-scope MCP servers share a name?
13. Can any client setting auto-accept elicitations?
14. Are `CLAUDE_PROJECT_DIR` and MCP roots stable for a session? What are they when Claude Code
    starts in a subdirectory or a git worktree?
15. Is the Docker socket reachable when Docker Desktop uses a non-default context or socket path?
    Is the Podman socket?
16. What does bubblewrap do with abstract unix sockets and D-Bus (affects `keyring` on Linux)?
17. Does `rmcp` support elicitation and roots at the pinned version?
18. Can the sandbox deny **connecting** to unix sockets (per path, default-deny with an allowlist)
    on Seatbelt and bubblewrap? Can it limit localhost TCP to declared ports?
19. Under Seatbelt: are Mach services, Apple Events and `launchctl` job submission blocked? Under
    bubblewrap: the session D-Bus and `systemd-run --user`?
20. Does the network filter apply to raw IPs, including instance-metadata addresses?
21. Do deny-write rules protect a symlink entry itself, or only its resolved target, on each
    platform?
22. Which commands does Claude Code run **outside** the sandbox inside the project (its own git
    calls, statusLine, excluded commands)?
23. Do MCP servers started by Claude Code run outside the sandbox? A copy of `valetkey mcp` the
    agent starts inside the sandbox must stay inert: it can't read secrets, and it can't change
    approvals.
24. Against real Postgres: does `COPY … TO PROGRAM` / `TO file` run inside a `READ ONLY`
    transaction? How do `pg_background` and `pg_net` behave? Build the initial extension
    allow-list.
25. Every Claude Code project file that can define hooks, MCP servers, permission modes or allowed
    tools, including skill and agent frontmatter.
26. The sandbox's default write scope: the **exact** set of writable paths (it may include caches or
    `~/.claude`). `detect` compares against this measured set, not literally "project + temp". Do
    file-tool edits outside the project only prompt?
27. Effective git dir and hooks path for worktrees, submodules and `core.hooksPath`, both inside
    and outside the sandbox.
28. Which environment variables does `rustls-platform-verifier` honour on each OS (`SSL_CERT_FILE`
    and similar)? The broker inherits the client's environment, so it clears those variables
    before building its TLS config. Corporate TLS-inspection setups instead set a CA bundle path
    in the **user-level** valetkey config, never in project config.
29. What `PATH` and environment do Claude Code hooks, the statusLine and plugin hooks run with?
30. Can skill or agent frontmatter define hooks? Do they run unsandboxed? Do they need user
    approval before running?
31. Against real Postgres: do untrusted-language functions run under `READ ONLY`? Write the catalog
    query for the `EXECUTE` check.

### Go/no-go table

M0 fills in the **Result** column per platform. A capability that isn't confirmed gets the
consequence in the last column; it's never silently accepted.

| Fence capability | Spike item | If not confirmed |
|---|---|---|
| Deny-read of secret paths applies to every child process | 3 | platform unfenced |
| Unix-socket connect deny (sockets dir; default-deny with allowlist) | 18 | platform unfenced; self-authenticating channels refused |
| Mach / D-Bus job submission blocked (launchd, systemd-user, Apple Events) | 19 | platform unfenced |
| Keychain / Secret Service IPC blocked | 4, 16 | `keyring` counts as exposed on that platform |
| Network filter covers raw IPs and metadata addresses | 20 | platform unfenced |
| Deny-write protects the entries valetkey depends on (incl. symlinks) | 21 | valetkey switches to copies it owns, or the platform is unfenced |
| Write scope limited to a known set | 26 | platform unfenced |
| localhost TCP limited to declared ports | 18 | executor token dirs deny-read **and** broker refuses protected targets while a known executor listens |
| Agent config that can define hooks is OS write-deniable | 25, 30 | platform unfenced |
| MCP servers run outside the sandbox; an in-sandbox broker is inert | 23 | valetkey can't work on that client |
| Elicitation can't be auto-accepted (or the setting is detectable) | 1, 13 | writes refused on that client |
