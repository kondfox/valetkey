# Glossary

Terms as valetkey uses them. Spec references point into `docs/design.md`.

- **Adapter:** the code for one kind of target (`postgres`, later `http`, `mysql`, …), implementing
  the `Adapter` trait. Defines its config section, its tools and its guards. §5
- **Agent:** the AI coding assistant calling valetkey's tools. In the threat model, assumed hostile.
- **Agent-usable without valetkey:** a target whose secret is exposed *and* whose channel the
  sandbox lets the agent reach directly. Only such targets skip write approval. §6.10,
  [[2026-10-04-write-approval-scope]]
- **Approval (config):** a human running `valetkey allow`, which stores a snapshot. §6.1
- **Approval (write):** the per-call human confirmation of a write, through MCP elicitation. §6.10
- **Audit log:** a JSON-lines record of every tool call. It never contains a secret. §6.7
- **Broker:** `valetkey mcp`, the MCP server that holds no secrets at rest and fetches them at call
  time, outside the sandbox. [[2026-10-04-credential-broker-pattern]]
- **Canonical form:** the deterministic serialization of a parsed `valetkey.toml`, which is what
  gets hashed and approved. §6.1
- **Channel:** how the broker reaches a target: a protected socket, verified TLS, or plain TCP. §6.2
- **Detect:** the fence-profile step that reads the agent client's effective settings to decide
  whether the session is fenced. It's a safety net, not a boundary. §6.4
- **Exposed secret:** a secret the agent can already read inside the fence (today: an env-file in
  the project). [[2026-10-04-secret-exposure-classification]]
- **Fence:** the agent's OS-enforced sandbox plus permission rules, as configured by valetkey. §6.5
- **Fence probe:** `valetkey doctor --fence`, run from the agent's shell. A diagnostic for humans,
  never a gate. §6.6
- **Fence profile:** per-agent code to generate, detect and probe a fence. Claude Code is first.
  [[2026-10-04-mcp-interface-per-agent-fence]]
- **Go/no-go table:** the mapping from each fence capability to the consequence when M0 can't
  confirm it. §11, [[2026-10-04-fail-closed-fence-capabilities]]
- **Installed copy:** the binary that `valetkey install` placed in the write-denied install dir.
  The only binary allowed to install updates. [[2026-10-04-binary-provenance-and-registration]]
- **Local address:** loopback plus this machine's own interface addresses, i.e. addresses the
  agent could bind. Checked on the resolved IP at every connect. §6.2
- **M0:** the verification spike before any product code. §10, §11
- **Project key:** blake3 of the canonical project root; it identifies a project's approvals. §6.1
- **Project root:** the directory of the first `valetkey.toml` found walking up from the client's
  directory. §6.1
- **Protected secret:** any secret the fence verifiably keeps from the agent.
  [[2026-10-04-secret-exposure-classification]]
- **Secret reference:** `<scheme>://…` in config; never the value itself.
- **Secret source:** the code for one scheme (`env-file`, `keyring`, `gcp-sm`, …), implementing
  `SecretSource`. It also declares its fence rules. §5
- **Shadowing:** another MCP server named `valetkey` defined outside user scope. While one exists,
  protected targets are refused. §6.3
- **Snapshot:** the approved canonical config stored in the approvals dir. The broker serves this,
  never the working file. [[2026-10-04-human-approved-config-snapshot]]
- **Sockets dir:** `<data_dir>/valetkey/sockets/`, where proxies put their unix sockets. The agent
  can neither write to it nor connect to it. §6.2
- **Target:** a named resource in `valetkey.toml` (`staging-app`, `crm-sandbox`) with a kind, a
  connection and a secret reference.
- **Unfenced mode:** the broker's behaviour when there's no verified fence: only exposed secrets are
  served. §6.4
- **`valetkey.toml`:** the project's committed, non-secret target and policy config. §2.3
