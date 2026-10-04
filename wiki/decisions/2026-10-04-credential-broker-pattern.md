# Isolation comes from broker + immutable binary + fence, not from the tool alone

Date: 2026-10-04 · Status: Active

## Context
AI coding agents need to query databases and call APIs whose credentials they must not be able to
read. The agent has a shell and runs as the developer's OS user.

## Options considered
1. A wrapper tool that reads the secret and runs the operation. The agent could just read the same
   secret the tool reads.
2. A broker process alone (an MCP server holding the secrets). The agent could still read the
   secret stores, or edit the broker's code.
3. **Broker + immutable binary + fence**: three parts, each closing a hole the others leave open.

## Decision
Option 3 ([[architecture]]):
- **broker:** an MCP server started by the agent client outside the agent's sandbox
- **immutable binary:** a signed release, installed outside every repo, in a location the agent
  can't write
- **fence:** the agent's OS-enforced sandbox, configured by `valetkey init`

## Why
- A tool running as the same OS user can't hide anything from a shell on its own. Only an
  OS-enforced boundary (Seatbelt, bubblewrap) can.
- An earlier project-specific prototype design (TypeScript, private monorepo) ran the broker from
  repo source. Its first review found the critical hole: the agent edits the source, and the next
  broker start runs that code **outside** the sandbox, with the developer's cloud login. The
  workarounds that followed (build from `origin/main`, fresh clones) each opened new holes:
  - a faked local ref
  - git hooks
  - an editable install bootstrap

  A signed release binary removes the whole class.
- That prototype's later review rounds also found the Docker-socket mount and proxy-port squatting.
  Both are fence concerns, which confirms that the fence is a first-class part, not an add-on.

## Consequences
- valetkey ships as a single binary per OS ([[2026-10-04-rust-single-binary]]).
- Every fence capability has to be verified per platform and per agent
  ([[2026-10-04-fail-closed-fence-capabilities]]).
- Clients without a fence profile can only use secrets the agent could read anyway
  ([[2026-10-04-secret-exposure-classification]]).

## Sources
- `docs/design.md` §1, `docs/threat-model.md` A5, A6 (commit `6181a1d`)
- Design sessions on 2026-10-04 (private transcripts; summarized here).
