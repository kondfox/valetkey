# Every write needs per-call human approval, unless the agent could reach the target without valetkey

Date: 2026-10-04 · Status: Active

## Context
`sql_execute` takes `allow_write: true`, which the agent sets itself, so a human must confirm
writes. The review went back and forth:
- Round 3 proposed skipping approval for exposed targets ("the agent has the password anyway").
- Round 4 showed that holding a password isn't the same as being able to use it. If the target is
  only reachable through the connect-denied sockets dir, or a host outside the sandbox network
  allowlist, valetkey is the agent's only route. Skipping approval would make valetkey an
  unapproved write path.

## Decision
Approval is skipped only for targets that are **agent-usable without valetkey**: the secret is
exposed **and** the channel is plain TCP to a host the sandbox can reach. The flag is recomputed on
every call, and approval is required whenever it's unknown. `confirm_writes = true` opts in anyway.
The prompt itself is built only by the broker, sanitized, and deny-by-default (`design.md §6.10`).

## Why
- A prompt protects only what the agent couldn't do on its own.
- Prompts that protect nothing train people to click through the ones that matter.

## Consequences
- Local development databases with `.env` passwords stay prompt-free.
- Staging databases reached through protected sockets always prompt.

## Sources
- `docs/design.md` §6.10; `docs/threat-model.md` A12, A12b (commit `6181a1d`)
