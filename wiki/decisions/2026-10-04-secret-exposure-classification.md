# Protection follows where a secret comes from, not which host it's for

Date: 2026-10-04 · Status: Active

## Context
The first draft treated `localhost` targets as low-value and let them use plain TCP. The review
showed why that fails: a `keyring://` password for a database on `localhost` travels over a port
the sandboxed agent can bind and squat.

## Options considered
- Classify by host (local vs deployed)
- **Classify by secret source**: whether the agent can already read the secret inside the fence

## Decision
Every secret reference is **exposed** (today: an `env-file://` inside the project) or **protected**
(every other source, provided the fence verifiably blocks it on this platform). The following key
off exposure (`design.md §6.0`):
- **channel rules:** protected secrets only travel over write- and connect-denied unix sockets, or
  verified TLS to addresses the agent can't bind
- **unfenced mode**
- **write approval** ([[2026-10-04-write-approval-scope]])

## Why
- The value of a secret to an attacker doesn't depend on the target's hostname.
- valetkey can't protect what the project already leaves readable, and it shouldn't pretend to.

## Consequences
- `keyring` counts as protected only where the fence verifiably blocks it. M0: exposed on macOS,
  protected on Linux while unix sockets are denied. Protected local secrets use `local://`
  ([[2026-10-04-local-secret-store]]).
- `init` offers to move `.env` passwords into `local://`.
- `doctor` warns when an env-file value equals a protected secret (compared by hash).

## Sources
- `docs/design.md` §6.0, §6.2; `docs/threat-model.md` A9, A9a, A9b (commit `6181a1d`)
- Design sessions on 2026-10-04 (private transcripts; summarized here).
