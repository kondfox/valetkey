# v1 doesn't start proxies or tunnels; humans do

Date: 2026-10-04 · Status: Active

## Context
Deployed databases are typically reached through a Cloud SQL Auth Proxy, an SSH tunnel or
`kubectl port-forward`. valetkey could start these itself (`valetkey up`).

## Decision
Not in v1. A human starts proxies, placing their sockets in valetkey's protected sockets dir. The
maintainer confirmed this on 2026-10-04. The seam stays open for v2: adapters only ever see a
socket path, so a later `Tunnel` trait doesn't change them (`design.md §7`).

## Why
- It keeps v1 small.
- Owning tunnels means owning their auth flows and lifecycles on three OSes.

## Consequences
- The docs must tell humans to start proxies on the protected socket **only**, from a normal
  terminal. `doctor` warns about extra TCP listeners for the same instance.
- The agent can stop a human-started proxy (denial of service only).

## Sources
- `docs/design.md` §1 non-goals, §6.2, §7 (commit `6181a1d`)
- Design sessions on 2026-10-04 (private transcripts; summarized here).
