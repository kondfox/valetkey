# A fence capability that isn't verified on a platform makes that platform unfenced

Date: 2026-10-04 · Status: Active

## Context
The design depends on sandbox behaviour that is still unverified:
- unix-socket connect denies
- blocking of Mach and D-Bus job submission
- keychain IPC blocking
- coverage of raw IPs by the network filter
- symlink semantics
- the write scope

The final review round found two complete sandbox escapes that the draft had filed as "accepted
residual risk": local command executors on TCP (such as Jupyter tokens), and job submission
through launchd, systemd-user or Apple Events.

## Decision
**Fail closed.** The go/no-go table in `design.md §11` maps each capability to the consequence when
M0 can't confirm it on a platform:
- the platform is unfenced, or
- a source counts as exposed, or
- an explicit, documented acceptance

Nothing becomes an accepted risk silently. "Full guarantee" in `design.md §2.7` is conditional on
that table.

## Why
- A security claim is only as good as its weakest unverified assumption.
- Making unverified capabilities fail closed keeps the docs honest, and turns M0 into a checklist
  with clear outcomes.

## Consequences
- M0 results are recorded per capability and platform in the wiki: `integrations/` pages, plus a
  go/no-go decision page.
- Some platforms may ship v0.1 unfenced for protected targets.

## Sources
- `docs/design.md` §6.5 "Fail closed", §11 go/no-go table; `docs/threat-model.md` A4b
  (commit `6181a1d`)
