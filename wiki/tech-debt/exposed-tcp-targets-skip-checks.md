# Exposed TCP targets skip the Postgres checks

Status: Open · Since: 2026-10-05 (M2)

**The debt.** The role-closure and catalog checks matter when the read path is the agent's
**only** route to a database: then any escape (COPY TO PROGRAM, a dangerous function) is an
escape *through valetkey*. That's true for protected targets and for every socket target, and
those get the checks. For an exposed target on plain TCP, the agent can often connect directly
with the password it can read, so M2 skips the checks there. But not always: if the host is
outside the sandbox's network allowlist, valetkey is again the only route.

**Why not now.** Whether the agent can reach a host itself depends on the fence's network rules,
which M4 reads (the same "agent-usable without valetkey" flag as write approval,
`docs/design.md §6.10`).

**Paying it down.** In M4, key the checks on "agent-usable without valetkey" instead of on
exposure and channel.

Code: `crates/valetkey-mcp/src/lib.rs` (`run_checks`).
