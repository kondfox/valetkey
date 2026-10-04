# `valetkey doctor`

Checks this machine and the current project, and prints exactly what to fix (`✔`, `⚠`, `✘`).
Exits non-zero on any `✘`.

M1 checks:
- the version, and a warning when it's a **debug build** (debug builds honour
  `VALETKEY_DEV_ROOT`; see [[2026-10-04-dev-root-only-in-debug-builds]])
- the valetkey root: its location (OS user database), owner-only permissions, and a warning when
  `HOME` disagrees with the user database
- the project: found, valid, approved / stale / not approved, with the absolute command to run
- each target: its exposure and writability. For socket targets, whether the proxy socket exists,
  and if not, the exact proxy command with an **absolute** socket path

Fence checks arrive in M4. Entry point: `crates/valetkey-cli/src/commands/doctor.rs`.
