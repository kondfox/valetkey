# Only debug builds honour `VALETKEY_DEV_ROOT`

Date: 2026-10-04 · Status: Active

## Context
The valetkey root must never come from the environment ([[2026-10-04-valetkey-root-dir]]), yet the
CLI's end-to-end tests run the real binary and must not touch the developer's real
`~/.valetkey/`.

## Options considered
1. A hidden `--root` flag. Any caller could pass it, and Claude Code passes the registered args.
2. A Cargo feature enabled only for tests. Integration tests of a binary can't turn features on
   cleanly.
3. **An environment variable read only under `cfg(debug_assertions)`.**

## Decision
Option 3. `ValetkeyRoot::resolve` reads `VALETKEY_DEV_ROOT` only in debug builds
(`crates/valetkey-core/src/paths.rs`).

## Why
- `cargo test` builds debug binaries; every shipped binary (`dist` releases, Homebrew) is a
  release build, so the override doesn't exist where it would matter.
- The variable lives in exactly one, easily audited place.

## Consequences
- `doctor` warns whenever it runs as a debug build.
- Threat model A7h: a debug build registered as the broker would be steerable through a settings
  `env` block. `install` (M5) registers only the installed release copy.

## Sources
- `docs/design.md §6.2.1`; `docs/threat-model.md` A7h
