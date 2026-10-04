# valetkey is written in Rust and ships as one static binary per OS

Date: 2026-10-04 · Status: Active

## Context
valetkey must run on macOS, Linux and Windows. The broker binary must be something the agent can't
tamper with ([[2026-10-04-credential-broker-pattern]]).

## Options considered
- The prototype's stack: TypeScript on Node. That means a runtime plus `node_modules`, which is
  more agent-writable surface and an install step that runs code.
- **Rust**: the maintainer's preference, if it was technically viable.

## Decision
Rust, edition 2024, with a pinned toolchain. All adapters are compiled into one binary, and Cargo
features are for development only. The crate choices are in `design.md §3`.

## Why
- One static artifact with no runtime and no dependency tree on disk. That turns "the agent can't
  modify the broker" into a single write-deny on one file, and signing becomes easy.
- Every crate needed was found to exist and be maintained on 2026-10-04: `rmcp`, `keyring`,
  `tokio-postgres`, `reqwest`, `mysql_async`, `tiberius`, `redis`, `mongodb`, `secrecy`,
  `minisign-verify`.
- `rustls` avoids OpenSSL, which simplifies cross-builds.
- `secrecy`'s `SecretString` lets the compiler enforce that a secret can't be printed, logged or
  serialized by accident.

## Consequences
- `tokio-postgres` instead of `sqlx`, for protocol-level control
  ([[2026-10-04-postgres-read-only-guards]]).
- Async trait objects need boxed futures (`design.md §6.11`).
- An MSRV check runs in CI (`design.md §9`).

## Sources
- `docs/design.md` §3, §4 (commit `6181a1d`); crates.io API, checked 2026-10-04
- Design sessions on 2026-10-04 (private transcripts; summarized here).
