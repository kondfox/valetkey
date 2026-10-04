# Rust 1.99.0 for development, 1.88 as the minimum supported version

Date: 2026-10-04 · Status: Active

## Context
The workspace needs a reproducible toolchain, and `docs/design.md §9` asks CI to build on the
declared MSRV so dependency upgrades can't raise it silently.

## Decision
- `rust-toolchain.toml` pins **1.99.0**, the current stable on 2026-10-04.
- `rust-version = "1.88"`: `rmcp` 3.5's own minimum, and the first stable release with
  let-chains in edition 2024.
- CI's `msrv` job runs `cargo check` on 1.88.

## Why
Development gets current lints and fixes. The MSRV is the lowest that our dependencies allow, so
it never blocks anyone for our own sake.

## Consequences
- Raising the MSRV is a deliberate change to `Cargo.toml` and this page.

## Sources
- crates.io API (`rmcp` 3.5.0 `rust_version`), checked 2026-10-04; local `cargo +1.88 check`
