# Development

## Toolchain
- `rust-toolchain.toml` pins Rust **1.99.0** with rustfmt and clippy. rustup installs it on first
  use.
- The MSRV is **1.88** (`rust-version` in `Cargo.toml`), set by `rmcp`'s own minimum. CI checks it
  ([[2026-10-04-toolchain-and-msrv]]).

## Everyday commands
```sh
cargo test --workspace                                   # every test, incl. the binary over MCP
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo run -q -p valetkey-cli -- doctor                    # run the CLI from a project dir
cargo run -q -p valetkey-cli -- schema > schema/valetkey.schema.json   # after config type changes
cargo deny check                                          # licences, advisories, dependency direction
python3 scripts/check_commit_messages.py origin/main..HEAD
python3 scripts/test_check_commit_messages.py              # the checker's own tests
cargo llvm-cov --workspace --summary-only                 # line coverage (needs cargo-llvm-cov)
```

A test fails when `schema/valetkey.schema.json` is stale. Two tests pin the canonical form
(`config.rs` `canonical_form_is_pinned`, postgres `normalized_form_is_pinned`): if one fails, every
existing approval's hash changed. Change them only on purpose, together with `CANONICAL_FORMAT` or
the kind's `KIND_VERSION`.

## Testing without touching `~/.valetkey/`
Debug builds read `VALETKEY_DEV_ROOT` and use it as the valetkey root. The CLI tests set it per
test, so they never touch a real root. Release builds ignore it
([[2026-10-04-dev-root-only-in-debug-builds]]).

## CI (`.github/workflows/ci.yml`)
- tests on Ubuntu, macOS and Windows: rustfmt (on Linux), clippy with `-D warnings`, and the tests
- an MSRV check
- `cargo-deny`
- the commit-message convention check (`AGENTS.md`)
- on Linux and macOS: a release build plus `scripts/check_release_ignores_dev_root.sh`, which proves
  that a release ignores `VALETKEY_DEV_ROOT`

Every push and pull request runs it, with `contents: read` permissions and no secrets.
