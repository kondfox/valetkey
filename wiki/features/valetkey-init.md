# `valetkey init`

Creates a commented starter `valetkey.toml` in the current directory. It never overwrites an
existing one. The template points editors at `schema/valetkey.schema.json` (`#:schema` comment) for
completion and validation, and its commented examples are valid config: a test uncomments them
and parses the result.

Entry point: `crates/valetkey-cli/src/commands/init.rs`. Fence generation joins it in M4
(`docs/design.md §2.3`).
