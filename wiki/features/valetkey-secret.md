# `valetkey secret set|rm|ls`

Manages `local://` secrets: one `0600` file per id in `~/.valetkey/secrets/` (`0700`)
([[2026-10-04-local-secret-store]]).

- `set <id>` reads the value with no echo, from an interactive terminal only. It refuses to
  overwrite unless `--replace` is given; after a replace it warns that a running broker may use the
  old value for up to 5 minutes (the cache).
- `rm <id>` deletes it. `ls` prints ids, never values.
- Ids are validated like `local://` references, so `../x` can't escape the directory.

Entry points: `crates/valetkey-cli/src/commands/secret.rs`; storage in
`crates/valetkey-secrets/src/sources.rs` (`LocalSource::store/remove/list`).
