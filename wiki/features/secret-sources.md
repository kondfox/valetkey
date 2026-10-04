# Secret sources

How the broker fetches a target's secret, after its policy checks pass (`valetkey-secrets`). Every
error's public message is fixed text; details go to the broker's log only.

| Scheme | Reads | Notes |
|---|---|---|
| `env-file://path#KEY` | a dotenv file **beneath** the project root, one component at a time without following links (`safe_read::read_untrusted_beneath`) | exposed; own parser: multi-line quoted values, BOM, CRLF, `export`; **no `${VAR}` expansion**, unlike python-dotenv and the `dotenv` npm package, so `${…}` stays literal; an unterminated quote is an error |
| `local://id` | `~/.valetkey/secrets/id`, which must be `0600` in a private directory | one trailing newline dropped |
| `keyring://service/account` | the OS keyring (`keyring` 4) | exposed on macOS (M0) |
| `gcp-sm://project/name` | `gcloud secrets versions access latest` through the process runner | needs `valetkey setup`; output format in [[gcloud]] |

**Process runner** (`valetkey-secrets/src/runner.rs`):
- absolute path and argv only
- an environment built from nothing
- stdin closed
- a 20 s timeout; the process group is killed on timeout, on stdout overflow and when the call is
  dropped. After the leader is reaped the group is never signalled again, because its id could
  then be reused.
- stdout capped at 64 KiB in a pre-sized buffer, zeroized on drop, with overflow killing the process
- stderr drained, capped and sanitized, for the log only

**Cache** (`valetkey-secrets/src/cache.rs`):
- 5 minutes, single-flight per key
- the key includes the config hash
- failures aren't cached
- the broker applies policy **before** it asks the cache
