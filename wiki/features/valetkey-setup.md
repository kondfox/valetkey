# `valetkey setup`

A human records which vendor CLIs the broker may run, in `~/.valetkey/config.toml` (`0600`). The
broker never looks tools up itself ([[2026-10-04-broker-environment-allowlist]]).

For `gcloud`:
1. resolve it through the human's `PATH` and canonicalize it
2. check the tool, the SDK root, `bin/`, `lib/` and the Python it will run with
   (`valetkey-secrets/src/trust.rs`):
   - refused inside the current project, in a temp dir, or inside a directory below home that
     contains `.git`, `valetkey.toml` or `.claude`
   - refused if any path or ancestor is owned by another user or is world-writable; group-writable
     is a warning
3. record `CLOUDSDK_PYTHON`: the SDK's bundled Python, else `python3` from `PATH`. A
   version-manager shim (pyenv, asdf, …) is refused, because it picks the interpreter from files
   like a project's `.python-version` ([[gcloud]]).
4. check **strictly** (group-writable is a refusal too) whatever steers gcloud: `CLOUDSDK_CONFIG`
   if the human has one set (a per-project config dir is refused), otherwise `~/.config/gcloud`,
   and the SDK's installation `properties` file. These set gcloud's endpoints, proxy and CA, so an
   agent-writable one could send the human's token anywhere.
5. show everything and save on `yes`

Interactive terminal only, and not from the home directory. `doctor` re-checks the recorded paths and says when to re-run `setup`.
Entry point: `crates/valetkey-cli/src/commands/setup.rs` (`review()` is the testable flow).
