# gcloud (Google Cloud CLI)

How the `gcp-sm://` source fetches secrets. Verified on 2026-10-05 by reading the source of Google
Cloud SDK 496.0.0 (`lib/surface/secrets/versions/access.py`,
`lib/googlecloudsdk/command_lib/secrets/fmt.py`, `bin/gcloud`).

## What we rely on

- `gcloud secrets versions access latest --secret=<name> --project=<project> --quiet` prints the
  secret using the default format
  `value[terminator="",private](payload.data.decode(base64).decode(utf8))`: the **decoded UTF-8
  value with no trailing newline**. valetkey passes no `--format`.
  `--format='get(payload.data)'` would print base64url instead. Binary secrets get corrupted by
  the UTF-8 conversion (gcloud's own doc), which is fine for passwords.
- The `gcloud` launcher is a shell script that runs Python. It uses `$CLOUDSDK_PYTHON` if set,
  else the SDK's bundled Python (`platform/bundledpythonunix/bin/python3`) if present, else the
  first `python3`/`python` on `PATH` (`bin/gcloud`, lines ~106–135). So `valetkey setup` records
  `CLOUDSDK_PYTHON` explicitly: under the broker's minimal `PATH`, macOS's `/usr/bin/python3`
  stub could prompt to install developer tools and hang.
- Credentials live in `~/.config/gcloud` unless `CLOUDSDK_CONFIG` says otherwise. That directory
  is the source's fence rule (deny-read, M4).

## Quirks

- The broker sets `CLOUDSDK_CORE_DISABLE_PROMPTS=1` and disables the update check, and passes
  `--quiet`, so gcloud never waits for input.
- Not yet checked against a live secret (needs a GCP project). The fake `gcloud` in
  `crates/valetkey-secrets/tests/sources.rs` mirrors the format above. **UNVERIFIED** end to end.

## Sources

- Google Cloud SDK 496.0.0 source, read 2026-10-05; `crates/valetkey-secrets/src/sources.rs`
