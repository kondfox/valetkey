# Protected local secrets live in valetkey's own store (`local://`), not the OS keychain

Date: 2026-10-04 · Status: Active

## Context
`keyring://` was meant to be the protected local option. M0 showed that the macOS sandbox always
allows the keychain's Mach service: a sandboxed `security find-generic-password -w` read a test
item, and there's no setting to remove the service ([[claude-code-sandbox]]).

## Options considered
1. **A valetkey-owned file store** under `~/.valetkey/secrets/`, deny-read by the fence, the same
   on every platform.
2. Keep `keyring://` and add `denyRead: ["~/Library/Keychains"]`. It blocks the file keychain, but
   breaks `gh` and git credential helpers inside the agent's shell, and the data-protection
   keychain is untested.
3. Cloud vaults only: projects without a vault would get no protected secrets.

## Decision
Option 1, chosen by the maintainer on 2026-10-04:
- `local://<id>` is one `0600` file per secret under `~/.valetkey/secrets/`. `valetkey secret set`
  writes there, and `init` offers to move `.env` passwords into it.
- `keyring://` stays available, but counts as **exposed on macOS**. On Linux it's protected while
  unix sockets are fully denied (the Secret Service is on D-Bus).

## Why
- It's protected by the same mechanism as every cloud credential file: an OS deny-read, which M0
  confirmed for every child process on both platforms.
- It doesn't break the developer's other tools inside the sandbox.

## Consequences
- Secrets are stored unencrypted at rest, with file permissions only, like gcloud's or AWS's
  credential files. Encryption at rest can be added later without changing the scheme.
- Keychain items of *other* tools stay readable from the macOS sandbox; that's a residual risk in
  the threat model.

## Sources
- [[claude-code-sandbox]] (keychain probes); `docs/design.md §6.0`; [[2026-10-04-m0-go-no-go]]
