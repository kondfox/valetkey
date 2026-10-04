# Only signed binaries reach the protected install dir, and only the installed copy can replace itself

Date: 2026-10-04 · Status: Active

## Context
The broker binary is the trusted computing base ([[2026-10-04-credential-broker-pattern]]). Each
review round found another way a fake binary could get in:
- symlinks in Homebrew paths
- a fake `valetkey` earlier on the human's `PATH`
- an `install` that checked signatures inside the very binary being checked

## Decision
`design.md §6.3`, `§8`:
- **Minisign is the only update-verification mechanism.** Keys are embedded in the binary, with a
  versioned list for rotation. Every asset ships a `.minisig`, Homebrew bottles included. GitHub
  attestations are optional extras that nothing depends on.
- Installers and Homebrew only *deliver* the binary. `valetkey install` copies it into valetkey's
  own write-denied dir and registers that copy at user scope by absolute path.
- After the first install, only the **installed copy** may verify and install a new binary
  (`<installed>/valetkey install --from <path>`). The first install is trust-on-first-use.
- Every hint valetkey prints uses the absolute path, and `install` prints a shell alias.

## Why
A check performed by the binary under test proves nothing. Trust has to flow from something already
trusted: the installed copy and its keys.

## Consequences
- `self-update` refuses on Homebrew installs (use `brew upgrade` plus `install --from`).
- The fence write-protects the install dir and the local Homebrew tap clone.

## Sources
- `docs/design.md` §6.3, §8; `docs/threat-model.md` A6, A7, A19b (commit `6181a1d`)
- Design sessions on 2026-10-04 (private transcripts; summarized here).
