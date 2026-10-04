# valetkey is developed in a public GitHub repo, dual-licensed MIT OR Apache-2.0

Date: 2026-10-04 · Status: Active

## Context
The first plan was a repo on an internal, VPN-only Git host. That rules out anonymous installs and
Homebrew, and that host had no macOS CI runners. The maintainer wanted Homebrew to work.

## Options considered
- Internal Git host: token-gated downloads, no Homebrew, macOS builds on a self-registered Mac runner
- **Public GitHub**: free hosted macOS, Linux and Windows runners for public repos; `dist`-generated
  releases, installers and a Homebrew tap; anonymous downloads
- The company's GitHub organization: not possible yet, because the maintainer can't create repos
  there

## Decision
Public repo `kondfox/valetkey`, which may be transferred to an organization later. Licensed
`MIT OR Apache-2.0`, the Rust convention (Apache adds a patent grant).

## Why
- Every distribution channel the usage design wanted (Homebrew, curl and PowerShell installers,
  `self-update`, CI on all three OSes) becomes free and simple.
- The security design doesn't rely on being secret, so publishing it costs nothing.

## Consequences
- **Nothing internal may enter the repo** (rule in `wiki/CLAUDE.md`).
- After a transfer, GitHub redirects the old URLs, but the old path must never be reused. The
  Homebrew tap name changes; M0 item 9 checks tap migration.
- A `SECURITY.md` is needed before the first release.

## Sources
- GitHub Actions hosted-runner docs, checked 2026-10-04
- Design sessions on 2026-10-04 (private transcripts; summarized here).
