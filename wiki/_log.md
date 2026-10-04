# Wiki log

Append-only, newest first, one self-contained line per entry (format in [[CLAUDE]]).

- 2026-10-04 · M1 · Added the worked end-to-end example to architecture (one valetkey_targets call), new features/ (init, allow, doctor, valetkey_targets), workflows/development, tech-debt/mcp-roots-deprecation, decisions dev-root-only-in-debug-builds and toolchain-and-msrv; 4 glossary terms.
- 2026-10-04 · decisions · Applied the M0-change review: the valetkey root comes from the OS user database (never HOME); separate snapshot (`projects/`) and write-approval (`write-approvals/`) stores; approvals bound to one request by hash, nonce and expiry; ~/.claude rows narrowed so agent memory stays editable.
- 2026-10-04 · M0 · Recorded the M0 spike: new integrations/ section (8 pages: Claude Code sandbox and client, Postgres, rmcp, rustls-platform-verifier, Cloud SQL proxy, dist/Homebrew, GitHub Actions); decisions m0-go-no-go, out-of-band-write-approval, local-secret-store, valetkey-root-dir, broker-environment-allowlist; updated postgres guards, exposure, approval scope, provenance, vendor CLIs; 7 glossary terms, 3 FAQ entries. Spike artifacts on branch spike/m0 (a0f1593, f917930).
- 2026-10-04 · decisions · Added [[2026-10-04-commit-message-convention]]: Conventional Commits with a Unicode gitmoji after the colon; rule added to AGENTS.md.
- 2026-10-04 · wiki · Bootstrapped the wiki from the LLM-wiki seed: schema with organic folder creation and the public-repo rule; index, architecture, glossary (29 terms), faq; 14 decision pages from the design sessions and `docs/` (commit `6181a1d`). Integration pages are deferred until M0 verifies behaviour; M0 results go to the wiki instead of `docs/spike.md`.
