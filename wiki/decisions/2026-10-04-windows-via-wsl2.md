# On Windows, the full guarantee requires WSL2; native Windows runs unfenced

Date: 2026-10-04 · Status: Active

## Context
valetkey must work on every major desktop OS. Claude Code's sandbox exists on macOS (Seatbelt) and
Linux/WSL2 (bubblewrap), but not on native Windows or WSL1, per Claude Code docs checked on
2026-10-04.

## Decision
- Windows users get the full guarantee by running the agent inside WSL2, with the Linux build of
  valetkey.
- Native Windows gets the broker in unfenced mode: only exposed secrets are served.
  The maintainer confirmed this on 2026-10-04.

## Why
There's no OS boundary to rely on in native Windows. Serving protected secrets there would turn
the broker into a way to get those secrets out.

## Consequences
- The Windows build is a secondary path.
- winget distribution only became possible once the repo was public ([[2026-10-04-public-github-repo]]).

## Sources
- `docs/design.md` §2.7, §6.4 (commit `6181a1d`); Claude Code sandboxing docs, 2026-10-04
  (UNVERIFIED beyond the docs; M0 verifies)
- Design sessions on 2026-10-04 (private transcripts; summarized here).
