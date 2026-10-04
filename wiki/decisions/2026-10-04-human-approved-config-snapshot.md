# The broker only serves a config snapshot a human approved (`valetkey allow`)

Date: 2026-10-04 · Status: Active

## Context
`valetkey.toml` is committed in the project repo, so the agent can edit it. The design review found
that the agent could add a target that sends a protected secret to a server it controls.

## Options considered
- Make the config file write-protected. That's brittle: humans need to edit it, and git checkouts
  rewrite it.
- **An approval step, like `direnv allow`**

## Decision
`valetkey allow` (`design.md §6.1`):
- It canonicalizes the parsed config and stores a snapshot plus a blake3 hash in a write-denied
  snapshot store (`~/.valetkey/projects/<project-key>/`), keyed by the canonical project root.
- The broker serves the **snapshot**. If the working file's hash differs, every tool refuses.
- `allow` stores exactly what it displayed, never re-reading the file.
- Each change carries a risk label based on its effect.

## Why
- A human stays in the loop for exactly the changes that matter. Hashing the canonical form means
  comment and whitespace edits don't cause approval fatigue.
- Serving the snapshot, not the file, removes a check-then-use race.
- Direnv's version of this pattern is familiar to developers.

## Consequences
- After any meaningful config edit, every developer has to re-run `allow`. The agent can make calls
  fail by toggling the file, which is a documented denial of service.
- Each clone and each worktree is approved separately.

## Sources
- `docs/design.md` §6.1; `docs/threat-model.md` A8, A19c (commit `6181a1d`)
- Design sessions on 2026-10-04 (private transcripts; summarized here).
