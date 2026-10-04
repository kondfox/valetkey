# Commit messages: Conventional Commits with a gitmoji after the colon

Date: 2026-10-04 · Status: Active

## Context
The maintainer wants every commit message to use [gitmoji](https://gitmoji.dev/) and to follow
[Conventional Commits](https://www.conventionalcommits.org/).

## Options considered
1. `📝 docs(wiki): …`: gitmoji first, a common gitmoji style. It breaks the Conventional Commits
   rule that a message **must** start with the type, so spec-compliant parsers (commitlint's
   conventional preset, changelog generators) reject it or misread it.
2. **`docs(wiki): 📝 …`**: type first, gitmoji as the first word of the description.
3. `:memo:` shortcodes instead of Unicode: renders on GitHub, but not in a terminal `git log`.

## Decision
Option 2, with Unicode gitmoji: `<type>(<optional scope>): <gitmoji> <description>`. The rule is in
`AGENTS.md`.

## Why
It satisfies both conventions without breaking either one's tooling. The type stays machine-readable
for future changelog and release automation (`dist`), and the gitmoji stays visible everywhere.

## Consequences
- The first commit predated the convention and was reworded (history rewritten while the repo was
  hours old and had a single user).
- A commit-msg check (commitlint or a CI job) can be added with M1's CI.

## Sources
- Maintainer request, 2026-10-04
