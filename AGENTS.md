# valetkey: agent instructions

## Project knowledge base: `wiki/`

`wiki/` is an LLM-maintained knowledge base for this project. It captures everything the code and
the specs alone don't show: decisions and their rationale, verified behaviour of the systems we
depend on, bug postmortems, hacks and tech debt, runbooks, and the domain glossary.

**On every non-trivial task, before starting work:**

- Read `wiki/CLAUDE.md`, the schema. It defines when to update the wiki and how to write pages.
  Treat its "When to update" list as a checklist for the current task.
- Skim `wiki/index.md`, the map of content. Find the pages relevant to the area you're touching
  and read them.

**While working:**

- When a decision is made, an M0 question is answered, a non-obvious bug is fixed, a hack is added,
  an integration's behaviour is verified, a domain term comes up, or an incident is handled:
  create or update the relevant wiki page per the schema, and append one line to `wiki/_log.md`.
  Wiki updates land in the **same commit (or PR)** as the change that triggered them.
- Folders in `wiki/` are created only when a page needs one (see the schema's catalog).
- No formatter touches the wiki (see the schema's tooling boundaries).

**For new feature work:**

`wiki/architecture.md` has a worked end-to-end example (one MCP call traced through every crate,
with `file:line` links) showing the pattern every new tool, adapter or secret source follows. Use
it as the template.

## What this project is

valetkey lets AI coding agents use credentials without being able to read them: an MCP broker
outside the agent's sandbox, a signed binary installed outside every repo, and a fence generated
from the project's config.

- Spec: `docs/design.md`. Threat model: `docs/threat-model.md`. Changing either is a design change:
  get it reviewed, and record the *why* in `wiki/decisions/`.
- **Status (2026-10-08).** The milestones are in `docs/design.md §10`; the latest entries in
  `wiki/_log.md` say what changed most recently.
  - M0 (spike), M1 (skeleton) and M2a (secret sources, runner, `setup`, `secret`; PR #2) are
    merged.
  - M2b (Postgres read path, `sql_query`, `sql_describe`) is in PR #3, reviewed and waiting for
    the maintainer's merge.
  - **Next: M3**: writes (`sql_execute`), out-of-band approval with `valetkey approve`, the audit
    log, and verified TLS for remote targets. The spec sections:
    - §6.10: approval (and `wiki/decisions/2026-10-04-out-of-band-write-approval.md`)
    - §6.2: TLS (post-TLS auth guard, local-address check on the resolved address, pinning,
      deny-read for local CA keys)
    - §6.7 step 7: the audit record's fields
    - §6.8: TLS and CA bundle settings only from user-level config
    - §6.9: the auth guard wraps the post-TLS stream
  - **Where M3 starts:** until PR #3 merges, branch `m3-…` from `m2b-postgres` and open M3 as a
    PR stacked on #3. After #3 merges, merge `main` into the M3 branch (see "How we work").
  - **Open follow-ups** from earlier reviews are tech-debt pages: see `wiki/tech-debt/_index.md`
    (on the branch you work on; M2b's are in PR #3).
  - Until M4 (fence detection), protected targets are refused unless `require_fence = false`.
- Building, testing and CI: `wiki/workflows/development.md`. Before every commit:
  `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`.

## How we work

These are the maintainer's standing instructions.

- **Every change gets an adversarial review before it lands**, following
  `wiki/workflows/review.md`. That page has the reviewer brief (a read-only subagent, fresh per
  change, the hostile-agent threat model, verify-or-mark-UNVERIFIED), the output format, and the
  rounds:
  - the plan before code, for milestones
  - re-reviews that only check blockers
  - at most 5 rounds; then stop and ask the maintainer, listing the open blockers

  Non-blocking findings are fixed, or recorded as `wiki/tech-debt/` pages.
- **Code goes through pull requests. Never merge a PR yourself;** the maintainer does.
  - Work on a branch and push it for CI.
  - Open the PR once the review approves and CI is green on Linux, macOS and Windows.
  - A large milestone may be split into stacked PRs.
  - The maintainer merges with "rebase and merge", which rewrites the SHAs. To update a stacked
    branch afterwards, **merge `main` into it** and check that the merged tree matches the
    reviewed one. Never force-push.
- **Doc-only changes** (wiki, `docs/`, this file) are committed straight to `main` after the
  review approves.
- **Commit only after the test command itself exits 0**, never chained onto a `grep` or `tail`
  that succeeds anyway.
- **Verify behaviour on the real system before relying on it**: sandbox capabilities, Postgres,
  vendor CLIs. Assumptions were wrong often enough in M0 and M2 (`wiki/integrations/`). Record
  what you verified, and how, on the integration page.
- The Postgres integration tests need Docker with Linux containers. They skip without it
  locally, and fail in CI on Linux.

## Rules

- **Commit messages** follow [Conventional Commits](https://www.conventionalcommits.org/) with a
  [gitmoji](https://gitmoji.dev/) (Unicode) right after the colon:
  `<type>(<optional scope>): <gitmoji> <description>`, e.g. `feat(postgres): ✨ add sql_describe`,
  `fix(fence): 🐛 deny writes to the resolved hooks path`, `docs(wiki): 📝 record M0 results`.
  The type comes first so spec-compliant tooling parses it. Pick the gitmoji that matches the
  change; breaking changes use `!` and a `BREAKING CHANGE:` footer as the spec says.
  See `wiki/decisions/2026-10-04-commit-message-convention.md`.

- **This repository is public.** Never commit internal names: no client or project names, no
  internal hostnames, URLs or ticket ids, no people's names or emails. Use made-up examples
  (`acme-stage`, `staging-app`).
- A security-relevant change updates `docs/threat-model.md` in the same change.
- Never weaken a fence rule or a guard to make something work. If a sandbox capability can't be
  verified, follow the go/no-go table in `docs/design.md §11`.
