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

`wiki/architecture.md` will contain a worked end-to-end example (added at M1) showing the pattern
every new adapter or secret source follows. Use it as the template.

## What this project is

valetkey lets AI coding agents use credentials without being able to read them: an MCP broker
outside the agent's sandbox, a signed binary installed outside every repo, and a fence generated
from the project's config.

- Spec: `docs/design.md`. Threat model: `docs/threat-model.md`. Changing either is a design change:
  get it reviewed, and record the *why* in `wiki/decisions/`.
- Status: M1 done on 2026-10-04: a Rust workspace with `init`, `allow`, `doctor` and the MCP tool
  `valetkey_targets`. Next is M2, the Postgres read path (`docs/design.md §10`).
- Building, testing and CI: `wiki/workflows/development.md`. Before every commit:
  `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`.

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
