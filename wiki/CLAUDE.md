# Wiki schema

This file is the single source of truth for **when** to update the valetkey wiki, **how** to write
its pages, and which categories exist. Every session that touches the repo consults it.

The wiki follows the [LLM Wiki pattern](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f):
an LLM-maintained knowledge base, updated incrementally as a side effect of normal work.

## Layers

1. **Sources: read-only ground truth.** Read them; never edit them during wiki maintenance.
   - The code (once it exists: `crates/`, `schema/`, `install/`, `tests/`).
   - The reviewed specs: [`docs/design.md`](../docs/design.md) and
     [`docs/threat-model.md`](../docs/threat-model.md). Changing them is a design change, not wiki
     maintenance.
   - Git history: `git log`, `git show`, `git blame`.
   - GitHub PRs and issues, via `gh` (repo `kondfox/valetkey`).
   - `wiki/assets/`, for raw material a human drops in (notes, transcripts, screenshots). The
     folder doesn't exist until someone needs it.
2. **The wiki: writable, derived.** Cross-linked Markdown pages in `wiki/`. Links use
   `[[page-name]]` (the file name without `.md`; add the folder if the name is ambiguous).
3. **The schema:** this file.

### Wiki vs specs

`docs/` holds the **spec**: what valetkey is designed to be, reviewed as a whole. The wiki holds
what the spec doesn't:
- **why** each choice was made (`decisions/`)
- verified facts about the systems we depend on (`integrations/`)
- what we learn while building

Link to spec sections (`design.md §6.2`) instead of copying them. When a spec and a wiki page
disagree, flag it in both places and in `_log.md`. Don't silently pick one.

## Public repository rule

**This repo is public.** Never write internal names into the wiki: no client or project names, no
internal hostnames, URLs or ticket ids, no people's names or email addresses. When material comes
from private sources (an earlier project-specific prototype, private session transcripts), describe
it generically, e.g. "an earlier project-specific prototype (TypeScript, private monorepo)". Use
made-up example names such as `acme-stage`, `staging-app` or `local-app`.

## Categories

**Folders are created organically.** None exists until the first page that needs it. When that
happens:
1. create the folder with an `_index.md` (purpose, page format, and an Active/Resolved split where
   the catalog says so)
2. link it from `index.md`
3. log it in `_log.md`

Root pages: `index.md` (map of content), `architecture.md`, `glossary.md`, `faq.md`, `_log.md`.

Catalog of known categories (created on first use):

| Folder | One page per | Split |
|---|---|---|
| `decisions/` | design or architecture decision: `YYYY-MM-DD-<slug>.md` | Active / Superseded |
| `integrations/` | external system we depend on: Claude Code (sandbox, permissions, MCP client), `rmcp`, Postgres, vendor CLIs, Homebrew/`dist`, GitHub Actions. Contract and verified quirks, not vendor docs. | — |
| `bugs/` | notable bug postmortem: `YYYY-MM-DD-<slug>.md` | Open / Resolved |
| `tech-debt/` | longer-lived owed work | Open / Paid down |
| `hacks/` | short-lived workaround | Active / Removed |
| `features/` | user-visible capability: a command, MCP tool, adapter or secret source | — |
| `workflows/` | how something gets done: release, dev setup, fence testing | — |
| `runbooks/` | what to do when something breaks: step by step, real commands | — |
| `assets/` | raw human-dropped material (a source, not wiki pages) | — |

Other categories may be added only when content genuinely fits none of these. Add the folder to
this table and add a trigger below. Evolution should be explicit and rare.

## When to update the wiki

Treat this as a checklist for every non-trivial task:

- **Decision made** (design, architecture, tooling, process) → `decisions/YYYY-MM-DD-<slug>.md`.
  Capture the *why*. Skip it if the diff makes the why obvious. A decision that replaces an older
  one moves the older page to Superseded and links both ways.
- **M0 spike question answered**, or any behaviour of an external system verified →
  `integrations/<system>.md`, with how it was verified (command, version, OS). Record go/no-go
  results from `design.md §11` in a decision page and link it from the integration pages.
- **Feature implemented or changed** (command, MCP tool, adapter, secret source) → `features/`, with
  entry-point `file:line` links.
- **Workaround added** → `hacks/`. **Accepted longer-lived debt** → `tech-debt/`. Update the
  folder's `_index.md` too.
- **Non-trivial bug fixed** → `bugs/YYYY-MM-DD-<slug>.md`, only when the root cause was surprising
  or the class is likely to recur. **Anything security-relevant is always worth a page.**
- **Release, CI or dev workflow added or changed** → `workflows/`.
- **Recurring failure or incident handled** → `runbooks/`.
- **Non-obvious question came up** → `faq.md`. **Domain term came up** → `glossary.md`.
- **Files dropped in `assets/`** → compile them into the right pages.
- **Always** append one line to `_log.md`.

## When NOT to update

- trivial changes: renames, formatting, lint fixes, dependency bumps
- anything already in `AGENTS.md`: link to it instead
- anything trivially derivable from the code or the specs
- speculative plans: the specs hold the plan, the wiki describes what *is* and why
- areas the current task didn't touch

When in doubt, link to the source (`file:line`, commit SHA, PR number, spec section) instead of
copying. A smaller true wiki beats a padded one.

## How to write pages

- One concept per page. Split a page that grows past ~200 lines.
- Lead with the answer, then the provenance.
- Cross-reference liberally with `[[page-name]]`.
- Provenance is mandatory for non-obvious claims: spec section, `file:line` (when stable), commit
  SHA, PR or issue number, or for verified behaviour, the command and the version it ran against.
  Mark unverified claims **UNVERIFIED**.
- Flag contradictions instead of overwriting. Keep the truer version and note it in `_log.md`.
- Dates are absolute (`YYYY-MM-DD`), never "recently".

### Decision page

```markdown
# <Decision as a statement>

Date: YYYY-MM-DD · Status: Active | Superseded by [[...]]

## Context
## Options considered
## Decision
## Why
## Consequences
## Sources
```

**Why** carries the most weight: it's the reason this page exists.

### Bug postmortem

```markdown
# <Symptom in one line>

Date: YYYY-MM-DD · Status: Open | Resolved

## Symptom
## Root cause
## Fix
## Lessons
## Sources
```

### Integration page

```markdown
# <System>

## What we rely on       (each item: claim · verified how/when · or UNVERIFIED)
## Quirks
## Sources
```

### `_log.md`

Append-only, newest first, **one self-contained line per entry**:

```
- YYYY-MM-DD · <area> · <what changed in the wiki and why> (<commit/PR if any>)
```

## Tooling boundaries

- No formatter or Markdown linter touches the wiki today (`rustfmt` ignores Markdown). If one is
  added (dprint, Prettier, markdownlint), exclude `wiki/` in the same change.
- The wiki is committed to git. **Wiki updates land in the same commit or PR as the change that
  triggered them**, so `git log` ties them together.
- `wiki/_log.md` uses the `union` merge driver (`.gitattributes`), so concurrent appends don't
  conflict. Keep every entry a single line.
