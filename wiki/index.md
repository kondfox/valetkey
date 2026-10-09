# valetkey wiki

The LLM-maintained knowledge base for valetkey: the *why* behind the design, verified facts about
the systems we depend on, and what we learn while building. The schema and maintenance rules are
in [[CLAUDE]].

**Status (2026-10-09):** M0, M1 and M2 are merged. M3a (`sql_execute`, `valetkey approve`, the
audit log) is in review; M3b (verified TLS) follows ([[2026-10-09-m3-scope]]). Current status and
working rules: `AGENTS.md`.

## Start here

- [[architecture]]: the three-part isolation model and how a tool call flows
- [[glossary]]: the vocabulary (broker, fence, exposed/protected, snapshot, …)
- [[faq]]: questions worth answering once

## Specs (sources, not wiki pages)

- [`docs/design.md`](../docs/design.md): usage, stack, mechanisms, milestones, spike questions
- [`docs/threat-model.md`](../docs/threat-model.md): attacks, mitigations, residual risks

## Sections

- [Decisions](decisions/_index.md): why things are the way they are
- [Integrations](integrations/_index.md): verified behaviour of Claude Code, Postgres and the
  rest of what we depend on
- [Features](features/_index.md): what each command and tool does, with entry points
- [Workflows](workflows/_index.md): building, testing, CI
- [Tech debt](tech-debt/_index.md): owed work, open and paid down

More sections appear as the work needs them (see the category catalog in [[CLAUDE]]).

## Log

- [[_log]]: what changed in the wiki, newest first
