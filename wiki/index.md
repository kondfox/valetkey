# valetkey wiki

The LLM-maintained knowledge base for valetkey: the *why* behind the design, verified facts about
the systems we depend on, and what we learn while building. The schema and maintenance rules are
in [[CLAUDE]].

**Status (2026-10-04):** design approved and M0 spike done ([[2026-10-04-m0-go-no-go]]); no product
code yet. Next: M1, the skeleton (`docs/design.md §10`).

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

More sections appear as the work needs them (see the category catalog in [[CLAUDE]]).

## Log

- [[_log]]: what changed in the wiki, newest first
