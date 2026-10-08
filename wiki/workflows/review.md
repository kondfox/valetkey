# The review loop

Every change gets an adversarial review before it lands (maintainer's rule, `AGENTS.md`). Over
M0–M2 this loop found real holes in every round that mattered, so the brief below is the one that
worked.

## The reviewer

- A **read-only subagent, fresh per change** (a new milestone, plan or PR). It reads and reports;
  it never edits code. Keep the same reviewer across that change's rounds (continue it with
  `SendMessage`), or paste the open blockers into the re-review brief.
- It gets the files to read (spec, threat model, the diff or plan, relevant wiki pages) and the
  focus areas for this change.
- **Threat model to apply:** the agent is hostile. It runs as the same OS user, inside the
  sandboxed shell (Seatbelt or bubblewrap). Its file tools (Read, Edit, Write) are governed only
  by Claude Code permission rules, not the OS sandbox. It can call any MCP tool with any
  arguments.
- It **verifies cheap facts** itself (the crates.io API with a neutral User-Agent and no personal
  data, docs, crate sources) and marks anything it can't verify **UNVERIFIED** instead of
  guessing. Unverified behaviour becomes a test or a spike item, not an assumption.
- It describes gaps at the design level, not as step-by-step exploits.

## The output

A verdict (`approved` / `needs_revision`), then findings ranked by severity, **blocking separated
from non-blocking**, each with a concrete fix. It ends with:

```json
{"verdict": "...", "blocking": ["..."], "concerns": ["..."], "questions": ["..."]}
```

## The rounds

1. **Plans first.** For a milestone, the plan is reviewed before any code. The reviewer accepts or
   rejects each scope decision (deviations from the spec) with reasons.
2. **Code.** Fix every blocker. Fix non-blocking findings too when they're cheap; otherwise record
   them as `wiki/tech-debt/` pages so they aren't lost.
3. **Re-review rounds** only check that the blockers are resolved and that nothing new contradicts
   the spec or itself. They don't re-review everything.
4. **At most 5 rounds.** If blockers remain after the fifth, stop and ask the maintainer, listing
   the open blockers and the options.

## Afterwards

- Code: open the PR once the reviewer approves and CI is green (`AGENTS.md`).
- Docs: commit to `main`.
- Say in the PR or commit what the review found and fixed.
