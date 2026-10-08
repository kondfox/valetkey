# `doctor` doesn't show a target's role closure

Status: Open · Since: 2026-10-05 (M2b review, non-blocking)

**The debt.** A read can see everything any role in the login role's closure can read, because
one statement can switch roles ([[sql-tools]]). Humans should see that effective scope before they
approve a target, but `doctor` never connects to databases, so it can't list the closure.

**Paying it down.** Add an opt-in `valetkey doctor --connect` (or show it in `allow`) that runs
the closure query and lists the roles and their notable privileges per target.
