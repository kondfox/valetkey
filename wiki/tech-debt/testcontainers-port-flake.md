# Intermittent `PortNotExposed` in the Postgres tests

Status: Open · Since: 2026-10-05 (M2b)

**The debt.** Twice during full local workspace runs (Docker Desktop, macOS), several Postgres test
containers reported `does not expose port 5432/tcp` right after starting. It never happened when
the Postgres tests ran alone, didn't recur in four further full runs, and 13 containers started by
hand at once were all fine. The cause is unknown.

**In place.** The port lookup retries for 5 s, and on failure the test prints the container's
state (`docker inspect`) and its last log lines (`mapped_port` in the test files).

**Paying it down.** When it recurs, read the printed state and logs, fix the cause, and remove
whatever no longer helps.
