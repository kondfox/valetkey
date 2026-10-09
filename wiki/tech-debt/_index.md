# Tech debt

One page per longer-lived owed work item. Pages move from *Open* to *Paid down*; they aren't
deleted.

## Open
- [[mcp-roots-deprecation]]: the project-dir cross-check relies on MCP roots, which are deprecated
- [[target-enum-in-tool-schemas]]: tools take the target as a string, not a closed set
- [[exposed-tcp-targets-skip-checks]]: the Postgres checks are skipped for exposed TCP targets
- [[doctor-shows-role-closure]]: humans can't see a target's effective read scope
- [[testcontainers-port-flake]]: an intermittent test-container failure with unknown cause
- [[broker-env-not-scrubbed]]: the broker keeps its inherited environment (paid down in M3b)

## Paid down

(none)
