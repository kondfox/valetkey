# FAQ

## Why can't a simple wrapper script hide the password from the agent?
The agent runs as the same OS user and has a shell, so it can read whatever the wrapper reads. Only
an OS-enforced boundary (the fence) stops that. [[2026-10-04-credential-broker-pattern]]

## Why not run the broker from the repo, like a normal dev tool?
The agent can edit repo files, and the broker runs outside the sandbox. Planted code would run with
the developer's cloud login at the next start. That was the critical finding in the prototype's
first review. [[2026-10-04-binary-provenance-and-registration]]

## Why does a database on `localhost` need a protected socket?
The sandboxed agent may bind local TCP ports, so it can pose as the database and collect the
password. Protection follows the secret's source, not the host.
[[2026-10-04-secret-exposure-classification]]

## Why doesn't every write ask for approval?
A prompt only helps when valetkey is the agent's only route to the target. Prompts that protect
nothing train people to click through. [[2026-10-04-write-approval-scope]]

## Why is native Windows "unfenced"?
Claude Code has no sandbox there, so nothing keeps the agent away from the secret stores.
[[2026-10-04-windows-via-wsl2]]

## I edited `valetkey.toml` and every tool now refuses. Why?
The broker serves only the snapshot a human approved. Run `valetkey allow` in a normal terminal.
Comment-only edits don't need this. [[2026-10-04-human-approved-config-snapshot]]
