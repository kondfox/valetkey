# valetkey

**Let AI agents use credentials without seeing them.**

valetkey is a credential broker for AI coding agents. The agent gets narrow, audited
operations, such as a read-only query on the staging database or a GET on an allowlisted API path.
It never gets the password or token behind them.

It's an MCP server, so any MCP-capable agent can call it. The hard guarantee comes from pairing it
with the agent's OS-enforced sandbox; Claude Code is supported first.

> Status: design phase. Nothing to install yet. See [docs/design.md](docs/design.md) and
> [docs/threat-model.md](docs/threat-model.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
