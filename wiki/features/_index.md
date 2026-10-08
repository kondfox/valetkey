# Features

One page per user-visible capability: a command, an MCP tool, an adapter or a secret source.
Each page gives what it does, its rules, and its entry point (`file:line`).

- [[valetkey-init]]: a starter `valetkey.toml`
- [[valetkey-allow]]: a human reviews and approves the config
- [[valetkey-doctor]]: checks this machine and project
- [[valetkey-targets-tool]]: the MCP tool listing what the agent may use
- [[valetkey-setup]]: a human records which vendor CLIs the broker may run
- [[valetkey-secret]]: manage `local://` secrets
- [[secret-sources]]: how each `<scheme>://` secret is fetched
- [[sql-tools]]: `sql_query` and `sql_describe`
