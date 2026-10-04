# Integrations

One page per external system valetkey depends on: the contract we rely on and its verified quirks,
not vendor docs. Every claim says how and when it was verified, or is marked **UNVERIFIED**. See
the integration page skeleton in [[CLAUDE]].

- [[claude-code-sandbox]]: the OS sandbox around the agent's shell (Seatbelt, bubblewrap), and the
  sandbox runtime it's built on
- [[claude-code-client]]: Claude Code as MCP client: environment, project dir, scopes, hooks,
  elicitation, frontmatter
- [[postgres]]: read-only escapes and the guards that stop them; the auth guard
- [[rmcp]]: the Rust MCP SDK
- [[rustls-platform-verifier]]: TLS trust sources and environment variables
- [[cloud-sql-auth-proxy]]: unix-socket layout and path limits
- [[dist-and-homebrew]]: release tooling, the Homebrew tap, tap moves
- [[github-actions]]: hosted runners and what the sandbox needs on them
