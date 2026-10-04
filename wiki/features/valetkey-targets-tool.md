# MCP tool `valetkey_targets`

The agent's starting point: the approved targets of its project, and why each one is or isn't
usable. Walked through line by line in [[architecture]].

Output (JSON):
- `project`:
  - `root`
  - `dir_verified`: whether `CLAUDE_PROJECT_DIR` matched the client's first MCP root
  - `approval`: `approved`, `not_approved`, `stale`, `root_mismatch` or `no_project`
  - `message`: for a human, with the absolute `allow` command
- `client`: `name`, `version`, and the `fence_profile` that applies (`claude-code`)
- `targets[]`: `id`, `kind`, `writable`, `secret_exposure`, `available`, `reason`

Rules:
- Only an approved, unchanged snapshot is listed. Otherwise the list is empty.
- Protected targets are refused while the project dir is unverified
  ([[tech-debt/mcp-roots-deprecation]]).
- `valetkey.toml` is read without following links (`valetkey-core/src/safe_read.rs`). Read and
  parse errors go to `~/.valetkey/logs/mcp.log`; the agent gets a fixed message, never file
  content.
- Exposure is recomputed per call. Protected targets are also refused when the valetkey root is
  accessible to other users.
- In M1 every target is unavailable (no adapter tools yet).

Entry point: `crates/valetkey-mcp/src/lib.rs`, tests in `crates/valetkey-mcp/tests/targets.rs`.
