# Tool schemas take the target as a plain string

Status: Open · Since: 2026-10-05 (M2)

**The debt.** `docs/design.md §2.5` wants each tool's JSON schema to list only the targets of its
kind, so the agent picks from a closed set. The tools take `target` as a free string instead,
because the approved targets are only known per call (after the session resolves the project),
while the tool list is fixed when the server starts. M2 decision D3 accepted this
([[2026-10-05-m2-scope]]).

**Mitigation in place.** The id is looked up in the approved snapshot and its kind checked; unknown
ids get a fixed error listing the approved ids. `valetkey_targets` is the discovery tool.

**Paying it down.** Override `list_tools` to build the schemas from the session (needs the client's
roots during `tools/list`), or emit `notifications/tools/list_changed` when the snapshot changes.
