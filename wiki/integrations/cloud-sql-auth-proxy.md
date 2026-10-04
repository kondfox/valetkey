# Cloud SQL Auth Proxy

Humans start the proxy (v1 doesn't manage tunnels), placing its socket where the fence protects it.
Verified from the v2.26.0 source on 2026-10-04.

## What we rely on

- `--unix-socket D` creates `D/<project:region:instance>/.s.PGSQL.5432`; the base dir must exist
  (`internal/proxy/proxy.go` L956-1001, `internal/proxy/unix.go` L24-26).
- **Per-instance path:** `'<instance>?unix-socket-path=/abs/dir'` puts the socket at
  `/abs/dir/.s.PGSQL.5432` (the proxy creates `dir`; its parent must exist) (`cmd/root.go`
  L164-172, L933-991). valetkey's docs use `~/.valetkey/sockets/<alias>`.
- With a unix socket, that instance gets **no TCP listener**; `--unix-socket` with `--port` or
  `--address` is an error (`proxy.go` L852-858, L878-936). Health-check and admin servers are
  separate TCP listeners (not checked in detail).

## Quirks

- Socket path limits (Go): ≤ 103 bytes on macOS, ≤ 107 on Linux. With a 45-character instance
  name, every base under `~/Library/Application Support/…` or `~/.local/share/…` is too long
  (116–145 bytes); `~/.valetkey/sockets/<alias>` with an alias ≤ ~40 characters fits. Instance names
  can be much longer than 45 characters, so valetkey validates the full path per platform.

## Sources

- GoogleCloudPlatform/cloud-sql-proxy v2.26.0 source; Go `syscall_bsd.go` L191,
  `syscall_linux.go` L550-561
