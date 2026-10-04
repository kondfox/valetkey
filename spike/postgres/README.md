# M0 Postgres spike

Throwaway experiments from the M0 spike (2026-10-04). Results are in `wiki/integrations/postgres.md`
on `main`; this branch is never merged.

- `Dockerfile`: `postgres:16`/`17` plus plpython3u, plperlu, `http`, `pg_background`, and `pg_net`
  built from source.
- `setup*.sql`, `q24*.sql`, `q31*.sql`, `q_bg*.sql`, `side.sql`: the read-only escape tests (run as a
  non-superuser with `PGOPTIONS='-c default_transaction_read_only=on'`, inside `BEGIN READ ONLY`).
- `catalog_final.sql`, `catalog_builtin_grants.sql`: the catalog checks (queries B and C).
- `pg_hba_spike.conf`: per-user `password` / `md5` / `scram-sha-256` methods for the auth tests.
- `q2auth/`: tokio-postgres 0.7.18 auth-guard prototype that refuses cleartext and MD5 password
  requests through `Config::connect_raw`.
