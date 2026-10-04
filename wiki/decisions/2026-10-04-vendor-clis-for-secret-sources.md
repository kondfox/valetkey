# Cloud secret sources shell out to the vendor CLIs instead of linking SDKs

Date: 2026-10-04 · Status: Active

## Context
The broker has to fetch secrets from GCP Secret Manager, and later from AWS, Azure and 1Password.

## Options considered
- The vendor SDK crates (`google-cloud-secretmanager-v1`, `aws-sdk-secretsmanager`,
  `azure_security_keyvault_secrets`)
- **The vendor CLIs** the developer already uses (`gcloud`, `aws`, `az`, `op`), through a hardened
  process runner

## Decision
Vendor CLIs, behind the `SecretSource` trait. The OS keyring (`keyring` crate) and env-files are
read natively. The maintainer confirmed this on 2026-10-04.

## Why
- The CLIs reuse the developer's existing login (SSO, MFA, `aws sso login`), so valetkey needs no
  auth code of its own.
- The binary stays small. The GCP and Azure SDKs are young, and each SDK brings its own credential
  chain.
- The trait leaves room for an SDK backend later.

## Consequences
- The process runner has to be hardened (`design.md §6.8`):
  - argument arrays only, never a shell
  - a reduced environment
  - timeouts and kill on drop
  - forced non-interactive flags
  - redacted stderr

  The prototype's review had found crash and hang bugs in a naive runner.
- Credential file locations are resolved from the human's environment, not assumed
  (`design.md §6.5`).

## Sources
- `docs/design.md` §3, §6.5, §6.8 (commit `6181a1d`)
- Design sessions on 2026-10-04 (private transcripts; summarized here).
