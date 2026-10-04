# GitHub Actions

Where valetkey's CI runs, including the fence tests.

## What we rely on

- Hosted runners, including macOS, are free with unlimited minutes for public repos: `macos-latest`
  (arm64), `macos-15-intel`, `ubuntu-latest` (GitHub docs, 2026-10-04).
- The sandbox runtime runs on both without a model ([[claude-code-sandbox]]); the M0 probe workflow
  passed on `macos-latest` (macOS 26.6.2) and `ubuntu-latest` (24.04.5, kernel 6.17).

## Quirks

- **Ubuntu 24.04 blocks unprivileged user namespaces** (AppArmor), so bubblewrap fails
  (`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`). Fix:
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` before the tests.
- The Linux runner is an Azure VM: the instance-metadata endpoint `169.254.169.254` is live, so a
  fence test that expects it blocked is a real test there.
- macOS runners have no Docker, and can't grant TCC consent for `osascript` tests.

## Sources

- `.github/workflows/spike-sandbox.yml` on branch `spike/m0` (commit `a0f1593`); run
  https://github.com/kondfox/valetkey/actions/runs/37221248457
