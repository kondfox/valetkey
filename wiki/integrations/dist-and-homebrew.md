# dist and Homebrew

Release tooling and the Homebrew tap. Verified from `dist` 0.33.0 and Homebrew 7.0.7 source and docs
on 2026-10-04.

## What we rely on

- **Tap publishing:** `tap = "kondfox/homebrew-tap"`, `publish-jobs = ["homebrew"]`, a
  `HOMEBREW_TAP_TOKEN` secret (PAT with `repo` scope). Prereleases are skipped unless
  `publish-prereleases = true`.
- **Installer location:** `install-path` (`"~/dir/bin"`, `"$VAR/sub"`, or a fallback list). Users can
  override with `<APP>_INSTALL_DIR`. The installer writes an `env` file and edits `~/.profile`.
- **Signatures:** no native per-file signing. Use a custom `global-artifacts-jobs` workflow
  (`secrets: inherit`) that signs the archives and uploads an Actions artifact named
  `artifacts-…`; the release step attaches `artifacts/*` (from the template; not in
  `dist-manifest.json`, **UNVERIFIED** that nothing filters them).
- The generated formula installs leftover archive files to `share/<formula>/`. The shell installer
  keeps only binaries.
- Attestations: `github-attestations = true` (experimental).
- **Homebrew layout:** `bin/<b>` → `../Cellar/<f>/<v>/bin/<b>` directly; `opt/<f>` →
  `../Cellar/<f>/<v>` is a separate link. The prefix is user-owned. Taps live in
  `$(brew --repository)/Library/Taps/<user>/homebrew-<tap>`.

## Quirks

- **Moved tap repos** are followed automatically on `brew update` (Homebrew PR #22706, 2026-06):
  the tap dir is renamed and the remote reset. Trust for the old name is dropped, and Homebrew ≥ 6
  requires `brew trust` for non-official taps, so users re-trust. `tap_migrations.json` is a
  per-formula mechanism and doesn't apply to a repo transfer. Existing kegs keep the old tap name
  in their tab; lookup by short name probably works (**UNVERIFIED** end to end).
- GitHub redirects stop for good if a new repo is created at the old path.

## Sources

- axodotdev/cargo-dist v0.33.0 book and templates; Homebrew/brew 7.0.7 (`keg.rb`, `tap.rb`,
  `cmd/update.sh`, `docs/Tap-Trust.md`), read 2026-10-04
