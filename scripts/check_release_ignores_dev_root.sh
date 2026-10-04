#!/usr/bin/env bash
# Proves that a release build ignores VALETKEY_DEV_ROOT (decision 2026-10-04-dev-root-only-in-
# debug-builds) and HOME: with both set to decoys, `valetkey doctor` must still report
# <home>/.valetkey, where <home> comes from the user database.
set -euo pipefail
bin="${1:-target/release/valetkey}"
bin="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"
decoy="$(mktemp -d)/decoy-root"
home="$(python3 -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"
fake_home="$(mktemp -d)/fake-home"
out="$(cd "$(mktemp -d)" && HOME="$fake_home" VALETKEY_DEV_ROOT="$decoy" "$bin" doctor || true)"
echo "$out"
if grep -q "$decoy" <<<"$out"; then
  echo "FAIL: the release build used VALETKEY_DEV_ROOT" >&2; exit 1
fi
if grep -q "valetkey root: $fake_home" <<<"$out"; then
  echo "FAIL: the release build used HOME" >&2; exit 1
fi
if ! grep -q "valetkey root: $home/.valetkey" <<<"$out"; then
  echo "FAIL: expected the root $home/.valetkey" >&2; exit 1
fi
if grep -q "debug build" <<<"$out"; then
  echo "FAIL: the release build reports itself as a debug build" >&2; exit 1
fi
echo "OK: the release build ignores VALETKEY_DEV_ROOT and HOME"
