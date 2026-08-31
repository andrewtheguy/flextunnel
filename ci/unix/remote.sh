#!/usr/bin/env bash
# Thin wrapper: the logic lives in the sibling devtools repo, parameterized by
# this repo's .devtools.conf.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
devtools="${DEVTOOLS_DIR:-$repo_root/../devtools}"
[ -f "$devtools/ci/unix/remote.sh" ] || {
  printf '%s\n' \
    "error: devtools not found at $devtools" \
    "  git clone git@github.com:andrewtheguy/devtools.git $repo_root/../devtools" \
    "  (or set DEVTOOLS_DIR)" >&2
  exit 1
}
DEVTOOLS_REPO_ROOT="$repo_root" exec "$devtools/ci/unix/remote.sh" "$@"
