#!/usr/bin/env bash
# Backward-compatible Azure entrypoint. The shared engine also supports local builds.
set -euo pipefail
export LASA_RELEASE_PROVIDER=azure LASA_RELEASE_BRANCH=main
exec bash "$(dirname "$0")/release.sh"
