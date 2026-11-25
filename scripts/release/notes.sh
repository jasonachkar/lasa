#!/usr/bin/env bash
# Print a released version's CHANGELOG section (without its heading).
set -euo pipefail
version=${1:?Usage: notes.sh VERSION}
cd "$(dirname "$0")/../.."
notes=$(awk -v v="$version" '
  /^## / { if (found) exit; if (index($0, "## " v " — ") == 1) { found=1; next } }
  found { print }' CHANGELOG.md)
[[ -n ${notes//[[:space:]]/} ]] || { echo "CHANGELOG has no notes for $version" >&2; exit 1; }
printf '%s\n' "$notes"
