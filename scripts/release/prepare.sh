#!/usr/bin/env bash
# Turn the top "## Unreleased" CHANGELOG section into a dated release heading.
# Merging that change to main is what publishes the release.
#
#   prepare.sh VERSION TITLE [--date YYYY-MM-DD]
#
# Compatible with macOS's system Bash 3.2.
set -euo pipefail
version=${1:?Usage: prepare.sh VERSION TITLE [--date YYYY-MM-DD]}
title=${2:?Missing release title}
date=$(date -u +%Y-%m-%d)
if [ "${3:-}" = --date ]; then date=${4:?Missing date}; fi
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
[[ $version =~ $semver ]] || { echo "Invalid version: $version" >&2; exit 1; }
[[ $date =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "Invalid date: $date" >&2; exit 1; }
case $title in *'('*|*')'*|'') echo 'The title must be non-empty and contain no parentheses' >&2; exit 1;; esac
cd "$(dirname "$0")/../.."
file=CHANGELOG.md
first=$(grep -m 1 '^## ' "$file" || true)
[[ $first == '## Unreleased' ]] || { echo "The first CHANGELOG section must be '## Unreleased' (found: ${first:-nothing})" >&2; exit 1; }
previous=$(sed -n -E 's/^## ([0-9]+\.[0-9]+\.[0-9]+) — .+ \([0-9]{4}-[0-9]{2}-[0-9]{2}\)$/\1/p' "$file" | head -n 1)
if [ -n "$previous" ]; then
  highest=$(printf '%s\n%s\n' "$version" "$previous" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
  [[ $version != "$previous" && $highest == "$version" ]] || { echo "Version $version must be greater than $previous" >&2; exit 1; }
fi
# The Unreleased section must say what changed.
body=$(awk '/^## /{n++; next} n==1' "$file" | grep -c '[^[:space:]]' || true)
[ "$body" -gt 0 ] || { echo 'The Unreleased section is empty; describe the changes first' >&2; exit 1; }
temp=$(mktemp)
awk -v heading="## $version — $title ($date)" '!done && $0=="## Unreleased" {print heading; done=1; next} {print}' "$file" > "$temp"
cat "$temp" > "$file"
rm -f "$temp"
printf 'Prepared %s in %s\n' "$version" "$file"
