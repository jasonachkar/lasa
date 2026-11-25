#!/usr/bin/env bash
# Commit versioned documentation to a distribution branch. Pushing is separate.
set -euo pipefail
umask 077
site=$(cd "${1:?Usage: publish-docs.sh SITE VERSION}" && pwd)
version=${2:?Missing documentation version}
root=$(cd "$(dirname "$0")/.." && pwd)

cd "$site"
branch=$(git symbolic-ref --short HEAD)
if [[ -n $(git status --porcelain) ]]; then
  echo 'Commit the staged package repository before generating documentation.' >&2
  exit 1
fi
if ! versions=$(git show "HEAD:versions.json" 2>/dev/null); then versions='[]'; fi
printf '%s\n' "$versions" | python3 "$root/scripts/check-docs-version.py" "$version" /dev/stdin
python3 "$root/scripts/prepare-docs.py"
mike_args=(--config-file "$root/mkdocs.yml" --branch "$branch" --remote origin)
# The first site published a version literally named "current". Packaged and
# bookmarked links use /current/, so it becomes an alias of every release.
if printf '%s\n' "$versions" | python3 -c 'import json, sys; sys.exit(0 if any(v.get("version") == "current" for v in json.load(sys.stdin)) else 1)'; then
  mike delete "${mike_args[@]}" current
fi
# Mike preserves the package tree and existing documentation versions.
mike deploy "${mike_args[@]}" --alias-type redirect --update-aliases "$version" latest current
mike set-default "${mike_args[@]}" latest
