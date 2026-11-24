#!/usr/bin/env bash
# Update the owner's local distribution branch. Pushing it is a separate action.
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
# Mike preserves the package tree and existing documentation versions.
mike deploy --config-file "$root/mkdocs.yml" --branch "$branch" --remote origin --alias-type redirect --update-aliases "$version" latest
mike set-default --config-file "$root/mkdocs.yml" --branch "$branch" --remote origin latest
