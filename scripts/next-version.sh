#!/usr/bin/env bash
# Highest stable ancestor tag + conventional commits, with no source-file edits.
set -euo pipefail
commit=${1:-HEAD}
git rev-parse --verify "$commit^{commit}" >/dev/null
previous=
while IFS= read -r candidate; do
  if [[ $candidate =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then previous=$candidate; break; fi
done < <(git tag --merged "$commit" --sort=-v:refname)
if [ -z "$previous" ]; then printf '0.1.0\n'; exit 0; fi
if [[ $(git rev-parse "$previous^{commit}") == $(git rev-parse "$commit^{commit}") ]]; then printf '%s\n' "${previous#v}"; exit 0; fi
IFS=. read -r major minor patch <<< "${previous#v}"
messages=$(git log --format=%B "$previous..$commit")
if grep -Eq 'BREAKING CHANGE:|^[a-zA-Z]+(\([^)]*\))?!:' <<< "$messages"; then
  major=$((major+1)); minor=0; patch=0
elif grep -Eq '^feat(\([^)]*\))?:' <<< "$messages"; then
  minor=$((minor+1)); patch=0
else
  patch=$((patch+1))
fi
printf '%s.%s.%s\n' "$major" "$minor" "$patch"
