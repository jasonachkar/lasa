#!/usr/bin/env bash
# Create a lightweight release tag on the verified commit, or confirm that an
# existing tag (from an interrupted run) already identifies exactly it.
# Repository rulesets forbid moving or deleting v* tags for every actor.
set -euo pipefail
: "${GITHUB_REPOSITORY:?}"
tag=${1:?Usage: create-tag.sh TAG SHA}
sha=${2:?Missing commit SHA}
[[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo "Invalid release tag: $tag" >&2; exit 1; }
[[ $sha =~ ^[a-f0-9]{40}$ ]] || { echo 'Expected a full commit SHA' >&2; exit 1; }
existing=$(gh api "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/$tag" --jq "[.[] | select(.ref == \"refs/tags/$tag\")] | length")
if [[ $existing == 0 ]]; then
  gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs" -f "ref=refs/tags/$tag" -f "sha=$sha" --jq .ref >/dev/null
  echo "Created $tag at $sha"
fi
tagged=$(gh api "repos/$GITHUB_REPOSITORY/commits/refs/tags/$tag" --jq .sha)
[[ $tagged == "$sha" ]] || { echo "Tag $tag identifies $tagged, not $sha" >&2; exit 1; }
echo "$tag identifies $sha"
