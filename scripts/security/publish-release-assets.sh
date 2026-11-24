#!/usr/bin/env bash
set -euo pipefail
: "${GITHUB_REPOSITORY:?}"
if [[ ${GITHUB_ACTIONS:-} == true ]]; then
  echo 'Run publication locally with GitHub CLI authenticated as the repository owner.' >&2
  exit 1
fi
owner=$(gh api "repos/$GITHUB_REPOSITORY" --jq .owner.login)
[[ -n $owner && $(gh api user --jq .login) == "$owner" ]] || {
  echo 'Publication requires GitHub CLI authentication as the repository owner.' >&2
  exit 1
}
tag=${1:?Specify the release tag}
directory=${2:?Specify the asset directory}
root=$(cd "$(dirname "$0")" && pwd)
version=${tag#v}
bash "$root/verify-release-source.sh" "$tag"
python3 "$root/verify-release-assets.py" "$directory" "$version"
bash "$root/verify-release-attestation.sh" "$directory/SHA256SUMS"

# Query the authenticated releases listing, which includes drafts. Avoid
# interpreting a failed permission/network check as a missing release.
lookup() {
  gh api --paginate "repos/$GITHUB_REPOSITORY/releases?per_page=100" --jq \
    ".[] | select(.tag_name == \"$tag\") | .id"
}
id=$(lookup)
if [[ -z $id ]]; then
  gh release create "$tag" --repo "$GITHUB_REPOSITORY" --verify-tag --draft --generate-notes
  id=$(lookup)
fi
[[ $id =~ ^[0-9]+$ ]] || { echo 'No unique release was found for the tag.' >&2; exit 1; }
endpoint="repos/$GITHUB_REPOSITORY/releases/$id"
status=$(gh api "$endpoint" --jq '[.tag_name,.draft,.prerelease] | join(" ")')
if [[ $status == "$tag false false" ]]; then
  existing=$(mktemp -d)
  trap 'rm -rf "$existing"' EXIT
  gh release download "$tag" --repo "$GITHUB_REPOSITORY" --dir "$existing"
  python3 "$root/verify-release-assets.py" "$existing" "$version"
  cmp "$directory/SHA256SUMS" "$existing/SHA256SUMS"
  exit 0
fi
[[ $status == "$tag true false" ]] || { echo 'Expected a stable draft release.' >&2; exit 1; }

assets=$(gh api --paginate --slurp "$endpoint/assets?per_page=100")
for file in "$directory/"*; do
  name=${file##*/}
  mapfile -t remote < <(jq -r --arg name "$name" '.[][] | select(.name == $name) | .digest // "unknown"' <<< "$assets")
  if (( ${#remote[@]} == 0 )); then
    gh release upload "$tag" "$file" --repo "$GITHUB_REPOSITORY"
  else
    digest=$(sha256sum "$file")
    [[ ${#remote[@]} -eq 1 && ${remote[0]} == "sha256:${digest%% *}" ]] || {
      echo "Existing draft asset differs: $name" >&2
      exit 1
    }
  fi
done
# Independently confirm that every remote entry has the expected digest and
# that no unexpected asset would be published alongside the attested payload.
assets=$(gh api --paginate --slurp "$endpoint/assets?per_page=100")
expected=$(cd "$directory" && sha256sum -- * | awk '{print $2, "sha256:" $1}' | LC_ALL=C sort)
actual=$(jq -r '.[][] | "\(.name) \(.digest)"' <<< "$assets" | LC_ALL=C sort)
[[ $expected == "$actual" ]] || { echo 'Remote draft inventory differs from the verified assets.' >&2; exit 1; }
[[ $(gh api "$endpoint" --jq .draft) == true ]] || { echo 'Draft state changed.' >&2; exit 1; }
bash "$root/verify-release-source.sh" "$tag"
gh api --method PATCH "$endpoint" -F draft=false --jq '.id' >/dev/null
