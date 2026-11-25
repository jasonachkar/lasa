#!/usr/bin/env bash
# Tag a built release and approve its protected deployment as the owner.
set -euo pipefail
export GITHUB_REPOSITORY=${GITHUB_REPOSITORY:-jasonachkar/lasa}
run=${1:?Usage: approve.sh RUN_ID vX.Y.Z}
tag=${2:?Missing release tag}
root=$(cd "$(dirname "$0")" && pwd)
fail() { printf '%s\n' "$1" >&2; exit 1; }
[[ $run =~ ^[1-9][0-9]*$ ]] || fail 'Expected a numeric GitHub Actions run ID.'
[[ $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || fail 'Expected a stable release tag vX.Y.Z.'
[[ ${GITHUB_ACTIONS:-} != true ]] || fail 'Approve releases from the owner session.'
run_api="repos/$GITHUB_REPOSITORY/actions/runs/$run"
run_info=$(gh api "$run_api")
sha=$(jq -er --arg repo "$GITHUB_REPOSITORY" '
  select(.head_repository.full_name == $repo and .head_branch == "main" and
         .path == ".github/workflows/release.yml" and
         (.event == "push" or .event == "workflow_dispatch")) |
  .head_sha | select(test("^[a-f0-9]{40}$"))
' <<< "$run_info") || fail 'Expected a release workflow run from this repository on main.'
# The pending deployments endpoint is authoritative for environment review.
# The overall workflow status can lag changes to the deployment gate.
environment=$(gh api "$run_api/pending_deployments" --jq '.[] | select(.environment.name == "release" and .current_user_can_approve) | .environment.id')
if [[ ! $environment =~ ^[0-9]+$ ]]; then
  status=$(jq -r '[.status, .conclusion] | map(select(. != null)) | join(" / ")' <<< "$run_info")
  fail "Release run $run has no deployment awaiting your approval (GitHub reports $status). Use setup to retry a failed run."
fi
build=$(gh api "$run_api/jobs?filter=all&per_page=100" --jq '[.jobs[] | select(.name == "build")] | max_by(.id) | .conclusion // empty')
[[ $build == success ]] || fail 'The release build must succeed before tagging.'
changelog=$(gh api "repos/$GITHUB_REPOSITORY/contents/CHANGELOG.md?ref=$sha" -H 'Accept: application/vnd.github.raw')
version=$(bash "$root/plan.sh" identify <<< "$changelog")
[[ $tag == "v$version" ]] || fail "Requested $tag, but the release commit's changelog specifies v$version."

bash "$root/create-tag.sh" "$tag" "$sha"
gh api --method POST "$run_api/pending_deployments" -F "environment_ids[]=$environment" \
  -f state=approved -f comment="Approved $tag through scripts/release/approve.sh" --jq 'length' >/dev/null
printf 'Approved %s in https://github.com/%s/actions/runs/%s\n' "$tag" "$GITHUB_REPOSITORY" "$run"
