#!/usr/bin/env bash
# A release may use only the exact protected-main commit that started this run:
# a merged release PR (push to main) or a manual retry dispatched from main.
# Usage: verify-release-source.sh TAG [--tag-may-be-absent]
# The automated pipeline verifies before it creates the tag, so the tag may be
# missing then; an existing tag must still identify exactly this commit.
set -euo pipefail
: "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}" "${GITHUB_REF:?}" "${GITHUB_EVENT_NAME:?}"
tag=${1:?Specify the release tag}
tag_may_be_absent=false
case ${2:-} in
  '') ;;
  --tag-may-be-absent) tag_may_be_absent=true;;
  *) echo "Unknown option: $2" >&2; exit 1;;
esac
[[ ($GITHUB_EVENT_NAME == workflow_dispatch || $GITHUB_EVENT_NAME == push) && $GITHUB_REF == refs/heads/main ]] || {
  echo 'Release source must be a push to main or a manual dispatch from main.' >&2
  exit 1
}
[[ $GITHUB_SHA =~ ^[a-f0-9]{40}$ && $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo 'Expected a full source SHA and stable release tag.' >&2
  exit 1
}
[[ $(git rev-parse HEAD) == "$GITHUB_SHA" ]] || { echo 'Checkout differs from dispatch commit.' >&2; exit 1; }
# matching-refs answers 200 with an empty list for a missing tag, so an API
# failure is never mistaken for absence.
existing=$(gh api "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/$tag" --jq "[.[] | select(.ref == \"refs/tags/$tag\")] | length")
if [[ $existing == 0 && $tag_may_be_absent == true ]]; then
  :
else
  [[ $existing == 1 ]] || { echo "Release tag $tag does not exist." >&2; exit 1; }
  # The commits endpoint accepts a full ref and peels annotated tags.
  tagged_sha=$(gh api "repos/$GITHUB_REPOSITORY/commits/refs/tags/$tag" --jq .sha)
  [[ $tagged_sha == "$GITHUB_SHA" ]] || { echo 'Tag does not identify the tested release commit.' >&2; exit 1; }
fi

main_base=$(gh api "repos/$GITHUB_REPOSITORY/compare/$GITHUB_SHA...main" --jq .merge_base_commit.sha)
[[ $main_base == "$GITHUB_SHA" ]] || { echo 'Release source is no longer in main history.' >&2; exit 1; }

# Require a completed push run of the canonical CI workflow on main. Exact
# ref/repository/SHA and the stable gate job are required on its latest attempt.
query='[.workflow_runs[] | select(.event == "push" and .head_branch == "main" and .status == "completed" and .conclusion == "success")][0] | .id // empty'
run=$(gh api --method GET "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml/runs" \
  -f event=push -f branch=main -f head_sha="$GITHUB_SHA" -F per_page=20 --jq "$query")
[[ $run =~ ^[0-9]+$ ]] || { echo 'No successful verification run for this main commit.' >&2; exit 1; }
run_state=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run" \
  --jq '[.head_repository.full_name,.head_sha,.head_branch,.event,.conclusion,.path] | join(" ")')
[[ $run_state == "$GITHUB_REPOSITORY $GITHUB_SHA main push success .github/workflows/ci.yml" ]] || {
  echo 'Verification run metadata does not match the release source.' >&2
  exit 1
}
gate=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run/jobs?filter=latest&per_page=100" \
  --jq '[.jobs[] | select(.name == "LASA verification gate") | .conclusion] | join(" ")')
[[ $gate == success ]] || { echo 'The canonical verification gate did not pass.' >&2; exit 1; }
