#!/usr/bin/env bash
# A release may use only the exact protected-main commit that started this run.
set -euo pipefail
: "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}" "${GITHUB_REF:?}" "${GITHUB_EVENT_NAME:?}"
tag=${1:?Specify the existing release tag}
[[ $GITHUB_EVENT_NAME == workflow_dispatch && $GITHUB_REF == refs/heads/main ]] || {
  echo 'Release source must be a manual dispatch from main.' >&2
  exit 1
}
[[ $GITHUB_SHA =~ ^[a-f0-9]{40}$ && $tag =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || {
  echo 'Expected a full source SHA and stable release tag.' >&2
  exit 1
}
[[ $(git rev-parse HEAD) == "$GITHUB_SHA" ]] || { echo 'Checkout differs from dispatch commit.' >&2; exit 1; }
# The commits endpoint accepts a full ref and peels annotated tags.
tagged_sha=$(gh api "repos/$GITHUB_REPOSITORY/commits/refs/tags/$tag" --jq .sha)
[[ $tagged_sha == "$GITHUB_SHA" ]] || { echo 'Tag does not identify the tested dispatch commit.' >&2; exit 1; }

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
