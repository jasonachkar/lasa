#!/usr/bin/env bash
# Wait for the canonical CI push run on a main commit to finish. The release
# source verification then requires it (and its gate job) to have succeeded.
set -euo pipefail
: "${GITHUB_REPOSITORY:?}"
sha=${1:?Usage: wait-for-ci.sh SHA [TIMEOUT_MINUTES]}
timeout=${2:-150}
[[ $sha =~ ^[a-f0-9]{40}$ ]] || { echo 'Expected a full commit SHA' >&2; exit 1; }
deadline=$(( $(date +%s) + timeout * 60 ))
while :; do
  state=$(gh api --method GET "repos/$GITHUB_REPOSITORY/actions/workflows/ci.yml/runs" \
    -f event=push -f branch=main -f head_sha="$sha" -F per_page=20 \
    --jq '[.workflow_runs[] | .status] | if length == 0 then "missing" elif all(. == "completed") then "completed" else "running" end')
  if [[ $state == completed ]]; then
    echo "CI finished for $sha"
    exit 0
  fi
  if (( $(date +%s) >= deadline )); then
    echo "Timed out after $timeout minutes waiting for CI on $sha (state: $state)" >&2
    exit 1
  fi
  echo "CI on $sha: $state; checking again in 60 seconds"
  sleep 60
done
