#!/usr/bin/env bash
# Exit nonzero if another provider owns publication. Never changes provider state.
set -euo pipefail
umask 077
expected=${1:?Usage: check-publisher.sh github|azure|local}
case "$expected" in github|azure|local) ;; *) echo 'Invalid publishing provider' >&2; exit 1;; esac
temporary=$(mktemp)
trap 'rm -f "$temporary"' EXIT
if provider=$(gh api "repos/${GITHUB_REPOSITORY:-jasonachkar/lasa}/actions/variables/PUBLISHING_PROVIDER" --jq .value 2> "$temporary"); then
  :
elif grep -q 'HTTP 404' "$temporary"; then
  provider=github # Original GitHub bootstrap did not set an explicit provider.
else
  echo 'Could not read the publishing provider; publication stopped before writes.' >&2
  exit 1
fi
if [ "$provider" != "$expected" ]; then
  echo 'Publishing provider changed; this publisher must stop before writing releases or documentation.' >&2
  exit 1
fi
