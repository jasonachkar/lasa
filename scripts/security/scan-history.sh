#!/usr/bin/env bash
# Keep matched material and commit messages out of console logs and artifacts.
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ $(git rev-parse --is-shallow-repository) != false ]]; then
  echo 'Full Git history is required.' >&2
  exit 1
fi
options=(--redact=100 --no-banner --log-level=error --max-archive-depth=2 --max-decode-depth=2)
gitleaks git --log-opts='--all --full-history' "${options[@]}"
git log --all --format='%B' | gitleaks stdin "${options[@]}"
tree=$(mktemp -d)
trap 'rm -rf "$tree"' EXIT
git archive HEAD | tar -xf - -C "$tree"
gitleaks dir "$tree" --max-target-megabytes=4 "${options[@]}"
