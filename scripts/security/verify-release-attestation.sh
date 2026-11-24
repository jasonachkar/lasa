#!/usr/bin/env bash
set -euo pipefail
: "${GITHUB_REPOSITORY:?}" "${GITHUB_SHA:?}"
gh attestation verify "${1:?Specify the checksum manifest}" --repo "$GITHUB_REPOSITORY" \
  --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" \
  --source-ref refs/heads/main --source-digest "$GITHUB_SHA" \
  --deny-self-hosted-runners
