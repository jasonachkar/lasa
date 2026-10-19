#!/usr/bin/env bash
set -euo pipefail
assets=${1:?Usage: verify-release-assets.sh ASSET_DIRECTORY github|openpgp}
policy=${2:?Missing provenance policy}
case "$policy" in
  github)
    : "${GITHUB_REPOSITORY:?Missing source repository}"
    gh attestation verify "$assets/SHA256SUMS" --repo "$GITHUB_REPOSITORY"
    ;;
  openpgp)
    : "${APT_SIGNING_FINGERPRINT:?Missing trusted signing fingerprint}"
    [[ $APT_SIGNING_FINGERPRINT =~ ^[A-F0-9]{40}$ ]] || { echo 'Invalid trusted signing fingerprint' >&2; exit 1; }
    status=$(gpg --batch --status-fd 1 --verify "$assets/SHA256SUMS.asc" "$assets/SHA256SUMS")
    grep -Eq "^\[GNUPG:\] VALIDSIG $APT_SIGNING_FINGERPRINT " <<< "$status" || { echo 'Release manifest was not signed by the configured primary APT key' >&2; exit 1; }
    ;;
  *) echo "Unknown release provenance policy: $policy" >&2; exit 1 ;;
esac
# Authenticate the manifest before reading any paths it contains.
(cd "$assets" && sha256sum --strict -c SHA256SUMS)
