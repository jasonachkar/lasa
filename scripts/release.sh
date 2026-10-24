#!/usr/bin/env bash
# Shared release engine; callers must verify the reviewed source before invocation.
set -euo pipefail
umask 077
trap 'printf "LASA release failed at line %s. Published assets and tags are immutable; rerun after resolving the preceding error.\n" "$LINENO" >&2' ERR
: "${APT_SIGNING_KEY:?Missing signing key}"
: "${APT_SIGNING_FINGERPRINT:?Missing signing fingerprint}"
: "${GITHUB_REPOSITORY:?Missing source repository}"
: "${RUNNER_TEMP:?Missing runner temporary directory}"
[[ $APT_SIGNING_FINGERPRINT =~ ^[A-F0-9]{40}$ ]] || exit 1
provider=${LASA_RELEASE_PROVIDER:-azure}
source_branch=${LASA_RELEASE_BRANCH:-main}
git check-ref-format --branch "$source_branch" >/dev/null
source_ref=$(python3 -c 'import sys; from urllib.parse import quote; print(quote(sys.argv[1], safe=""))' "$source_branch")
check_source() {
  bash scripts/check-publisher.sh "$provider"
  test "$(gh api "repos/$GITHUB_REPOSITORY/git/ref/heads/$source_ref" --jq .object.sha)" = "$commit" || {
    echo 'The selected source branch advanced. Update to its newest commit before publishing.' >&2
    exit 1
  }
}
temp=$(mktemp -d "$RUNNER_TEMP/lasa-release.XXXXXX")
export GNUPGHOME="$temp/gnupg"
mkdir -m 0700 "$GNUPGHOME"
# shellcheck disable=SC2317
cleanup() { gpgconf --kill gpg-agent || true; rm -rf "$temp"; }
trap cleanup EXIT
printf '%s\n' "$APT_SIGNING_KEY" | gpg --batch --import
commit=$(git rev-parse HEAD)
# Refuse a queued old commit and a competing publisher before any remote writes.
check_source
export VERSION RELEASE_TAG RELEASE_PROVENANCE=openpgp
VERSION=$(bash scripts/next-version.sh "$commit")
RELEASE_TAG=v$VERSION
if tagged_commit=$(git rev-parse --verify --quiet "$RELEASE_TAG^{commit}"); then
  test "$tagged_commit" = "$commit" || {
    echo 'The calculated version tag belongs to a different commit. Reconcile release history before allocating another release; no tag was moved.' >&2
    exit 1
  }
fi
if draft=$(gh api "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG" --jq .draft 2> "$temp/release-error"); then
  test "$(gh api "repos/$GITHUB_REPOSITORY/commits/$RELEASE_TAG" --jq .sha)" = "$commit" || {
    echo 'The existing release tag resolves to a different source commit. Its assets and documentation were not reused.' >&2
    exit 1
  }
  if [ "$draft" = false ]; then
    # Existing GitHub-origin releases retain their stricter OIDC verification.
    # A present detached signature must verify; it cannot fall back to OIDC.
    if ! gh api "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG" --jq '.assets[].name' > "$temp/asset-names"; then exit 1; fi
    if ! grep -qx SHA256SUMS.asc "$temp/asset-names"; then export RELEASE_PROVENANCE=github; fi
    # Verification and download happen in the publisher; do not rebuild bytes.
    check_source
    bash scripts/publish-docs.sh "$VERSION"
    bash scripts/publish-from-actions.sh
    if [ "$provider" = local ]; then bash scripts/publish-docs.sh current; fi
    exit 0
  fi
elif ! grep -q 'HTTP 404' "$temp/release-error"; then
  cat "$temp/release-error" >&2
  exit 1
fi
# Remove only generated output so old versions cannot enter this manifest.
rm -rf dist
bash scripts/build-signed-packages.sh "$VERSION"
tar --sort=name --mtime="@$(git show -s --format=%ct HEAD)" --owner=0 --group=0 --numeric-owner -C dist -cf - licenses | gzip -n > "dist/lasa-$VERSION-licenses.tar.gz"
bash scripts/write-release-manifest.sh "$VERSION"
gpg --batch --yes --armor --local-user "$APT_SIGNING_FINGERPRINT!" --detach-sign dist/SHA256SUMS
gpg --batch --armor --export "$APT_SIGNING_FINGERPRINT" > dist/release-signing-key.asc
check_source
if git rev-parse "$RELEASE_TAG" >/dev/null 2>&1; then
  test "$(git rev-parse "$RELEASE_TAG^{commit}")" = "$commit"
else
  gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs" -f "ref=refs/tags/$RELEASE_TAG" -f "sha=$commit" >/dev/null
fi
if ! gh release view "$RELEASE_TAG" >/dev/null 2>&1; then
  gh release create "$RELEASE_TAG" --verify-tag --draft --generate-notes
fi
# Recheck immediately before clobbering a repairable draft; published bytes are protected.
test "$(gh api "repos/$GITHUB_REPOSITORY/releases/tags/$RELEASE_TAG" --jq .draft)" = true || { echo 'Release became published while building; rerun to reuse its assets.' >&2; exit 1; }
gh release upload "$RELEASE_TAG" dist/lasa-*-linux-amd64 dist/lasa-*-linux-arm64 dist/*.deb dist/*.rpm dist/*.pkg.tar.zst dist/*.pkg.tar.zst.sig dist/*.apk dist/*.cdx.json dist/*.tar.gz dist/SHA256SUMS dist/SHA256SUMS.asc dist/release-signing-key.asc --clobber
check_source
gh release edit "$RELEASE_TAG" --draft=false
# Stable documentation must not wait for a successful APT indexing/deployment.
bash scripts/publish-docs.sh "$VERSION"
bash scripts/publish-from-actions.sh
if [ "$provider" = local ]; then bash scripts/publish-docs.sh current; fi
