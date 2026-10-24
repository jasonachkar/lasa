#!/usr/bin/env bash
set -euo pipefail
umask 077
trap 'printf "Package publication failed at line %s. See the preceding command error.\n" "$LINENO" >&2' ERR
: "${RUNNER_TEMP:?Missing runner temporary directory}"
: "${RELEASE_TAG:?Missing release tag from workflow}"
: "${GITHUB_REPOSITORY:?Missing source repository from workflow}"
: "${DISTRIBUTION_REPOSITORY:?Run the distribution bootstrap first}"
: "${DISTRIBUTION_BRANCH:?Missing distribution branch}"
: "${DISTRIBUTION_DEPLOY_KEY:?Missing distribution deploy key secret}"
: "${APT_SIGNING_KEY:?Missing APT signing key secret}"
: "${APK_SIGNING_KEY:?Run the updated owner bootstrap for the Alpine signing key}"
: "${APK_PUBLIC_KEY_SHA256:?Missing Alpine public-key pin}"
: "${APT_SIGNING_FINGERPRINT:?Missing signing fingerprint variable}"
: "${APT_REPOSITORY_URL:?Missing APT repository URL}"
[[ $DISTRIBUTION_REPOSITORY =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || exit 1
if [ -n "${LASA_RELEASE_PROVIDER:-}" ]; then bash scripts/check-publisher.sh "$LASA_RELEASE_PROVIDER"; fi
temp=$(mktemp -d "$RUNNER_TEMP/lasa-publish.XXXXXX")
export GNUPGHOME="$temp/gnupg"
mkdir -m 0700 "$GNUPGHOME"
# shellcheck disable=SC2317 # Invoked by the EXIT trap, including failed commands.
cleanup() { gpgconf --kill gpg-agent || true; rm -rf "$temp"; }
trap cleanup EXIT
printf '%s\n' "$APT_SIGNING_KEY" | gpg --batch --import
printf '%s\n' "$DISTRIBUTION_DEPLOY_KEY" > "$temp/key"
unset APT_SIGNING_KEY DISTRIBUTION_DEPLOY_KEY
chmod 0600 "$temp/key"
# Authenticate SSH host keys through GitHub's HTTPS API, never ssh-keyscan.
gh api meta --jq '.ssh_keys[] | "github.com " + .' > "$temp/known_hosts"
test -s "$temp/known_hosts"
printf -v GIT_SSH_COMMAND 'ssh -i %q -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%q' "$temp/key" "$temp/known_hosts"
export GIT_SSH_COMMAND
git clone --single-branch --branch "$DISTRIBUTION_BRANCH" "git@github.com:$DISTRIBUTION_REPOSITORY.git" "$temp/site"
mkdir -p "$temp/assets"
gh release download "$RELEASE_TAG" --repo "$GITHUB_REPOSITORY" --dir "$temp/assets"
bash scripts/verify-release-assets.sh "$temp/assets" "${RELEASE_PROVENANCE:-github}"
bash scripts/publish-distribution.sh "$temp/site" "$temp/assets" "${RELEASE_TAG#v}" "$GITHUB_REPOSITORY" "$APT_REPOSITORY_URL"
git -C "$temp/site" config user.name 'LASA release automation'
git -C "$temp/site" config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git -C "$temp/site" add .
if ! git -C "$temp/site" diff --cached --quiet; then
  git -C "$temp/site" commit -m "Publish LASA $RELEASE_TAG packages"
  if [ -n "${LASA_RELEASE_PROVIDER:-}" ]; then bash scripts/check-publisher.sh "$LASA_RELEASE_PROVIDER"; fi
  git -C "$temp/site" push origin "HEAD:$DISTRIBUTION_BRANCH"
fi
# A successful push alone does not mean the packages are downloadable via Pages.
for ((attempt=0; attempt<80; attempt++)); do
  if curl --proto '=https' --tlsv1.2 -fsSL "$APT_REPOSITORY_URL/dists/stable/InRelease" -o "$temp/served" && cmp -s "$temp/served" "$temp/site/apt/dists/stable/InRelease"; then
    echo 'GitHub Pages serves the newly signed APT repository.'
    exit 0
  fi
  sleep 10
done
echo "Distribution commit was pushed, but Pages did not serve it within 13 minutes. Check https://github.com/$DISTRIBUTION_REPOSITORY/actions and Pages policy; rerun this job after fixing it." >&2
exit 1
