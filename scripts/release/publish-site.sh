#!/usr/bin/env bash
# Publish verified release packages to the signed APT repository, refresh the
# Homebrew formula and installer, deploy the versioned documentation, and push
# the distribution site. Runs in the release workflow's protected environment.
#
#   publish-site.sh VERSION ASSET_DIR
#
# Environment (secrets come only from the `release` environment):
#   APT_SIGNING_SUBKEY               armored secret export of ONLY the CI signing subkey
#   DISTRIBUTION_DEPLOY_KEY          SSH key with write access to the distribution repo
#   APT_SIGNING_FINGERPRINT          pinned primary fingerprint (repository variable)
#   APT_SIGNING_SUBKEY_FINGERPRINT   CI signing subkey fingerprint (repository variable)
#   DISTRIBUTION_REPOSITORY, DISTRIBUTION_BRANCH, APT_REPOSITORY_URL, GITHUB_REPOSITORY
#   DISTRIBUTION_REMOTE              optional Git URL override (tests)
#   SERVED_SITE_URL                  optional; when set, wait until it serves the push
set -euo pipefail
umask 077
trap 'printf "Site publication failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
version=${1:?Usage: publish-site.sh VERSION ASSET_DIR}
assets=$(cd "${2:?Missing asset directory}" && pwd)
root=$(cd "$(dirname "$0")/../.." && pwd)
: "${APT_SIGNING_SUBKEY:?}" "${DISTRIBUTION_DEPLOY_KEY:?}" "${APT_SIGNING_FINGERPRINT:?}" "${APT_SIGNING_SUBKEY_FINGERPRINT:?}"
: "${DISTRIBUTION_REPOSITORY:?}" "${DISTRIBUTION_BRANCH:?}" "${APT_REPOSITORY_URL:?}" "${GITHUB_REPOSITORY:?}"
[[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo "Invalid version: $version" >&2; exit 1; }
[[ $DISTRIBUTION_REPOSITORY =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ && $DISTRIBUTION_BRANCH =~ ^[A-Za-z0-9._/-]+$ ]] || { echo 'Invalid distribution repository or branch' >&2; exit 1; }
primary=$APT_SIGNING_FINGERPRINT
subkey=$APT_SIGNING_SUBKEY_FINGERPRINT
[[ $primary == "$(cat "$root/deploy/apt/primary-fingerprint")" ]] || { echo 'APT_SIGNING_FINGERPRINT differs from the fingerprint pinned in the source tree' >&2; exit 1; }

work=$(mktemp -d)
export GNUPGHOME="$work/gnupg"
mkdir -m 0700 "$GNUPGHOME"
cleanup() { gpgconf --homedir "$GNUPGHOME" --kill all >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

# 1. Signing material: the primary must be an offline stub, the subkey usable.
printf '%s\n' "$APT_SIGNING_SUBKEY" | gpg --batch --quiet --import 2>/dev/null
secret=$(gpg --batch --with-colons --fixed-list-mode --list-secret-keys)
primaries=$(awk -F: '$1=="sec"{p=1;next} p&&$1=="fpr"{print $10;p=0}' <<< "$secret")
[[ $primaries == "$primary" ]] || { echo 'The CI signing secret belongs to an unexpected primary key' >&2; exit 1; }
primary_secret=$(awk -F: '$1=="sec"{print $15; exit}' <<< "$secret")
[[ $primary_secret == '#' ]] || { echo 'Refusing to publish: the CI secret contains the primary private key. Store only the signing subkey.' >&2; exit 1; }
subkey_record=$(awk -F: '$1=="ssb"{v=$2;e=$7;c=$12;s=$15;n=1;next} n&&$1=="fpr"{print $10":"v":"e":"c":"s;n=0}' <<< "$secret" | grep "^$subkey:" || true)
[[ -n $subkey_record ]] || { echo "The CI signing secret lacks subkey $subkey" >&2; exit 1; }
IFS=: read -r _ validity expires capabilities serial <<< "$subkey_record"
[[ $capabilities == *s* && $serial != '#' ]] || { echo "Subkey $subkey is not a usable signing key" >&2; exit 1; }
case $validity in r|e|i|n|d) echo "Subkey $subkey is revoked, expired or invalid" >&2; exit 1;; esac
if [[ -n $expires ]] && (( expires < $(date +%s) + 14 * 86400 )); then
  echo "Subkey $subkey expires within 14 days; rotate it with scripts/setup-ci-publishing.sh --rotate" >&2
  exit 1
fi
# Installed clients learn about the subkey through the packaged keyring, so
# publishing with a subkey the package does not carry would lock them out.
bash "$root/scripts/release/check-keyring.sh" "$root/deploy/apt/lasa-archive-keyring.asc" "$primary" "$subkey"
gpg --batch --armor --export "$primary" > "$work/public.asc"
bash "$root/scripts/release/check-keyring.sh" "$work/public.asc" "$primary" "$subkey"
python3 -I "$root/scripts/release/dearmor.py" "$root/deploy/apt/lasa-archive-keyring.asc" "$work/expected.gpg"
for arch in amd64 arm64; do
  dpkg-deb --fsys-tarfile "$assets/lasa_${version}_${arch}.deb" | tar -xOf - ./usr/share/keyrings/lasa-archive-keyring.gpg > "$work/packaged-$arch.gpg"
  cmp "$work/packaged-$arch.gpg" "$work/expected.gpg" || { echo "The $arch package does not carry the committed APT keyring" >&2; exit 1; }
done

# 2. Distribution checkout over SSH with a pinned GitHub host key.
printf '%s\n' "$DISTRIBUTION_DEPLOY_KEY" > "$work/deploy-key"
unset APT_SIGNING_SUBKEY DISTRIBUTION_DEPLOY_KEY
chmod 0600 "$work/deploy-key"
printf '%s\n' 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl' > "$work/known_hosts"
export GIT_SSH_COMMAND="ssh -i $work/deploy-key -o IdentitiesOnly=yes -o UserKnownHostsFile=$work/known_hosts -o StrictHostKeyChecking=yes -o BatchMode=yes"
remote=${DISTRIBUTION_REMOTE:-git@github.com:$DISTRIBUTION_REPOSITORY.git}
site="$work/site"
git clone --quiet --branch "$DISTRIBUTION_BRANCH" "$remote" "$site"
git -C "$site" config user.name 'LASA release automation'
git -C "$site" config user.email '41898282+github-actions[bot]@users.noreply.github.com'
before=$(git -C "$site" rev-parse HEAD)

# 3. Packages, signed indexes, formula and installer.
# Preserve the exact published index on a retry, including a migration
# signature the owner may have added after the first subkey-signed release.
packages_current() {
  grep -Fxq "  version \"$version\"" "$site/Formula/lasa.rb" 2>/dev/null || return 1
  local arch package digest
  for arch in amd64 arm64; do
    package="lasa_${version}_${arch}.deb"
    cmp -s "$assets/$package" "$site/apt/pool/main/l/lasa/$package" || return 1
    digest=$(sha256sum "$assets/$package")
    grep -Fxq "SHA256: ${digest%% *}" "$site/apt/dists/stable/main/binary-$arch/Packages" || return 1
  done
  gpgv --keyring "$work/expected.gpg" "$site/apt/dists/stable/InRelease" 2>/dev/null
}
if packages_current; then
  echo "Signed package repository already contains LASA $version"
else
  APT_SIGNING_KEYS="$subkey!" bash "$root/scripts/publish-distribution.sh" "$site" "$assets" "$version" "$GITHUB_REPOSITORY" "$APT_REPOSITORY_URL"
fi
# Clients verify with exactly the packaged keyring; so does this check.
gpgv --keyring "$work/expected.gpg" "$site/apt/dists/stable/InRelease" 2>/dev/null
git -C "$site" add --all
if ! git -C "$site" diff --cached --quiet; then
  git -C "$site" commit --quiet -m "Publish LASA v$version packages"
fi

# 4. Versioned documentation (Mike commits to the same branch).
bash "$root/scripts/publish-docs.sh" "$site" "$version"

# 5. Fast-forward push; the distribution ruleset rejects anything else.
after=$(git -C "$site" rev-parse HEAD)
if [[ $after == "$before" ]]; then
  echo "Distribution already contains LASA $version; nothing to push."
else
  git -C "$site" push --quiet origin "HEAD:refs/heads/$DISTRIBUTION_BRANCH"
  echo "Pushed LASA $version to $DISTRIBUTION_REPOSITORY ($before..$after)"
fi

# 6. Confirm what customers download is what was just signed.
if [[ -n ${SERVED_SITE_URL:-} ]]; then
  expected=$(git -C "$site" show HEAD:apt/dists/stable/InRelease)
  for attempt in $(seq 1 40); do
    served=$(curl --proto '=https' --tlsv1.2 -fsS -H 'Cache-Control: no-cache' "${SERVED_SITE_URL%/}/apt/dists/stable/InRelease?run=$attempt" || true)
    versions=$(curl --proto '=https' --tlsv1.2 -fsS -H 'Cache-Control: no-cache' "${SERVED_SITE_URL%/}/versions.json?run=$attempt" || true)
    if [[ $served == "$expected" ]] && grep -q "\"$version\"" <<< "$versions"; then
      echo "Served site matches the published LASA $version index and documentation"
      exit 0
    fi
    echo "Waiting for GitHub Pages to serve the new site (attempt $attempt/40)"
    sleep 30
  done
  echo 'The pushed site was not served within 20 minutes; check the Pages build of the distribution repository' >&2
  exit 1
fi
