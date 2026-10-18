#!/usr/bin/env bash
# Compatible with macOS's system Bash 3.2. No Linux host or Docker required.
set -euo pipefail
umask 077
stage=initialization
trap 'printf "LASA setup failed during %s (line %s). See the error above. No branch protections or required approvals were bypassed.\n" "$stage" "$LINENO" >&2' ERR
die() { printf '%s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: bash scripts/bootstrap-distribution.sh [--configure-only] [--repo OWNER/REPO] [--distribution-repo OWNER/REPO]

Installs missing publishing tools, authenticates with GitHub, creates a public
distribution repository, generates local signing/deploy keys, configures GitHub
secrets/variables and Pages, then tags this clean, already-pushed checkout and
waits for its release. Existing tags are never moved. No source branch is merged.
--configure-only configures publishing without creating a tag or a release.
GitHub/macOS may require interactive account or administrator consent.
EOF
}
repo=jasonachkar/lasa
distribution=
configure_only=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0;;
    --configure-only) configure_only=true; shift;;
    --repo) [ "$#" -ge 2 ] || die '--repo needs OWNER/REPO'; repo=$2; shift 2;;
    --distribution-repo) [ "$#" -ge 2 ] || die '--distribution-repo needs OWNER/REPO'; distribution=$2; shift 2;;
    *) die "Unknown argument: $1 (see --help)";;
  esac
done
[[ $repo =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || die 'Invalid source repository'
distribution=${distribution:-${repo%/*}/homebrew-lasa}
[[ $distribution =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || die 'Invalid distribution repository'
[[ $repo != "$distribution" ]] || die 'Source and distribution repositories must be different'
cd "$(dirname "$0")/.."
git rev-parse --show-toplevel >/dev/null
[[ -z $(git status --porcelain) ]] || die 'Checkout has uncommitted changes. Commit and push the intended release before running setup.'
commit=$(git rev-parse HEAD)
stage='installing publishing tools'
case "$(uname -s)" in
  Darwin)
    for prefix in /opt/homebrew /usr/local; do
      if [ -x "$prefix/bin/brew" ]; then export PATH="$prefix/bin:$PATH"; break; fi
    done
    if ! command -v gh >/dev/null || ! command -v gpg >/dev/null || ! command -v jq >/dev/null; then
      if ! command -v brew >/dev/null; then
        # Fetch the official installer at a reviewed immutable Git commit.
        installer=$(mktemp -d)
        git clone --quiet https://github.com/Homebrew/install.git "$installer/install"
        git -C "$installer/install" checkout --quiet be041513824fd2666a0e93cf5c3b0ca3bb0eb4b6
        /bin/bash "$installer/install/install.sh"
        rm -rf "$installer"
        case "$(uname -m)" in arm64) export PATH="/opt/homebrew/bin:$PATH";; *) export PATH="/usr/local/bin:$PATH";; esac
      fi
      command -v gh >/dev/null || brew install gh
      command -v gpg >/dev/null || brew install gnupg
      command -v jq >/dev/null || brew install jq
    fi
    state_base="$HOME/Library/Application Support/lasa-distribution"
    ;;
  Linux)
    if ! command -v gh >/dev/null || ! command -v gpg >/dev/null || ! command -v jq >/dev/null; then
      command -v apt-get >/dev/null || die 'Automatic Linux tool installation needs Debian/Ubuntu. On this distribution, provide gh and gpg, or run this script on macOS.'
      sudo_cmd=()
      if [ "$(id -u)" != 0 ]; then sudo_cmd=(sudo); fi
      "${sudo_cmd[@]}" apt-get update -o APT::Update::Error-Mode=any
      "${sudo_cmd[@]}" apt-get install -y gh gnupg jq ca-certificates openssh-client
    fi
    state_base="${XDG_STATE_HOME:-$HOME/.local/state}/lasa-distribution"
    ;;
  *) die 'Publishing bootstrap supports macOS and Linux';;
esac
for tool in gh gpg jq ssh-keygen curl; do command -v "$tool" >/dev/null || die "Missing publishing tool: $tool"; done
stage='GitHub authentication'
if ! gh auth status --hostname github.com >/dev/null 2>&1; then
  if [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ]; then
    die 'The supplied GitHub token is unusable. Reauthenticate in your local shell; this script will not replace or print an injected token.'
  fi
  gh auth login --hostname github.com --git-protocol https --web --scopes repo,workflow
fi
# Failure here is an authorization/network error, never evidence to create a repo.
gh api "repos/$repo" --jq .full_name >/dev/null
gh api "repos/$repo/commits/$commit" --jq .sha >/dev/null || die 'This commit is not on GitHub. Push your branch first.'
[[ $(gh api "repos/$repo/contents/.github/workflows/release.yml?ref=$commit" --jq .type) == file ]] || die 'This commit has no release workflow'
stage='refreshing version history'
fetch_options=(--tags --no-recurse-submodules)
if [[ $(git rev-parse --is-shallow-repository) == true ]]; then fetch_options+=(--unshallow); fi
git -c credential.helper= -c 'credential.helper=!gh auth git-credential' fetch "${fetch_options[@]}" "https://github.com/$repo.git" "$commit"
version=$(bash scripts/next-version.sh "$commit")
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'Could not allocate a stable semantic version'
tag="v$version"
stage='checking release immutability'
refs=$(gh api "repos/$repo/git/matching-refs/tags/$tag" --jq ".[] | select(.ref == \"refs/tags/$tag\") | .object.sha")
if [ -n "$refs" ]; then
  # Handles existing annotated tags too; /commits/TAG resolves the commit.
  tagged_commit=$(gh api "repos/$repo/commits/$tag" --jq .sha)
  [[ $tagged_commit == "$commit" ]] || die "$tag already identifies a different commit. Fetch current tags and rerun from the intended new release commit; existing versions are immutable."
fi
stage='creating the public package repository'
owner=${distribution%/*}
name=${distribution#*/}
# Listing accessible repositories avoids treating an arbitrary API failure as 404.
found=$(gh repo list "$owner" --limit 1000 --json nameWithOwner --jq ".[] | select((.nameWithOwner | ascii_downcase) == (\"$distribution\" | ascii_downcase)) | .nameWithOwner")
if [ -z "$found" ]; then
  gh repo create "$distribution" --public --add-readme --description 'Generated LASA Linux packages, signed APT repository and Homebrew tap'
fi
[[ $(gh api "repos/$distribution" --jq .visibility) == public ]] || die 'The distribution repository must be public. Its visibility will not be changed automatically.'
branch=$(gh api "repos/$distribution" --jq .default_branch)
stage='generating and safeguarding local publishing keys'
state="$state_base/${repo//\//_}"
mkdir -p "$state/gnupg"
chmod 0700 "$state" "$state/gnupg"
# Unix-domain socket names have a short OS limit. An ephemeral short alias keeps
# GnuPG working even with long macOS home/Application Support paths.
gpg_alias=$(mktemp -d /tmp/lasa-gpg.XXXXXX)
ln -s "$state/gnupg" "$gpg_alias/home"
export GNUPGHOME="$gpg_alias/home"
# shellcheck disable=SC2317
cleanup() { gpgconf --kill gpg-agent || true; rm -rf "$gpg_alias"; }
trap cleanup EXIT
stage='preparing the release environment without changing approval rules'
environment_error=$(mktemp)
if ! gh api "repos/$repo/environments/release" >/dev/null 2> "$environment_error"; then
  if ! grep -q 'HTTP 404' "$environment_error"; then cat "$environment_error" >&2; rm -f "$environment_error"; die 'Could not read the release environment'; fi
  gh api --method PUT "repos/$repo/environments/release" >/dev/null
fi
rm -f "$environment_error"
secrets=$(gh secret list --repo "$repo" --env release --json name --jq '.[].name')
repository_secrets=$(gh secret list --repo "$repo" --json name --jq '.[].name')
secrets=$(printf '%s\n%s\n' "$secrets" "$repository_secrets")
stage='generating and safeguarding local publishing keys'
if [ ! -f "$state/signing-fingerprint" ]; then
  if printf '%s\n' "$secrets" | grep -qx APT_SIGNING_KEY; then
    die "APT_SIGNING_KEY exists on GitHub, but its local signing state is missing at $state. Restore that directory from your secure backup; automatic key rotation would break existing installations."
  fi
  identity="LASA packages ($repo) <jasonachkardiab@gmail.com>"
  existing=$(gpg --batch --list-secret-keys --with-colons "$identity" 2>/dev/null | awk -F: '$1=="fpr"{print $10;exit}' || true)
  if [ -z "$existing" ]; then
    gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key "$identity" rsa3072 sign 0
  fi
  generated_fingerprint=$(gpg --batch --list-secret-keys --with-colons "$identity" | awk -F: '$1=="fpr"{print $10;exit}')
  [[ $generated_fingerprint =~ ^[A-F0-9]{40}$ ]] || die 'GnuPG did not return one valid primary signing fingerprint'
  printf '%s\n' "$generated_fingerprint" > "$state/signing-fingerprint.new"
  mv "$state/signing-fingerprint.new" "$state/signing-fingerprint"
fi
fingerprint=$(cat "$state/signing-fingerprint")
[[ $fingerprint =~ ^[A-F0-9]{40}$ ]] || die "Invalid saved signing fingerprint in $state"
gpg --batch --list-secret-keys "$fingerprint" >/dev/null
if [ ! -f "$state/deploy-key" ]; then
  if printf '%s\n' "$secrets" | grep -qx DISTRIBUTION_DEPLOY_KEY; then
    die "DISTRIBUTION_DEPLOY_KEY exists on GitHub but its local private key is missing at $state. Restore your secure backup."
  fi
  ssh-keygen -q -t ed25519 -N '' -C "LASA publisher $repo" -f "$state/deploy-key"
fi
chmod 0600 "$state/deploy-key"
public_key=$(ssh-keygen -y -f "$state/deploy-key")
existing_key=$(gh api --paginate "repos/$distribution/keys" --jq '.[] | select(.title=="LASA distribution publisher") | .key')
if [ -n "$existing_key" ]; then
  [[ ${existing_key% *} == "$public_key" || $existing_key == "$public_key" ]] || die 'The distribution deploy key differs from local state. Restore the original key; no existing key was revoked.'
else
  gh api --method POST "repos/$distribution/keys" -f title='LASA distribution publisher' -f key="$public_key" -F read_only=false >/dev/null
fi
stage='configuring GitHub Actions secrets and variables'
# Private material goes through stdin, never command arguments or the checkout.
gpg --batch --armor --export-secret-keys "$fingerprint" | gh secret set APT_SIGNING_KEY --repo "$repo" --env release
gh secret set DISTRIBUTION_DEPLOY_KEY --repo "$repo" --env release < "$state/deploy-key"
gh variable set APT_SIGNING_FINGERPRINT --repo "$repo" --body "$fingerprint"
gh variable set DISTRIBUTION_REPOSITORY --repo "$repo" --body "$distribution"
gh variable set DISTRIBUTION_BRANCH --repo "$repo" --body "$branch"
apt_url="https://$(printf '%s' "$owner" | tr '[:upper:]' '[:lower:]').github.io/$name/apt"
gh variable set APT_REPOSITORY_URL --repo "$repo" --body "$apt_url"
gh variable set DOCS_SITE_URL --repo "$repo" --body "${apt_url%/apt}/"
stage='configuring GitHub Pages'
pages_error=$(mktemp)
if pages=$(gh api "repos/$distribution/pages" --jq '.build_type+" "+.source.branch+" "+.source.path' 2> "$pages_error"); then
  [[ $pages == "legacy $branch /" ]] || die 'GitHub Pages already uses a different publishing configuration; it was not overwritten. Use a dedicated distribution repository.'
else
  if ! grep -q 'HTTP 404' "$pages_error"; then cat "$pages_error" >&2; rm -f "$pages_error"; die 'Could not read GitHub Pages configuration'; fi
  gh api --method POST "repos/$distribution/pages" -f build_type=legacy -f "source[branch]=$branch" -f 'source[path]=/' >/dev/null
fi
rm -f "$pages_error"
printf 'Publishing configured. Private local state: %s\nAPT signing fingerprint: %s\n' "$state" "$fingerprint"
if $configure_only; then echo 'Configuration complete; no release tag was created.'; exit 0; fi
stage='configuring GoDaddy DNS and documentation HTTPS'
bash scripts/configure-domain.sh "$distribution"
gh variable set DOCS_SITE_URL --repo "$repo" --body 'https://lasa.secureobs.com/'
gh variable set APT_REPOSITORY_URL --repo "$repo" --body 'https://lasa.secureobs.com/apt'
apt_url=https://lasa.secureobs.com/apt
stage="publishing $tag"
if [ -z "$refs" ]; then
  gh api --method POST "repos/$repo/git/refs" -f "ref=refs/tags/$tag" -f "sha=$commit" >/dev/null
fi
# Tag-triggered workflows work from this commit; no merge to main is required.
run=
for ((attempt=0; attempt<60; attempt++)); do
  run=$(gh run list --repo "$repo" --commit "$commit" --event push --limit 100 --json databaseId,headBranch,workflowName --jq ".[] | select((.headBranch==\"$tag\" and .workflowName==\"Signed release\") or .workflowName==\"Automatic version and release\") | .databaseId" | head -n 1)
  [ -z "$run" ] || break
  sleep 5
done
[ -n "$run" ] || die "No release workflow appeared for $tag within five minutes. Check Actions policy at https://github.com/$repo/actions; the existing tag was preserved."
conclusion=$(gh run view "$run" --repo "$repo" --json conclusion --jq .conclusion)
case "$conclusion" in
  failure|cancelled|timed_out) gh run rerun "$run" --repo "$repo" --failed;;
esac
if ! gh run watch "$run" --repo "$repo" --exit-status; then
  die "Release workflow failed: https://github.com/$repo/actions/runs/$run . Fix the reported cause and rerun this script; it will preserve the tag and signing identity."
fi
printf 'Release: https://github.com/%s/releases/tag/%s\nAPT: %s\nLinux Homebrew: brew install %s/lasa/lasa\n' "$repo" "$tag" "$apt_url" "$owner"
