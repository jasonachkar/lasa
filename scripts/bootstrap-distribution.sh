#!/usr/bin/env bash
# Compatible with macOS's system Bash 3.2. No Linux host or Docker required.
set -euo pipefail
umask 077
stage=initialization
trap 'printf "LASA setup failed during %s (line %s). See the error above. No branch protections or required approvals were bypassed.\n" "$stage" "$LINENO" >&2' ERR
die() { printf '%s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: bash scripts/bootstrap-distribution.sh [--configure-domain] [--repo OWNER/REPO] [--distribution-repo OWNER/REPO]

Prepares a public package repository, the existing GitHub release environment,
its signing/deploy keys and GitHub Pages. The GitHub CLI must be logged in.
--configure-domain also configures the requested custom domain.
EOF
}
repo=jasonachkar/lasa
distribution=
configure_domain=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0;;
    --configure-only) shift;; # Accepted for callers of earlier versions.
    --configure-domain) configure_domain=true; shift;;
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
stage='checking publishing tools and GitHub access'
case "$(uname -s)" in
  Darwin) state_base="$HOME/Library/Application Support/lasa-distribution";;
  Linux) state_base="${XDG_STATE_HOME:-$HOME/.local/state}/lasa-distribution";;
  *) die 'Publishing bootstrap supports macOS and Linux';;
esac
for tool in gh gpg jq ssh-keygen curl; do command -v "$tool" >/dev/null || die "Missing publishing tool: $tool"; done
gh auth status --hostname github.com >/dev/null 2>&1 || die 'Sign in to the GitHub CLI before configuring publishing.'
gh api "repos/$repo" --jq .full_name >/dev/null
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
if printf '%s\n' "$repository_secrets" | grep -Eq '^(APT_SIGNING_KEY|DISTRIBUTION_DEPLOY_KEY)$'; then
  die 'Publishing credentials are present at repository scope. Review and migrate them before configuring environment secrets.'
fi
stage='generating and safeguarding local publishing keys'
if [ ! -f "$state/signing-fingerprint" ]; then
  if printf '%s\n' "$secrets" | grep -qx APT_SIGNING_KEY; then
    die "APT_SIGNING_KEY exists on GitHub, but its local signing state is missing at $state. Restore that directory from your secure backup; automatic key rotation would break existing installations."
  fi
  identity="LASA packages ($repo)"
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
# SSH comments are labels, not key identity. OpenSSH may emit a multiword
# comment, while GitHub may omit it; compare only algorithm and key data.
public_key=$(ssh-keygen -y -f "$state/deploy-key" | awk '{print $1, $2}')
existing_key=$(gh api --paginate "repos/$distribution/keys" --jq '.[] | select(.title=="LASA distribution publisher") | .key' | awk 'NF {print $1, $2}')
if [ -n "$existing_key" ]; then
  [[ $existing_key == "$public_key" ]] || die 'The distribution deploy key material differs from local state (SSH comments ignored). Restore the original key; no existing key was revoked.'
else
  gh api --method POST "repos/$distribution/keys" -f title='LASA distribution publisher' -f key="$public_key" -F read_only=false >/dev/null
fi
stage='configuring GitHub Actions secrets and variables'
# Private material goes through stdin, never command arguments or the checkout.
if ! printf '%s\n' "$secrets" | grep -qx APT_SIGNING_KEY; then
  gpg --batch --armor --export-secret-keys "$fingerprint" | gh secret set APT_SIGNING_KEY --repo "$repo" --env release
fi
if ! printf '%s\n' "$secrets" | grep -qx DISTRIBUTION_DEPLOY_KEY; then
  gh secret set DISTRIBUTION_DEPLOY_KEY --repo "$repo" --env release < "$state/deploy-key"
fi
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
if $configure_domain; then
  stage='configuring GoDaddy DNS and documentation HTTPS'
  bash scripts/configure-domain.sh "$distribution"
  gh variable set DOCS_SITE_URL --repo "$repo" --body 'https://lasa.secureobs.com/'
  gh variable set APT_REPOSITORY_URL --repo "$repo" --body 'https://lasa.secureobs.com/apt'
fi
printf 'Publishing configured. APT signing fingerprint: %s\n' "$fingerprint"
