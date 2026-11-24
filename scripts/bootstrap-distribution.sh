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

Prepares a public package repository, local APT signing and GitHub Pages.
The GitHub CLI must be logged in.
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
for tool in gh gpg jq curl; do command -v "$tool" >/dev/null || die "Missing publishing tool: $tool"; done
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
published_fingerprint=$(gh variable list --repo "$repo" --json name,value --jq '.[] | select(.name=="APT_SIGNING_FINGERPRINT") | .value')
if [ ! -f "$state/signing-fingerprint" ]; then
  if [ -n "$published_fingerprint" ]; then
    die "An APT signing fingerprint is configured on GitHub, but its local signing state is missing at $state. Restore the original state from your secure backup."
  fi
  identity="LASA packages ($repo)"
  existing=$(gpg --batch --list-secret-keys --with-colons "$identity" 2>/dev/null | awk -F: '$1=="fpr"{print $10;exit}' || true)
  if [ -z "$existing" ]; then
    gpg --quick-generate-key "$identity" rsa3072 sign 0
  fi
  generated_fingerprint=$(gpg --batch --list-secret-keys --with-colons "$identity" | awk -F: '$1=="fpr"{print $10;exit}')
  [[ $generated_fingerprint =~ ^[A-F0-9]{40}$ ]] || die 'GnuPG did not return one valid primary signing fingerprint'
  printf '%s\n' "$generated_fingerprint" > "$state/signing-fingerprint.new"
  mv "$state/signing-fingerprint.new" "$state/signing-fingerprint"
fi
fingerprint=$(cat "$state/signing-fingerprint")
[[ $fingerprint =~ ^[A-F0-9]{40}$ ]] || die "Invalid saved signing fingerprint in $state"
gpg --batch --list-secret-keys "$fingerprint" >/dev/null
if [[ -n $published_fingerprint && $published_fingerprint != "$fingerprint" ]]; then
  die 'The configured and local APT signing fingerprints differ. Restore the original key before publishing.'
fi
stage='configuring public publishing variables'
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
