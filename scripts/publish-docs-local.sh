#!/usr/bin/env bash
# Publish directly from the owner's Mac without spending Actions minutes.
set -euo pipefail
umask 077
trap 'printf "Local documentation publication failed at line %s; see the preceding error. Rerunning preserves signing keys and published releases.\n" "$LINENO" >&2' ERR
cd "$(dirname "$0")/.."
for prefix in /opt/homebrew /usr/local; do
  if [ -x "$prefix/bin/brew" ]; then export PATH="$prefix/bin:$PATH"; break; fi
done
command -v brew >/dev/null || { echo 'Homebrew is required on this Mac; run the existing distribution bootstrap first.' >&2; exit 1; }
for tool in gh jq; do command -v "$tool" >/dev/null || brew install "$tool"; done
gh auth status >/dev/null 2>&1 || gh auth login --web --git-protocol https
brew list --versions python@3.12 >/dev/null || brew install python@3.12
"$(brew --prefix python@3.12)/bin/python3.12" -m venv .build/docs-venv
# shellcheck disable=SC1091
source .build/docs-venv/bin/activate
python -m pip install --disable-pip-version-check -r requirements-docs.txt
export DISTRIBUTION_REPOSITORY=jasonachkar/homebrew-lasa
export DISTRIBUTION_BRANCH
DISTRIBUTION_BRANCH=$(gh api "repos/$DISTRIBUTION_REPOSITORY" --jq .default_branch)
state="$HOME/Library/Application Support/lasa-distribution/jasonachkar_lasa"
test -s "$state/deploy-key" || { echo "Restore the existing deploy-key in $state; no key has been regenerated." >&2; exit 1; }
export DISTRIBUTION_DEPLOY_KEY
DISTRIBUTION_DEPLOY_KEY=$(cat "$state/deploy-key")
export DOCS_SITE_URL=https://lasa.secureobs.com/
bash scripts/publish-docs.sh preview
