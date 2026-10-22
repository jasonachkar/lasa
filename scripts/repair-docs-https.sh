#!/usr/bin/env bash
# Repair only LASA's Pages domain, using the owner's existing local GitHub login.
set -euo pipefail
umask 077
distribution=${1:-jasonachkar/homebrew-lasa}
[[ $# -le 1 && $distribution =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'Usage: bash scripts/repair-docs-https.sh [OWNER/DISTRIBUTION-REPO]' >&2; exit 1; }
cd "$(dirname "$0")/.."
for prefix in /opt/homebrew /usr/local; do
  if [ -x "$prefix/bin/brew" ]; then export PATH="$prefix/bin:$PATH"; break; fi
done
for tool in gh jq; do
  if ! command -v "$tool" >/dev/null; then
    command -v brew >/dev/null || { echo "Missing $tool. Install it or use your Mac with Homebrew." >&2; exit 1; }
    brew install "$tool"
  fi
done
if ! gh auth status --hostname github.com >/dev/null 2>&1; then
  [[ -z ${GH_TOKEN:-}${GITHUB_TOKEN:-} ]] || { echo 'GitHub authentication failed with an injected token. Use a working owner session locally; no credentials were replaced.' >&2; exit 1; }
  gh auth login --hostname github.com --web --git-protocol https --scopes repo
fi
case "$(uname -s)" in
  Darwin) state_base="$HOME/Library/Application Support/lasa-distribution";;
  *) state_base="${XDG_STATE_HOME:-$HOME/.local/state}/lasa-distribution";;
esac
export LASA_HTTPS_REPAIR_STATE="$state_base/${distribution//\//_}.certificate-repair"
bash scripts/configure-domain.sh "$distribution" --repair-certificate
