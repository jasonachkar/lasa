#!/usr/bin/env bash
# macOS Bash 3.2; account consent remains interactive when no session exists.
set -euo pipefail
umask 077
trap 'printf "Azure bootstrap failed at line %s. See the error above; existing signing keys have not been rotated.\n" "$LINENO" >&2' ERR
cd "$(dirname "$0")/.."
if [ "${1:-}" = --help ]; then
  echo 'Usage: bash scripts/bootstrap-azure.sh [--configure-only]'
  echo 'Defaults: https://dev.azure.com/jasonachkardiab, private project LASA.'
  echo 'Optional: LASA_AZURE_ORGANIZATION, LASA_AZURE_PROJECT, LASA_GITHUB_TOKEN.'
  exit 0
fi
[[ $# = 0 || ($# = 1 && $1 = --configure-only) ]] || { echo 'Unknown argument; use --help' >&2; exit 1; }
[[ -z $(git status --porcelain) ]] || { echo 'Commit and push this checkout before setup.' >&2; exit 1; }
git fetch origin "$(git branch --show-current)"
test "$(git rev-parse HEAD)" = "$(git rev-parse FETCH_HEAD)" || { echo 'Push this commit to its current origin branch before setup.' >&2; exit 1; }
for prefix in /opt/homebrew /usr/local; do
  if [ -x "$prefix/bin/brew" ]; then export PATH="$prefix/bin:$PATH"; break; fi
done
command -v brew >/dev/null || { echo 'Homebrew is required; run the distribution bootstrap first.' >&2; exit 1; }
for tool in azure-cli gh gnupg; do
  case "$tool" in azure-cli) binary=az;; gnupg) binary=gpg;; *) binary=$tool;; esac
  command -v "$binary" >/dev/null || brew install "$tool"
done
brew list --versions python@3.12 >/dev/null || brew install python@3.12
gh auth status >/dev/null 2>&1 || gh auth login --web --git-protocol https
if ! az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798 --output none 2>/dev/null; then
  az login --allow-no-subscriptions --output none
fi
# Use the owner's authenticated local session, never a token pasted into chat.
export LASA_GITHUB_TOKEN
if [ -z "${LASA_GITHUB_TOKEN:-}" ]; then LASA_GITHUB_TOKEN=$(gh auth token); fi
export LASA_AZURE_CONFIGURE_ONLY=0
if [ "${1:-}" = --configure-only ]; then export LASA_AZURE_CONFIGURE_ONLY=1; fi
"$(brew --prefix python@3.12)/bin/python3.12" scripts/configure-azure.py
unset LASA_GITHUB_TOKEN
