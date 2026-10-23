#!/usr/bin/env bash
# macOS Bash 3.2; account consent remains interactive when no session exists.
set -euo pipefail
umask 077
trap 'printf "Azure bootstrap failed at line %s. See the error above; existing signing keys have not been rotated.\n" "$LINENO" >&2' ERR
# Keep an optional pre-existing PAT out of git, Homebrew, gh and browser processes.
lasa_bootstrap_devops_pat=${AZURE_DEVOPS_EXT_PAT:-}
unset AZURE_DEVOPS_EXT_PAT
cd "$(dirname "$0")/.."
if [ "${1:-}" = --help ]; then
  echo 'Usage: bash scripts/bootstrap-azure.sh [--configure-only] [--reauth | --devops-pat]'
  echo 'Defaults: https://dev.azure.com/jasonachkardiab, private project LASA.'
  echo 'Optional: LASA_AZURE_ORGANIZATION, LASA_AZURE_PROJECT, LASA_AZURE_TENANT, LASA_GITHUB_TOKEN.'
  echo '--reauth opens a fresh Azure sign-in without clearing other cached accounts or resetting keys.'
  echo '--devops-pat uses a short-lived Azure DevOps PAT from the organization owner, entered in a hidden local prompt.'
  echo 'An existing AZURE_DEVOPS_EXT_PAT is accepted in PAT mode; it is never stored in the pipeline.'
  exit 0
fi
export LASA_AZURE_CONFIGURE_ONLY=0 LASA_AZURE_REAUTH=0 LASA_AZURE_DEVOPS_PAT=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --configure-only) LASA_AZURE_CONFIGURE_ONLY=1;;
    --reauth) LASA_AZURE_REAUTH=1;;
    --devops-pat) LASA_AZURE_DEVOPS_PAT=1;;
    *) echo 'Unknown argument; use --help' >&2; exit 1;;
  esac
  shift
done
if [ "$LASA_AZURE_REAUTH" = 1 ] && [ "$LASA_AZURE_DEVOPS_PAT" = 1 ]; then
  echo 'Choose --reauth (Azure CLI) or --devops-pat (Azure DevOps PAT), not both.' >&2
  exit 1
fi
[[ -z $(git status --porcelain) ]] || { echo 'Commit and push this checkout before setup.' >&2; exit 1; }
git fetch origin "$(git branch --show-current)"
test "$(git rev-parse HEAD)" = "$(git rev-parse FETCH_HEAD)" || { echo 'Push this commit to its current origin branch before setup.' >&2; exit 1; }
if ! command -v brew >/dev/null; then
  for prefix in /opt/homebrew /usr/local; do
    if [ -x "$prefix/bin/brew" ]; then export PATH="$prefix/bin:$PATH"; break; fi
  done
fi
command -v brew >/dev/null || { echo 'Homebrew is required; run the distribution bootstrap first.' >&2; exit 1; }
for tool in azure-cli gh gnupg; do
  if [ "$tool" = azure-cli ] && [ "$LASA_AZURE_DEVOPS_PAT" = 1 ]; then continue; fi
  case "$tool" in azure-cli) binary=az;; gnupg) binary=gpg;; *) binary=$tool;; esac
  command -v "$binary" >/dev/null || brew install "$tool"
done
brew list --versions python@3.12 >/dev/null || brew install python@3.12
gh auth status >/dev/null 2>&1 || gh auth login --web --git-protocol https
# Use the owner's authenticated local session, never a token pasted into chat.
export LASA_GITHUB_TOKEN
if [ -z "${LASA_GITHUB_TOKEN:-}" ]; then LASA_GITHUB_TOKEN=$(gh auth token); fi
lasa_bootstrap_python="$(brew --prefix python@3.12)/bin/python3.12"
if [ "$LASA_AZURE_DEVOPS_PAT" = 1 ]; then
  AZURE_DEVOPS_EXT_PAT="$lasa_bootstrap_devops_pat" "$lasa_bootstrap_python" scripts/configure-azure.py
else
  "$lasa_bootstrap_python" scripts/configure-azure.py
fi
unset LASA_GITHUB_TOKEN lasa_bootstrap_devops_pat
