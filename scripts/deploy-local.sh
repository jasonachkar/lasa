#!/usr/bin/env bash
# Manual publishing from macOS. The disposable Linux guest performs all builds.
set -euo pipefail
umask 077
trap 'printf "Local publisher setup failed at line %s; see the tool diagnostic above.\n" "$LINENO" >&2' ERR
cd "$(dirname "$0")/.."
if [ "${1:-}" = --help ]; then
  echo 'Usage: bash scripts/deploy-local.sh [--check] [--cpus 2] [--memory 4G] [--disk 40G]'
  echo 'Publishes this clean, pushed branch using existing signing keys and a disposable Ubuntu VM.'
  echo '--check checks prerequisites and GitHub configuration without creating a VM or publishing.'
  echo 'Docs only: bash scripts/publish-docs-local.sh'
  exit 0
fi
validate_options() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --check) shift;;
      --cpus|--memory|--disk)
        [ "$#" -ge 2 ] || { echo 'A VM sizing option is missing its value; use --help.' >&2; exit 1; }
        shift 2;;
      *) echo 'Unknown option; use --help.' >&2; exit 1;;
    esac
  done
}
validate_options "$@"
test "$(uname -s)" = Darwin || { echo 'This launcher requires macOS and Multipass.' >&2; exit 1; }
check_only=0
for argument in "$@"; do if [ "$argument" = --check ]; then check_only=1; fi; done
if ! command -v brew >/dev/null; then
  for prefix in /opt/homebrew /usr/local; do
    if [ -x "$prefix/bin/brew" ]; then export PATH="$prefix/bin:$PATH"; break; fi
  done
fi
command -v brew >/dev/null || { echo 'Homebrew is required; use your existing Mac publishing setup.' >&2; exit 1; }
for tool in gh gpg jq multipass; do
  if ! command -v "$tool" >/dev/null; then
    if [ "$check_only" = 1 ]; then echo "Missing local prerequisite: $tool. Normal deployment installs it through Homebrew." >&2; exit 1; fi
    case "$tool" in
      gpg) brew install gnupg;;
      multipass) brew install --cask multipass;;
      *) brew install "$tool";;
    esac
  fi
done
if ! brew list --versions python@3.12 >/dev/null; then
  if [ "$check_only" = 1 ]; then echo 'Missing python@3.12; normal deployment installs it through Homebrew.' >&2; exit 1; fi
  brew install python@3.12
fi
github_authenticated=0
if [ -n "${LASA_GITHUB_TOKEN:-}" ]; then
  if GH_TOKEN="$LASA_GITHUB_TOKEN" gh auth status --hostname github.com >/dev/null 2>&1; then github_authenticated=1; fi
elif gh auth status --hostname github.com >/dev/null 2>&1; then
  github_authenticated=1
fi
if [ "$github_authenticated" = 0 ]; then
  if [ "$check_only" = 1 ] || [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}${LASA_GITHUB_TOKEN:-}" ]; then
    echo 'A usable owner GitHub session is required. Authenticate locally with gh auth login --hostname github.com.' >&2
    exit 1
  fi
  gh auth login --hostname github.com --web --git-protocol https --scopes repo,workflow
fi
"$(brew --prefix python@3.12)/bin/python3.12" scripts/deploy-local.py "$@"
