#!/usr/bin/env bash
# Run authorized privileged checks in an isolated local Linux VM, including on Apple Silicon.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
if [ "${1:-}" = --help ]; then
  echo 'Usage: bash scripts/validate-on-mac.sh [--keep-vm]'
  echo 'Creates an Ubuntu 24.04 VM using Multipass, validates the current clean commit, copies private results to .build/validation, and deletes only that VM.'
  exit 0
fi
[[ $# = 0 || ($# = 1 && $1 = --keep-vm) ]] || { echo 'Unknown argument; use --help' >&2; exit 1; }
test "$(uname -s)" = Darwin || { echo 'This wrapper requires macOS. On an authorized disposable Linux VM use scripts/validate-linux-vm.sh --disposable-vm.' >&2; exit 1; }
test -z "$(git status --porcelain)" || { echo 'Commit the checkout first so the VM validates the exact reviewed source revision.' >&2; exit 1; }
for prefix in /opt/homebrew /usr/local; do
  if [ -x "$prefix/bin/brew" ]; then export PATH="$prefix/bin:$PATH"; break; fi
done
command -v brew >/dev/null || { echo 'Homebrew is required to install Multipass on this Mac.' >&2; exit 1; }
command -v multipass >/dev/null || brew install --cask multipass
multipass version >/dev/null || { echo 'The Multipass service is unavailable; check the installer/service diagnostic above.' >&2; exit 1; }
revision=$(git rev-parse HEAD)
vm="lasa-validation-$(date +%s)-$$"
artifacts="$PWD/.build/validation/$vm"
mkdir -p "$artifacts"
archive=$(mktemp /tmp/lasa-validation.XXXXXX)
created=0
keep=0
if [ "${1:-}" = --keep-vm ]; then keep=1; fi
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ "$created" = 1 ]; then
    if ! multipass transfer --recursive "$vm:/home/ubuntu/lasa-validation/.build/validation-results" "$artifacts/"; then
      echo "Some VM results could not be retrieved; VM name: $vm" >&2
      keep=1
    fi
    if [ "$keep" = 0 ]; then
      multipass delete --purge "$vm" || { echo "Could not remove validation VM $vm; remove this named VM when finished." >&2; status=1; }
    else
      echo "Validation VM retained: $vm"
    fi
  fi
  rm -f "$archive"
  echo "Validation artifacts: $artifacts"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
git archive --format=tar HEAD > "$archive"
if multipass info "$vm" >/dev/null 2>&1; then echo "Refusing existing VM name: $vm" >&2; exit 1; fi
created=1
multipass launch 24.04 --name "$vm" --memory 4G --disk 16G --cpus 2
multipass transfer "$archive" "$vm:/tmp/lasa-source.tar"
multipass exec "$vm" -- bash -c 'mkdir -p /home/ubuntu/lasa-validation && tar -xf /tmp/lasa-source.tar -C /home/ubuntu/lasa-validation && rm -f /tmp/lasa-source.tar'
# git archive excludes credentials and .git; provenance is passed as a public SHA.
multipass exec "$vm" -- sudo env "LASA_VALIDATION_REVISION=$revision" bash /home/ubuntu/lasa-validation/scripts/validate-linux-vm.sh --disposable-vm | tee "$artifacts/console.log"
