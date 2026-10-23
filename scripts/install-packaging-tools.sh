#!/usr/bin/env bash
# Install only the reviewed packaging binary into this checkout, never /usr/bin.
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(uname -s)" = Linux || { echo 'Package builds run on the Linux publishing runner.' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) arch=x86_64; digest=6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750;;
  aarch64|arm64) arch=arm64; digest=a9a75213763783b7669719e505474c748c5ad7dc66591a195619deb50f85c2f4;;
  *) echo 'Packaging supports Linux AMD64/ARM64 builders.' >&2; exit 1;;
esac
destination="$PWD/.build/package-tools/nfpm-2.48.0"
mkdir -p "$destination"
archive="$destination/nfpm.tar.gz"
if ! printf '%s  %s\n' "$digest" "$archive" | sha256sum --status -c -; then
  temp=$(mktemp -d "$destination/download.XXXXXX")
  trap 'rm -rf "$temp"' EXIT
  curl --proto '=https' --proto-redir '=https' --fail --silent --show-error --location --retry 3 --max-time 180 --max-filesize 67108864 \
    "https://github.com/goreleaser/nfpm/releases/download/v2.48.0/nfpm_2.48.0_Linux_$arch.tar.gz" -o "$temp/nfpm.tar.gz"
  printf '%s  %s\n' "$digest" "$temp/nfpm.tar.gz" | sha256sum -c -
  mv "$temp/nfpm.tar.gz" "$archive"
fi
tar -xzf "$archive" -C "$destination" nfpm
test -x "$destination/nfpm"
