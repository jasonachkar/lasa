#!/usr/bin/env bash
# Real signatures: wrong trusted key, altered manifest and altered bytes must fail.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
temp=$(mktemp -d)
export GNUPGHOME="$temp/gnupg"
mkdir -m 0700 "$GNUPGHOME"
cleanup() { gpgconf --kill gpg-agent || true; rm -rf "$temp"; }
trap cleanup EXIT
mkdir "$temp/assets"
printf 'release bytes\n' > "$temp/assets/package"
(cd "$temp/assets" && sha256sum package > SHA256SUMS)
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'LASA provenance test <test@example.invalid>' ed25519 sign 0
APT_SIGNING_FINGERPRINT=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1=="fpr"{print $10;exit}')
export APT_SIGNING_FINGERPRINT
gpg --batch --armor --detach-sign "$temp/assets/SHA256SUMS"
bash "$root/scripts/verify-release-assets.sh" "$temp/assets" openpgp
if APT_SIGNING_FINGERPRINT=0000000000000000000000000000000000000000 bash "$root/scripts/verify-release-assets.sh" "$temp/assets" openpgp > "$temp/error" 2>&1; then exit 1; fi
grep -q 'configured primary APT key' "$temp/error"
printf 'tampered bytes\n' > "$temp/assets/package"
if bash "$root/scripts/verify-release-assets.sh" "$temp/assets" openpgp > "$temp/error" 2>&1; then exit 1; fi
grep -q FAILED "$temp/error"
(cd "$temp/assets" && sha256sum package > SHA256SUMS)
if bash "$root/scripts/verify-release-assets.sh" "$temp/assets" openpgp > "$temp/error" 2>&1; then exit 1; fi
grep -q 'BAD signature' "$temp/error"
if bash "$root/scripts/verify-release-assets.sh" "$temp/assets" unsigned > "$temp/error" 2>&1; then exit 1; fi
grep -q 'Unknown release provenance policy' "$temp/error"
echo 'PASS: signed release integrity, trusted fingerprint and tampering rejection'
