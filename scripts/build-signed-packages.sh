#!/usr/bin/env bash
# Trusted release jobs only. Signing material never enters source or public artifacts.
set -euo pipefail
umask 077
version=${1:?Usage: build-signed-packages.sh VERSION}
: "${APT_SIGNING_KEY:?Run the owner publishing bootstrap first}"
: "${APT_SIGNING_FINGERPRINT:?Missing OpenPGP signing fingerprint}"
: "${APK_SIGNING_KEY:?Run the updated owner bootstrap to configure the Alpine key}"
: "${APK_PUBLIC_KEY_SHA256:?Missing Alpine public-key pin}"
[[ $APT_SIGNING_FINGERPRINT =~ ^[A-F0-9]{40}$ && $APK_PUBLIC_KEY_SHA256 =~ ^[a-f0-9]{64}$ ]] || exit 1
cd "$(dirname "$0")/.."
temp=$(mktemp -d)
export GNUPGHOME="$temp/gnupg"
mkdir -m 0700 "$GNUPGHOME"
# shellcheck disable=SC2317
cleanup() { gpgconf --kill gpg-agent || true; rm -rf "$temp"; }
trap cleanup EXIT
printf '%s\n' "$APT_SIGNING_KEY" > "$temp/openpgp.asc"
printf '%s\n' "$APK_SIGNING_KEY" > "$temp/alpine.pem"
unset APT_SIGNING_KEY APK_SIGNING_KEY
gpg --batch --import "$temp/openpgp.asc"
fingerprints=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1=="sec"{primary=1;next} primary && $1=="fpr"{print $10;primary=0}')
[[ $fingerprints == "$APT_SIGNING_FINGERPRINT" ]] || { echo 'Release signing secret has an unexpected primary key.' >&2; exit 1; }
openssl pkey -in "$temp/alpine.pem" -pubout -out "$temp/alpine.pub"
test "$(sha256sum "$temp/alpine.pub" | awk '{print $1}')" = "$APK_PUBLIC_KEY_SHA256" || { echo 'Alpine signing secret does not match its configured public-key pin.' >&2; exit 1; }
export RPM_SIGNING_KEY_FILE="$temp/openpgp.asc" APK_SIGNING_KEY_FILE="$temp/alpine.pem"
make packages VERSION="$version"
for arch in x86_64 aarch64; do
  gpg --batch --yes --local-user "$APT_SIGNING_FINGERPRINT!" --digest-algo SHA256 --detach-sign --output "dist/lasa-$version-1-$arch.pkg.tar.zst.sig" "dist/lasa-$version-1-$arch.pkg.tar.zst"
done
bash scripts/write-release-manifest.sh "$version"
