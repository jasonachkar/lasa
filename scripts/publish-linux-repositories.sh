#!/usr/bin/env bash
# Called by the existing authenticated publisher after release-manifest verification.
set -euo pipefail
umask 022
site=${1:?Usage: publish-linux-repositories.sh SITE ASSETS VERSION BASE_URL}
assets=${2:?Missing release assets}
version=${3:?Missing version}
base_url=${4:?Missing public URL}
: "${APT_SIGNING_FINGERPRINT:?Missing OpenPGP signing identity}"
: "${APK_SIGNING_KEY:?Run the updated owner publishing bootstrap for Alpine}"
: "${APK_PUBLIC_KEY_SHA256:?Missing pinned Alpine key}"
for arch in x86_64 aarch64; do
  for filename in "lasa-$version-1.$arch.rpm" "lasa-$version-1-$arch.pkg.tar.zst" "lasa-$version-1-$arch.pkg.tar.zst.sig" "lasa-$version-r1-$arch.apk"; do
    test -s "$assets/$filename" || { echo "Release $version lacks $filename. Publish a new version with the native package pipeline; existing published releases are immutable." >&2; exit 1; }
  done
done
for tool in createrepo_c repo-add bsdtar docker rpmkeys rpmdb python3 openssl; do command -v "$tool" >/dev/null || { echo "Missing repository tool: $tool" >&2; exit 1; }; done
[[ $APK_PUBLIC_KEY_SHA256 =~ ^[a-f0-9]{64}$ ]] || exit 1
# Pinned multi-architecture official Alpine image; used offline only for apk index/verify.
image=alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
printf '%s\n' "$APK_SIGNING_KEY" > "$temp/alpine.pem"
unset APK_SIGNING_KEY
mkdir -p "$site/apk" "$site/keys"
openssl pkey -in "$temp/alpine.pem" -pubout -out "$temp/lasa.rsa.pub"
test "$(sha256sum "$temp/lasa.rsa.pub" | awk '{print $1}')" = "$APK_PUBLIC_KEY_SHA256" || { echo 'Alpine key does not match the configured pin.' >&2; exit 1; }
install -m 0644 "$temp/lasa.rsa.pub" "$site/apk/lasa.rsa.pub"
install -m 0644 "$temp/lasa.rsa.pub" "$site/keys/lasa.rsa.pub"
gpg --batch --armor --export "$APT_SIGNING_FINGERPRINT" > "$temp/openpgp.asc"
rpmdb --dbpath "$temp/rpmdb" --initdb
rpmkeys --dbpath "$temp/rpmdb" --import "$temp/openpgp.asc"
copy_immutable() {
  if [ -f "$2" ]; then cmp "$1" "$2" || { echo "Refusing to replace published package/signature $2; increment the version." >&2; exit 1; }
  else install -m 0644 "$1" "$2"; fi
}
for arch in x86_64 aarch64; do
  rpm_dir="$site/rpm/$arch"
  arch_dir="$site/arch/$arch"
  apk_dir="$site/apk/$arch"
  mkdir -p "$rpm_dir" "$arch_dir" "$apk_dir"
  package="lasa-$version-1.$arch.rpm"
  rpmkeys --dbpath "$temp/rpmdb" --checksig --verbose "$assets/$package" > "$temp/rpm-check"
  grep -q 'Signature.*OK' "$temp/rpm-check" || { echo "RPM has no verified native signature: $package" >&2; exit 1; }
  copy_immutable "$assets/$package" "$rpm_dir/$package"
  createrepo_c --checksum sha256 --database "$rpm_dir"
  gpg --batch --yes --armor --local-user "$APT_SIGNING_FINGERPRINT!" --digest-algo SHA256 --detach-sign --output "$rpm_dir/repodata/repomd.xml.asc" "$rpm_dir/repodata/repomd.xml"
  install -m 0644 "$temp/openpgp.asc" "$rpm_dir/repodata/repomd.xml.key"
  package="lasa-$version-1-$arch.pkg.tar.zst"
  gpg --batch --verify "$assets/$package.sig" "$assets/$package"
  copy_immutable "$assets/$package" "$arch_dir/$package"
  copy_immutable "$assets/$package.sig" "$arch_dir/$package.sig"
  bash "$(dirname "$0")/build-arch-database.sh" "$arch_dir" "$package"
  # Pages/git preserve regular files reliably; replace repo-add's short aliases.
  rm -f "$arch_dir/lasa.db" "$arch_dir/lasa.files"
  cp "$arch_dir/lasa.db.tar.gz" "$arch_dir/lasa.db"
  cp "$arch_dir/lasa.files.tar.gz" "$arch_dir/lasa.files"
  for index in lasa.db lasa.db.tar.gz lasa.files lasa.files.tar.gz; do
    gpg --batch --yes --local-user "$APT_SIGNING_FINGERPRINT!" --digest-algo SHA256 --detach-sign --output "$arch_dir/$index.sig" "$arch_dir/$index"
  done
  copy_immutable "$assets/lasa-$version-r1-$arch.apk" "$apk_dir/lasa-$version-r1.apk"
  # apk's arch name for ARM64 is aarch64. Verify signed inputs using the pinned key.
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --user "$(id -u):$(id -g)" \
    -v "$site/apk:/repo:ro" -v "$site/keys:/keys:ro" "$image" apk --keys-dir /keys --arch "$arch" verify "/repo/$arch/lasa-$version-r1.apk"
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --user "$(id -u):$(id -g)" \
    -v "$apk_dir:/repo:rw" "$image" sh -ec 'apk --arch "$1" index --allow-untrusted --output /repo/APKINDEX.tar.gz /repo/*.apk' _ "$arch"
  python3 "$(dirname "$0")/sign-apk.py" "$apk_dir/APKINDEX.tar.gz" "$temp/alpine.pem"
done
# Pin both trust keys inside the generated dispatcher, alongside the APT installer hash.
apt_installer_hash=$(sha256sum "$site/install-apt.sh" | awk '{print $1}')
{
  printf '#!/bin/sh\nLASA_BASE_URL=%s\nLASA_OPENPGP_FINGERPRINT=%s\nLASA_APK_PUBLIC_KEY_SHA256=%s\nLASA_APT_INSTALLER_SHA256=%s\n' "$base_url" "$APT_SIGNING_FINGERPRINT" "$APK_PUBLIC_KEY_SHA256" "$apt_installer_hash"
  cat "$(dirname "$0")/install-linux-body.sh"
} > "$site/install.sh"
chmod 0755 "$site/install.sh"
printf '{"schema":"lasa.distribution/v1","version":"%s","architectures":["amd64","arm64"],"formats":["deb","rpm","archlinux","apk"],"openpgp_fingerprint":"%s","apk_public_key_sha256":"%s"}\n' "$version" "$APT_SIGNING_FINGERPRINT" "$APK_PUBLIC_KEY_SHA256" > "$site/distribution.json"
