#!/usr/bin/env bash
set -euo pipefail
version=${1:?Usage: write-release-manifest.sh VERSION [DIST]}
assets=${2:-dist}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
cd "$assets"
files=("lasa-$version-linux-amd64" "lasa-$version-linux-arm64" "lasa_${version}_amd64.deb" "lasa_${version}_arm64.deb" "lasa-$version-linux-amd64.tar.gz" "lasa-$version-linux-arm64.tar.gz" lasa-amd64.cdx.json lasa-arm64.cdx.json)
for arch in x86_64 aarch64; do
  files+=("lasa-$version-1.$arch.rpm" "lasa-$version-1-$arch.pkg.tar.zst" "lasa-$version-r1-$arch.apk")
  if [ -f "lasa-$version-1-$arch.pkg.tar.zst.sig" ]; then files+=("lasa-$version-1-$arch.pkg.tar.zst.sig"); fi
done
if [ -f "lasa-$version-licenses.tar.gz" ]; then files+=("lasa-$version-licenses.tar.gz"); fi
sha256sum -- "${files[@]}" > SHA256SUMS.new
mv SHA256SUMS.new SHA256SUMS
