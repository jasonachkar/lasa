#!/usr/bin/env bash
# Linux release runner only. The publisher's Mac never needs dpkg or Go.
set -euo pipefail
umask 022
trap 'printf "Packaging failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
cd "$(dirname "$0")/.."
version=${1:?Usage: package-release.sh VERSION}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected a stable MAJOR.MINOR.PATCH version' >&2; exit 1; }
for tool in dpkg-deb tar gzip git; do command -v "$tool" >/dev/null || { echo "Missing packaging dependency: $tool" >&2; exit 1; }; done
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || exit 1
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
for arch in amd64 arm64; do
  binary="dist/lasa-$version-linux-$arch"
  test -s "$binary"
  root="$stage/$arch"
  mkdir -p "$root/usr/bin" "$root/usr/share/doc/lasa/examples"
  install -m 0755 "$binary" "$root/usr/bin/lasa"
  cp -R dist/licenses "$root/usr/share/doc/lasa/"
  install -m 0644 docs/customer/*.md "$root/usr/share/doc/lasa/"
  # Examples only: package installation never creates a user or enables a scan.
  sed 's@/usr/local/bin/lasa@/usr/bin/lasa@g' deploy/systemd/lasa.service > "$root/usr/share/doc/lasa/examples/lasa.service"
  sed 's@/usr/local/bin/lasa@/usr/bin/lasa@g' deploy/systemd/lasa-deep.service > "$root/usr/share/doc/lasa/examples/lasa-deep.service"
  mkdir -p "$root/DEBIAN"
  cat > "$root/DEBIAN/control" <<EOF
Package: lasa
Version: $version
Architecture: $arch
Maintainer: Jason Achkar Diab <jasonachkardiab@gmail.com>
Section: utils
Priority: optional
Installed-Size: $(du -sk "$root/usr" | awk '{print $1}')
Homepage: https://github.com/jasonachkar/lasa
Description: Scoped read-only Linux attack surface analyzer
 Collects local Linux metadata and reports evidence-backed conditional risks.
 Requires Linux openat2 support (normally kernel 5.6+) and visible procfs.
 No service is enabled and no scan runs during installation.
EOF
  chmod -R u=rwX,go=rX "$root"
  find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  dpkg-deb --root-owner-group --uniform-compression --build "$root" "dist/lasa_${version}_${arch}.deb"
  archive="$stage/archive-$arch"
  mkdir -p "$archive/bin" "$archive/share/doc/lasa"
  install -m 0755 "$binary" "$archive/bin/lasa"
  cp -R dist/licenses "$archive/share/doc/lasa/"
  install -m 0644 docs/customer/*.md "$archive/share/doc/lasa/"
  chmod -R u=rwX,go=rX "$archive"
  tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$archive" -cf - . | gzip -n > "dist/lasa-$version-linux-$arch.tar.gz"
done

bash scripts/package-linux-formats.sh "$version" "$stage"
