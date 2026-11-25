#!/usr/bin/env bash
# Linux release runner only. The publisher's Mac never needs dpkg or Go.
set -euo pipefail
umask 022
trap 'printf "Packaging failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
cd "$(dirname "$0")/.."
version=${1:?Usage: package-release.sh VERSION}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected a stable MAJOR.MINOR.PATCH version' >&2; exit 1; }
for tool in dpkg-deb tar gzip git gpg python3; do command -v "$tool" >/dev/null || { echo "Missing packaging dependency: $tool" >&2; exit 1; }; done
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || exit 1
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
# Manual page and completions are architecture-independent; generate them
# once with the binary that runs on this host.
case "$(uname -m)" in x86_64) host_arch=amd64 ;; aarch64|arm64) host_arch=arm64 ;; *) echo "Unsupported packaging host $(uname -m)" >&2; exit 1 ;; esac
generator="dist/lasa-$version-linux-$host_arch"
test -x "$generator"
generated="$stage/generated"
mkdir -p "$generated"
"$generator" __man | gzip -n -9 > "$generated/lasa.1.gz"
"$generator" completion bash > "$generated/lasa.bash"
"$generator" completion zsh > "$generated/_lasa"
"$generator" completion fish > "$generated/lasa.fish"
# The package carries the APT trust anchor so signing-subkey rotations reach
# installed clients through ordinary upgrades. Only the pinned primary key is
# accepted, and conversion is byte-for-byte deterministic.
keyring_source=deploy/apt/lasa-archive-keyring.asc
bash scripts/release/check-keyring.sh "$keyring_source" "$(cat deploy/apt/primary-fingerprint)"
python3 -I scripts/release/dearmor.py "$keyring_source" "$generated/lasa-archive-keyring.gpg"
# Packaged Markdown has no site navigation: point relative links at files
# shipped alongside it or at the online documentation.
customer_docs() {
  local destination=$1 page
  for page in docs/customer/*.md; do
    sed -e 's@](\.\./\.\./README\.md)@](https://lasa.secureobs.com/current/)@g' \
      -e 's@](\.\./\.\./deploy/systemd/@](examples/@g' \
      -e 's@](\.\./\.\./schemas/@](https://lasa.secureobs.com/current/assets/schemas/@g' \
      "$page" > "$destination/$(basename "$page")"
    chmod 0644 "$destination/$(basename "$page")"
  done
}
for arch in amd64 arm64; do
  binary="dist/lasa-$version-linux-$arch"
  test -s "$binary"
  root="$stage/$arch"
  mkdir -p "$root/usr/bin" "$root/usr/share/doc/lasa/examples" "$root/usr/share/man/man1" "$root/usr/share/keyrings" \
    "$root/usr/share/bash-completion/completions" "$root/usr/share/zsh/vendor-completions" "$root/usr/share/fish/vendor_completions.d"
  install -m 0755 "$binary" "$root/usr/bin/lasa"
  cp -R dist/licenses "$root/usr/share/doc/lasa/"
  customer_docs "$root/usr/share/doc/lasa"
  install -m 0644 "$generated/lasa.1.gz" "$root/usr/share/man/man1/lasa.1.gz"
  install -m 0644 "$generated/lasa.bash" "$root/usr/share/bash-completion/completions/lasa"
  install -m 0644 "$generated/_lasa" "$root/usr/share/zsh/vendor-completions/_lasa"
  install -m 0644 "$generated/lasa.fish" "$root/usr/share/fish/vendor_completions.d/lasa.fish"
  install -m 0644 "$generated/lasa-archive-keyring.gpg" "$root/usr/share/keyrings/lasa-archive-keyring.gpg"
  # Examples only: package installation never creates a user or enables a scan.
  sed 's@/usr/local/bin/lasa@/usr/bin/lasa@g' deploy/systemd/lasa.service > "$root/usr/share/doc/lasa/examples/lasa.service"
  sed 's@/usr/local/bin/lasa@/usr/bin/lasa@g' deploy/systemd/lasa-deep.service > "$root/usr/share/doc/lasa/examples/lasa-deep.service"
  mkdir -p "$root/DEBIAN"
  cat > "$root/DEBIAN/control" <<EOF
Package: lasa
Version: $version
Architecture: $arch
Maintainer: Jason Achkar Diab <83395276+jasonachkar@users.noreply.github.com>
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
  customer_docs "$archive/share/doc/lasa"
  mkdir -p "$archive/share/man/man1" "$archive/share/completions"
  install -m 0644 "$generated/lasa.1.gz" "$archive/share/man/man1/lasa.1.gz"
  install -m 0644 "$generated/lasa.bash" "$generated/_lasa" "$generated/lasa.fish" "$archive/share/completions/"
  chmod -R u=rwX,go=rX "$archive"
  tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$archive" -cf - . | gzip -n > "dist/lasa-$version-linux-$arch.tar.gz"
done
