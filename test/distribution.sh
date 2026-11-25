#!/usr/bin/env bash
# Real package/signature/APT integration. No installed packages or trust modified.
set -euo pipefail
umask 077
unset APT_VALIDITY_DAYS
cd "$(dirname "$0")/.."
version=$(make -s print-version)
temp=$(mktemp -d)
export GNUPGHOME="$temp/gnupg"
mkdir -m 0700 "$GNUPGHOME"
cleanup() { gpgconf --kill gpg-agent || true; rm -rf "$temp"; }
trap cleanup EXIT
for tool in apt-ftparchive dpkg-scanpackages gpgv apt-get; do command -v "$tool" >/dev/null || { echo "Missing test dependency: $tool" >&2; exit 1; }; done
bash scripts/package-release.sh "$version"
mkdir "$temp/first"
cp dist/*.deb dist/lasa-*-linux-*.tar.gz "$temp/first/"
bash scripts/package-release.sh "$version"
for file in "$temp/first/"*; do cmp "$file" "dist/${file##*/}"; done
for arch in amd64 arm64; do
  package="dist/lasa_${version}_${arch}.deb"
  [[ $(dpkg-deb -f "$package" Architecture) == "$arch" ]]
  [[ $(dpkg-deb -f "$package" Version) == "$version" ]]
  dpkg-deb -e "$package" "$temp/control-$arch"
  [[ $(find "$temp/control-$arch" -type f | wc -l) -eq 1 ]]
  dpkg-deb -x "$package" "$temp/extracted-$arch"
  [[ -x "$temp/extracted-$arch/usr/bin/lasa" ]]
  [[ ! -e "$temp/extracted-$arch/lib/systemd/system/lasa.service" ]]
  gzip -dc "$temp/extracted-$arch/usr/share/man/man1/lasa.1.gz" | grep -q '^.SH EXIT STATUS'
  grep -q 'lasa' "$temp/extracted-$arch/usr/share/bash-completion/completions/lasa"
  [[ -s "$temp/extracted-$arch/usr/share/zsh/vendor-completions/_lasa" && -s "$temp/extracted-$arch/usr/share/fish/vendor_completions.d/lasa.fish" ]]
  if grep -rq '](\.\./' "$temp/extracted-$arch/usr/share/doc/lasa"; then echo 'Packaged documentation has broken relative links' >&2; exit 1; fi
  cmp "$temp/extracted-$arch/usr/bin/lasa" "dist/lasa-$version-linux-$arch"
  # The package carries exactly the committed, fingerprint-pinned APT keyring.
  python3 -I scripts/release/dearmor.py deploy/apt/lasa-archive-keyring.asc "$temp/expected-keyring.gpg"
  cmp "$temp/extracted-$arch/usr/share/keyrings/lasa-archive-keyring.gpg" "$temp/expected-keyring.gpg"
  [[ $(stat -c %a "$temp/extracted-$arch/usr/share/keyrings/lasa-archive-keyring.gpg") == 644 ]]
  tar -xzf "dist/lasa-$version-linux-$arch.tar.gz" -C "$temp/control-$arch"
  cmp "$temp/control-$arch/bin/lasa" "dist/lasa-$version-linux-$arch"
  dpkg-deb -c "$package" > "$temp/listing"
  grep -q 'root/root' "$temp/listing"
done
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) exit 1;; esac
[[ $("$temp/extracted-$arch/usr/bin/lasa" version) == "$version" ]]
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'LASA distribution test <test@example.invalid>' ed25519 sign 0
APT_SIGNING_FINGERPRINT=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1=="fpr"{print $10;exit}')
export APT_SIGNING_FINGERPRINT
mkdir "$temp/site"
bash scripts/publish-distribution.sh "$temp/site" dist "$version" example/lasa https://example.github.io/homebrew-lasa/apt
gpg --batch --export "$APT_SIGNING_FINGERPRINT" > "$temp/keyring.gpg"
gpgv --keyring "$temp/keyring.gpg" "$temp/site/apt/dists/stable/InRelease"
gpgv --keyring "$temp/keyring.gpg" "$temp/site/apt/dists/stable/Release.gpg" "$temp/site/apt/dists/stable/Release"
bash -n "$temp/site/install-apt.sh"
for arch in amd64 arm64; do
  digest=$(sha256sum "dist/lasa-$version-linux-$arch.tar.gz" | awk '{print $1}')
  grep -q "$digest" "$temp/site/Formula/lasa.rb"
done
mkdir -p "$temp/lists/partial" "$temp/cache/archives/partial" "$temp/downloads"
mkdir "$temp/apt-parts"
: > "$temp/apt-main"
printf 'Dir::Etc::parts "%s/apt-parts";\nDir::Etc::main "%s/apt-main";\n' "$temp" "$temp" > "$temp/apt.conf"
export APT_CONFIG="$temp/apt.conf"
printf 'deb [arch=amd64,arm64 signed-by=%s] file:%s stable main\n' "$temp/keyring.gpg" "$temp/site/apt" > "$temp/sources.list"
apt_options=(-o "Dir::Etc::sourcelist=$temp/sources.list" -o Dir::Etc::sourceparts=- -o "Dir::State::lists=$temp/lists" -o Dir::State::status=/dev/null -o "Dir::Cache=$temp/cache" -o Debug::NoLocking=1 -o "APT::Sandbox::User=$(id -un)" -o APT::Update::Error-Mode=any)
apt-get "${apt_options[@]}" update
(cd "$temp/downloads" && apt-get "${apt_options[@]}" download "lasa:amd64=$version" "lasa:arm64=$version")
for arch in amd64 arm64; do cmp "dist/lasa_${version}_${arch}.deb" "$temp/downloads/lasa_${version}_${arch}.deb"; done
# Re-running preserves immutable packages and remains a valid signed repository.
bash scripts/publish-distribution.sh "$temp/site" dist "$version" example/lasa https://example.github.io/homebrew-lasa/apt
gpgv --keyring "$temp/keyring.gpg" "$temp/site/apt/dists/stable/InRelease"
# Expiry is opt-in. Exercise it with real signed metadata and an isolated APT.
release="$temp/site/apt/dists/stable/Release"
inrelease="$temp/site/apt/dists/stable/InRelease"
if grep -q '^Valid-Until: ' "$release"; then exit 1; fi
APT_VALIDITY_DAYS=7 bash scripts/publish-distribution.sh "$temp/site" dist "$version" example/lasa https://example.github.io/homebrew-lasa/apt
grep -q '^Valid-Until: ' "$release"
find "$temp/lists" -type f -delete
apt-get "${apt_options[@]}" update
expired=$(LC_ALL=C date -u -R --date=yesterday)
sed -i "s/^Valid-Until: .*/Valid-Until: $expired/" "$release"
gpg --batch --yes --local-user "$APT_SIGNING_FINGERPRINT" --clearsign --output "$inrelease" "$release"
find "$temp/lists" -type f -delete
if apt-get "${apt_options[@]}" update > "$temp/rejection" 2>&1; then echo 'APT accepted expired metadata' >&2; exit 1; fi
grep -qi 'expired' "$temp/rejection"
# Tampered signatures must be rejected by real APT, not just by a mock.
sed -i 's/Suite: stable/Suite: tampered/' "$temp/site/apt/dists/stable/InRelease"
find "$temp/lists" -type f -delete
if apt-get "${apt_options[@]}" update > "$temp/rejection" 2>&1; then echo 'APT accepted a tampered signature' >&2; exit 1; fi
grep -Eq 'BADSIG|invalid|signature' "$temp/rejection"
# Existing package bytes and newer distributions cannot be overwritten.
mkdir "$temp/bad-assets"
cp dist/*.deb "$temp/bad-assets/"
printf tampered >> "$temp/bad-assets/lasa_${version}_amd64.deb"
if bash scripts/publish-distribution.sh "$temp/site" "$temp/bad-assets" "$version" example/lasa https://example.github.io/homebrew-lasa/apt > "$temp/rejection" 2>&1; then exit 1; fi
grep -q 'Refusing to replace' "$temp/rejection"
sed -i "s/version \"$version\"/version \"999.0.0\"/" "$temp/site/Formula/lasa.rb"
if bash scripts/publish-distribution.sh "$temp/site" dist "$version" example/lasa https://example.github.io/homebrew-lasa/apt > "$temp/rejection" 2>&1; then exit 1; fi
grep -q 'Refusing to roll back' "$temp/rejection"
# Exercise the actual generated installer through key rejection. Mock only OS
# package operations/downloads; any attempted key/source installation is fatal.
mkdir "$temp/mock"
cat > "$temp/mock/apt-get" <<'EOF'
#!/bin/sh
exit 0
EOF
cat > "$temp/mock/id" <<'EOF'
#!/bin/sh
echo 0
EOF
cat > "$temp/mock/dpkg" <<'EOF'
#!/bin/sh
echo amd64
EOF
cat > "$temp/mock/curl" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = -o ]; then cp "$MOCK_KEY" "$2"; exit; fi
  shift
done
exit 1
EOF
cat > "$temp/mock/install" <<'EOF'
#!/bin/sh
echo 'Untrusted key reached privileged installation' >&2
exit 99
EOF
chmod +x "$temp/mock/"*
sed 's/^APT_FINGERPRINT=.*/APT_FINGERPRINT=0000000000000000000000000000000000000000/' "$temp/site/install-apt.sh" > "$temp/wrong-key.sh"
if MOCK_KEY="$temp/site/apt/lasa-signing-key.asc" PATH="$temp/mock:$PATH" bash "$temp/wrong-key.sh" > "$temp/rejection" 2>&1; then exit 1; fi
grep -q 'does not match the installer fingerprint' "$temp/rejection"
if grep -q 'Untrusted key reached' "$temp/rejection"; then exit 1; fi
echo 'PASS: reproducible packages, both architectures, signatures, real isolated APT downloads, repeat publishing, expiry/tamper/key rejection and downgrade/immutability guards'
