#!/usr/bin/env bash
# Run on Linux with access to the owner's APT signing key.
# Updates a checked-out distribution repository; committing/pushing is separate.
set -euo pipefail
umask 022
trap 'printf "Distribution generation failed at line %s: %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR
site=$(cd "${1:?Usage: publish-distribution.sh SITE DIST VERSION OWNER/REPO APT_URL}" && pwd)
assets=$(cd "${2:?Missing assets directory}" && pwd)
version=${3:?Missing version}
repository=${4:?Missing source repository}
apt_url=${5:?Missing APT URL}
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 1
[[ $repository =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || exit 1
[[ $apt_url =~ ^https://[a-z0-9-]+\.github\.io/[A-Za-z0-9_.-]+/apt$ || $apt_url == https://lasa.secureobs.com/apt ]] || { echo 'Expected the LASA custom domain or a GitHub Pages HTTPS APT URL' >&2; exit 1; }
[[ ${APT_SIGNING_FINGERPRINT:-} =~ ^[A-F0-9]{40}$ ]] || { echo 'APT_SIGNING_FINGERPRINT must identify exactly one signing key' >&2; exit 1; }
validity_days=${APT_VALIDITY_DAYS:-}
if [[ -n $validity_days && ! $validity_days =~ ^([1-9]|[1-8][0-9]|90)$ ]]; then
  echo 'APT_VALIDITY_DAYS must be 1 through 90, or unset.' >&2
  exit 1
fi
for tool in dpkg-scanpackages apt-ftparchive gpg sha256sum gzip; do command -v "$tool" >/dev/null || { echo "Missing publishing dependency: $tool" >&2; exit 1; }; done
# Read configuration before APT's system snippets, including unrelated hooks.
# Index as the current unprivileged user, who can read the private staging tree.
index_config_dir=$(mktemp -d)
trap 'rm -rf "$index_config_dir"' EXIT
mkdir "$index_config_dir/parts"
: > "$index_config_dir/main"
index_config="$index_config_dir/config"
printf 'Dir::Etc::parts "%s/parts";\nDir::Etc::main "%s/main";\nAPT::Sandbox::User "%s";\n' "$index_config_dir" "$index_config_dir" "$(id -un)" > "$index_config"
if [ -f "$site/Formula/lasa.rb" ]; then
  previous=$(sed -n 's/^  version "\([0-9][0-9.]*\)"$/\1/p' "$site/Formula/lasa.rb")
  [[ $previous =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Cannot safely identify the existing formula version' >&2; exit 1; }
  if dpkg --compare-versions "$version" lt "$previous"; then
    echo "Refusing to roll back the distribution from $previous to $version" >&2
    exit 1
  fi
fi
mkdir -p "$site/apt/pool/main/l/lasa" "$site/Formula"
touch "$site/.nojekyll"
for arch in amd64 arm64; do
  package="lasa_${version}_${arch}.deb"
  # A version is immutable. Never replace bytes already offered to APT users.
  if [ -f "$site/apt/pool/main/l/lasa/$package" ]; then
    cmp "$assets/$package" "$site/apt/pool/main/l/lasa/$package" || { echo "Refusing to replace published $package; increment the version" >&2; exit 1; }
  else
    install -m 0644 "$assets/$package" "$site/apt/pool/main/l/lasa/$package"
  fi
done
(
  cd "$site/apt"
  for arch in amd64 arm64; do
    directory="dists/stable/main/binary-$arch"
    mkdir -p "$directory"
    dpkg-scanpackages --arch "$arch" --multiversion pool /dev/null > "$directory/Packages"
    gzip -n -9 -c "$directory/Packages" > "$directory/Packages.gz"
  done
  # By-hash avoids mismatched indexes while Pages caches are being refreshed.
  for directory in dists/stable/main/binary-*; do
    mkdir -p "$directory/by-hash/SHA256" "$directory/by-hash/SHA512"
    for index in Packages Packages.gz; do
      install -m 0644 "$directory/$index" "$directory/by-hash/SHA256/$(sha256sum "$directory/$index" | awk '{print $1}')"
      install -m 0644 "$directory/$index" "$directory/by-hash/SHA512/$(sha512sum "$directory/$index" | awk '{print $1}')"
    done
  done
  rm -f dists/stable/Release dists/stable/InRelease dists/stable/Release.gpg
  APT_CONFIG="$index_config" apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=LASA \
    -o APT::FTPArchive::Release::Label=LASA \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o 'APT::FTPArchive::Release::Architectures=amd64 arm64' \
    -o APT::FTPArchive::Release::Components=main \
    -o APT::FTPArchive::Release::Acquire-By-Hash=yes \
    release dists/stable > Release.new
  if [[ -n $validity_days ]]; then
    expiry=$(LC_ALL=C date -u -R --date="+$validity_days days")
    # Release is one deb822 stanza. Insert the field before the checksum lists.
    sed -i "/^Date: /a Valid-Until: $expiry" Release.new
    grep -Fxq "Valid-Until: $expiry" Release.new
  fi
  mv Release.new dists/stable/Release
  for arch in amd64 arm64; do
    for index in Packages Packages.gz; do
      path="main/binary-$arch/$index"
      digest=$(sha256sum "dists/stable/$path" | awk '{print $1}')
      awk -v digest="$digest" -v path="$path" '$1==digest && $3==path{found=1} END{exit !found}' dists/stable/Release || { echo "Release metadata does not authenticate $path" >&2; exit 1; }
    done
  done
  grep -qx 'Acquire-By-Hash: yes' dists/stable/Release
  gpg --batch --yes --local-user "$APT_SIGNING_FINGERPRINT" --digest-algo SHA256 --clearsign --output dists/stable/InRelease dists/stable/Release
  gpg --batch --yes --local-user "$APT_SIGNING_FINGERPRINT" --digest-algo SHA256 --armor --detach-sign --output dists/stable/Release.gpg dists/stable/Release
  gpg --batch --armor --export "$APT_SIGNING_FINGERPRINT" > lasa-signing-key.asc
  test -s lasa-signing-key.asc
  printf '%s\n' "$APT_SIGNING_FINGERPRINT" > signing-key-fingerprint.txt
)
amd64=$(sha256sum "$assets/lasa-$version-linux-amd64.tar.gz" | awk '{print $1}')
arm64=$(sha256sum "$assets/lasa-$version-linux-arm64.tar.gz" | awk '{print $1}')
cat > "$site/Formula/lasa.rb" <<EOF
class Lasa < Formula
  desc "Scoped read-only Linux attack surface analyzer"
  homepage "https://github.com/$repository"
  version "$version"
  license "MIT"
  depends_on :linux

  on_linux do
    on_intel do
      url "https://github.com/$repository/releases/download/v$version/lasa-$version-linux-amd64.tar.gz"
      sha256 "$amd64"
    end
    on_arm do
      url "https://github.com/$repository/releases/download/v$version/lasa-$version-linux-arm64.tar.gz"
      sha256 "$arm64"
    end
  end

  def install
    bin.install "bin/lasa"
    doc.install Dir["share/doc/lasa/*"]
  end

  test do
    assert_equal version.to_s, shell_output("#{bin}/lasa version").strip
    system bin/"lasa", "rules", "list"
  end
end
EOF
# The installer pins the expected key rather than trusting any downloaded key.
{
  printf '#!/usr/bin/env bash\nAPT_URL=%q\nAPT_FINGERPRINT=%q\n' "$apt_url" "$APT_SIGNING_FINGERPRINT"
  cat "$(dirname "$0")/install-apt-body.sh"
} > "$site/install-apt.sh"
chmod 0755 "$site/install-apt.sh"
cat > "$site/README.md" <<EOF
# LASA packages

Generated Linux AMD64/ARM64 packages from [$repository](https://github.com/$repository).
APT repository: $apt_url (suite stable, component main).
Signing key fingerprint: $APT_SIGNING_FINGERPRINT.
Run install-apt.sh on Debian/Ubuntu, or use this repository as a Linux Homebrew tap.
LASA requires Linux openat2 support. It cannot scan macOS or native Windows.
Installing the package does not start a service or perform a scan.
EOF
