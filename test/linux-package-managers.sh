#!/usr/bin/env bash
# Real native clients in ephemeral containers; no host package database/trust changed.
set -euo pipefail
site=${1:?Usage: linux-package-managers.sh PUBLIC_SITE VERSION}
version=${2:?Missing version}
next_site=${3:-$site}
next_version=${4:-$version}
next_site=$(cd "$next_site" && pwd)
site=$(cd "$site" && pwd)
installer=$(cd "$(dirname "$0")/../scripts" && pwd)/install-linux-body.sh
case "$(uname -m)" in
  x86_64) ;;
  aarch64|arm64)
    if [ "${LASA_TEST_EMULATED_AMD64:-}" != 1 ] || ! grep -qx enabled /proc/sys/fs/binfmt_misc/qemu-x86_64 || ! grep -Eq '^flags:.*F' /proc/sys/fs/binfmt_misc/qemu-x86_64; then
      echo 'AMD64 package-client fixtures on ARM64 require explicit emulation and a registered static QEMU handler.' >&2
      exit 1
    fi
    echo 'Package-client matrix: emulated AMD64 on ARM64; this does not establish native ARM64 package-client compatibility.'
    ;;
  *) echo 'This package-client matrix requires AMD64 or explicitly enabled ARM64 emulation.' >&2; exit 1;;
esac
fedora=fedora:43@sha256:a651ddf48ea28a06ed4e1e6519f51c9f47e7a5a138722ade87369b8fbb7e5b42
suse=opensuse/leap:15.6@sha256:79be7751205ea84559990fb76b1bec71e38d6fad41c70a4f6c921b803b58f421
arch=archlinux:base@sha256:52dfbd5afb23a220d5ee92dafcb4c788d96c026ed04179890c23adef4c897fa0
alpine=alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
for image in "$fedora" "$suse" "$arch" "$alpine"; do
  docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
done
# Only public signed repository content is mounted. Private fixture keys stay outside.
docker run --platform linux/amd64 --rm --network none --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER --security-opt no-new-privileges -v "$installer:/installer.sh:ro" -v "$site:/lasa:ro" -v "$next_site:/lasa-next:ro" "$fedora" bash -euc '
  test "$(sh /installer.sh --detect)" = "dnf x86_64"
  cp -a /lasa/rpm/x86_64 /repo
  rm -f /etc/yum.repos.d/*.repo
  printf "[lasa]\nname=LASA\nbaseurl=file:///repo\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///lasa/apt/lasa-signing-key.asc\n" > /etc/yum.repos.d/lasa.repo
  dnf -y --setopt=install_weak_deps=False install lasa
  test "$(lasa version)" = "$1"
  cp -a /lasa-next/rpm/x86_64/. /repo/
  dnf clean all
  dnf -y upgrade lasa
  test "$(lasa version)" = "$2"
  dnf -y remove lasa
  ! command -v lasa
  printf tampered > /repo/repodata/repomd.xml.asc
  dnf clean all
  if dnf -y install lasa > /tmp/rejected 2>&1; then cat /tmp/rejected; exit 1; fi
  grep -Ei "signature|gpg|repomd" /tmp/rejected
' _ "$version" "$next_version"
docker run --platform linux/amd64 --rm --network none --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER --security-opt no-new-privileges -v "$installer:/installer.sh:ro" -v "$site:/lasa:ro" -v "$next_site:/lasa-next:ro" "$suse" bash -euc '
  test "$(sh /installer.sh --detect)" = "zypper x86_64"
  cp -a /lasa/rpm/x86_64 /repo
  rm -f /etc/zypp/repos.d/*.repo
  rpm --import /lasa/apt/lasa-signing-key.asc
  zypper --non-interactive addrepo --gpgcheck-strict file:///repo lasa
  zypper --non-interactive --gpg-auto-import-keys refresh lasa
  zypper --non-interactive install --no-recommends lasa
  test "$(lasa version)" = "$1"
  cp -a /lasa-next/rpm/x86_64/. /repo/
  zypper --non-interactive --gpg-auto-import-keys refresh --force lasa
  zypper --non-interactive update lasa
  test "$(lasa version)" = "$2"
  zypper --non-interactive remove lasa
  ! command -v lasa
  printf tampered > /repo/repodata/repomd.xml.asc
  if zypper --non-interactive refresh --force lasa > /tmp/rejected 2>&1; then cat /tmp/rejected; exit 1; fi
  grep -Ei "signature|gpg|verification" /tmp/rejected
' _ "$version" "$next_version"
docker run --platform linux/amd64 --rm --network none --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER --security-opt no-new-privileges -v "$installer:/installer.sh:ro" -v "$site:/lasa:ro" -v "$next_site:/lasa-next:ro" "$arch" bash -euc '
  test "$(sh /installer.sh --detect)" = "pacman x86_64"
  cp -a /lasa/arch/x86_64 /repo
  # This isolated fixture has only LASA; the existing image is never partially upgraded.
  printf "[options]\nArchitecture = x86_64\nSigLevel = Required DatabaseRequired\nLocalFileSigLevel = Required\n[lasa]\nServer = file:///repo\n" > /etc/pacman.conf
  pacman-key --init
  pacman-key --add /lasa/apt/lasa-signing-key.asc
  fingerprint=$(gpg --show-keys --with-colons /lasa/apt/lasa-signing-key.asc | awk -F: '\''$1=="fpr"{print $10;exit}'\'')
  pacman-key --lsign-key "$fingerprint"
  pacman --noconfirm -Syu lasa
  test "$(lasa version)" = "$1"
  cp -a /lasa-next/arch/x86_64/. /repo/
  pacman --noconfirm -Syyu lasa
  test "$(lasa version)" = "$2"
  pacman --noconfirm -R lasa
  ! command -v lasa
  printf tampered > /repo/lasa.db.sig
  rm -f /var/lib/pacman/sync/lasa.db*
  if pacman --noconfirm -Syy > /tmp/rejected 2>&1; then cat /tmp/rejected; exit 1; fi
  grep -Ei "signature|invalid|gpg" /tmp/rejected
' _ "$version" "$next_version"
docker run --platform linux/amd64 --rm --network none --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER --security-opt no-new-privileges -v "$installer:/installer.sh:ro" -v "$site:/lasa:ro" -v "$next_site:/lasa-next:ro" "$alpine" sh -euc '
  test "$(sh /installer.sh --detect)" = "apk x86_64"
  cp -a /lasa/apk /repo
  cp /lasa/apk/lasa.rsa.pub /etc/apk/keys/lasa.rsa.pub
  printf "/repo\n" > /etc/apk/repositories
  apk update
  apk add lasa
  test "$(lasa version)" = "$1"
  cp -a /lasa-next/apk/. /repo/
  apk update
  apk upgrade lasa
  test "$(lasa version)" = "$2"
  apk del lasa
  ! command -v lasa
  printf tampered > /repo/x86_64/APKINDEX.tar.gz
  if apk --no-cache add lasa > /tmp/rejected 2>&1; then cat /tmp/rejected; exit 1; fi
  grep -Ei "signature|invalid|bad|error|package" /tmp/rejected
' _ "$version" "$next_version"
echo 'PASS: real DNF, Zypper, Pacman and APK clients verified signed repositories, installed matching LASA, upgraded versions, removed LASA and rejected tampered repository metadata without host package/trust changes.'
