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
rejection=$(cd "$(dirname "$0")" && pwd)/assert-package-rejection.sh
pacman_client=$(cd "$(dirname "$0")" && pwd)/package-client-pacman.sh
# shellcheck source=scripts/package-containers.sh
source "$(dirname "$0")/../scripts/package-containers.sh"
lasa_check_package_containers
fedora=$lasa_client_fedora
suse=$lasa_client_suse
arch=$lasa_client_pacman
alpine=$lasa_client_alpine
run_client() {
  local label=$1 image=$2
  local capabilities=(--cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER)
  if [ "$label" = Pacman ]; then capabilities+=(--cap-add SYS_CHROOT); fi
  shift 2
  bash "$(dirname "$0")/../scripts/run-package-container.sh" 300 "$label on $lasa_client_platform" \
    --platform "$lasa_client_platform" --network none "${capabilities[@]}" \
    --security-opt no-new-privileges -v "$installer:/installer.sh:ro" -v "$rejection:/assert-rejection.sh:ro" -v "$pacman_client:/pacman-client.sh:ro" \
    -v "$site:/lasa:ro" -v "$next_site:/lasa-next:ro" "$image" "$@"
}
# Only public signed repository content is mounted. Private fixture keys stay outside.
# shellcheck disable=SC2016 # Expanded inside the disposable client, not the host.
run_client Fedora "$fedora" bash -euc '
  native=$1; version=$2; next_version=$3
  test "$(sh /installer.sh --detect)" = "dnf $native"
  cp -a "/lasa/rpm/$native" /repo
  rm -f /etc/yum.repos.d/*.repo
  printf "[lasa]\nname=LASA\nbaseurl=file:///repo\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=file:///lasa/apt/lasa-signing-key.asc\n" > /etc/yum.repos.d/lasa.repo
  echo "DNF: signed installation"
  dnf -q -y --setopt=install_weak_deps=False install lasa
  test "$(lasa version)" = "$version"
  cp -a "/lasa-next/rpm/$native/." /repo/
  dnf clean all
  echo "DNF: signed upgrade and removal"
  dnf -q -y upgrade lasa
  test "$(lasa version)" = "$next_version"
  dnf -q -y remove lasa
  ! command -v lasa
  printf tampered > /repo/repodata/repomd.xml.asc
  dnf clean all
  echo "DNF: tampered repository must be rejected"
  sh /assert-rejection.sh "signature|gpg|repomd" dnf -y install lasa
' _ "$lasa_client_machine" "$version" "$next_version"
# shellcheck disable=SC2016 # Expanded inside the disposable client, not the host.
run_client openSUSE "$suse" bash -euc '
  native=$1; version=$2; next_version=$3
  test "$(sh /installer.sh --detect)" = "zypper $native"
  cp -a "/lasa/rpm/$native" /repo
  rm -f /etc/zypp/repos.d/*.repo
  rpm --import /lasa/apt/lasa-signing-key.asc
  zypper --non-interactive addrepo --gpgcheck-strict file:///repo lasa
  zypper --non-interactive --gpg-auto-import-keys refresh lasa
  zypper --non-interactive install --no-recommends lasa
  test "$(lasa version)" = "$version"
  cp -a "/lasa-next/rpm/$native/." /repo/
  zypper --non-interactive --gpg-auto-import-keys refresh --force lasa
  zypper --non-interactive update lasa
  test "$(lasa version)" = "$next_version"
  zypper --non-interactive remove lasa
  ! command -v lasa
  printf tampered > /repo/repodata/repomd.xml.asc
  sh /assert-rejection.sh "signature|gpg|verification" zypper --non-interactive refresh --force lasa
' _ "$lasa_client_machine" "$version" "$next_version"
run_client Pacman "$arch" bash /pacman-client.sh "$lasa_client_machine" "$version" "$next_version"
# shellcheck disable=SC2016 # Expanded inside the disposable client, not the host.
run_client Alpine "$alpine" sh -euc '
  native=$1; version=$2; next_version=$3
  test "$(sh /installer.sh --detect)" = "apk $native"
  cp -a /lasa/apk /repo
  cp /lasa/apk/lasa.rsa.pub /etc/apk/keys/lasa.rsa.pub
  printf "/repo\n" > /etc/apk/repositories
  apk update
  apk add lasa
  test "$(lasa version)" = "$version"
  cp -a /lasa-next/apk/. /repo/
  apk update
  apk upgrade lasa
  test "$(lasa version)" = "$next_version"
  apk del lasa
  ! command -v lasa
  printf tampered > "/repo/$native/APKINDEX.tar.gz"
  sh /assert-rejection.sh "signature|invalid|bad|error|package" apk --no-cache add lasa
' _ "$lasa_client_machine" "$version" "$next_version"
echo 'PASS: real DNF, Zypper, Pacman and APK clients verified signed repositories, installed matching LASA, upgraded versions, removed LASA and rejected tampered repository metadata without host package/trust changes.'
