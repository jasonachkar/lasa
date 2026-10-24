#!/usr/bin/env bash
# Runs inside a disposable native client container with public fixture mounts.
set -euo pipefail
native=${1:?Missing architecture}
version=${2:?Missing installed version}
next_version=${3:?Missing upgrade version}
log=$(mktemp)
trap 'rm -f "$log"' EXIT
pacman_checked() {
  pacman "$@" 2>&1 | tee "$log"
  if grep -Eiq '^error:|could not change the root directory' "$log"; then
    echo 'Pacman reported a transaction/hook error despite its exit status; verification failed.' >&2
    exit 1
  fi
}
expected=pacman
if command -v apt-get >/dev/null; then expected=apt-get; fi
test "$(sh /installer.sh --detect)" = "$expected $native"
cp -a "/lasa/arch/$native" /repo
# Ubuntu's ARM64 fixture validates libalpm/Pacman protocol, not an Arch OS.
printf '[options]\nArchitecture = %s\nSigLevel = Required DatabaseRequired\nLocalFileSigLevel = Required\n[lasa]\nServer = file:///repo\n' "$native" > /etc/pacman.conf
pacman-key --init
pacman-key --add /lasa/apt/lasa-signing-key.asc
fingerprint=$(gpg --show-keys --with-colons /lasa/apt/lasa-signing-key.asc | awk -F: '$1=="fpr"{print $10;exit}')
pacman-key --lsign-key "$fingerprint"
pacman_checked --noconfirm -Syu lasa
test "$(lasa version)" = "$version"
cp -a "/lasa-next/arch/$native/." /repo/
pacman_checked --noconfirm -Syyu lasa
test "$(lasa version)" = "$next_version"
pacman_checked --noconfirm -R lasa
if command -v lasa; then echo 'Pacman removal left LASA installed.' >&2; exit 1; fi
printf tampered > /repo/lasa.db.sig
rm -f /var/lib/pacman/sync/lasa.db*
sh /assert-rejection.sh 'signature|invalid|gpg' pacman --noconfirm -Syy
