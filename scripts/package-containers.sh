#!/usr/bin/env bash
# Shared, pinned container tools for repository generation and client verification.
set -euo pipefail
# AMD64 platform manifests from the previously pinned indexes:
# Fedora a651ddf48ea28a06ed4e1e6519f51c9f47e7a5a138722ade87369b8fbb7e5b42
# openSUSE 79be7751205ea84559990fb76b1bec71e38d6fad41c70a4f6c921b803b58f421
# Arch 52dfbd5afb23a220d5ee92dafcb4c788d96c026ed04179890c23adef4c897fa0
lasa_container_fedora=fedora:43@sha256:1ad64e0ebefee83263fffacc5cb139b37ff70def215e4fe44720896c83353132
lasa_container_suse=opensuse/leap:15.6@sha256:ca2942f9510c3e30fd322017782cdf6c067b2183dd7d56b39d0c697a9808ce2a
lasa_container_arch=archlinux:base@sha256:dfb01267da058e5d08ffdc543bf484c9b404655b0bac1d0201d972bf950cdfd0
# Platform manifests from the reviewed Alpine index
# sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f.
# Distinct references avoid classic Docker's index-digest cache collision when
# an ARM64 publisher also loads AMD64 clients. No image/cache deletion is needed.
lasa_container_alpine=alpine:3.22@sha256:dc92f017beea8e7f43263073d717f7bc011228c95d5312e440deb4d035bb4eec
lasa_container_alpine_arm64=alpine:3.22@sha256:3e07a4f627d12468155eb812785e10f2453a447c346872b47788a62437366764
# Ubuntu platform manifests from index
# sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac.
lasa_container_ubuntu=ubuntu:24.04@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc
lasa_container_ubuntu_arm64=ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d

lasa_native_container_platform() {
  case "$(uname -m)" in
    x86_64) echo linux/amd64;;
    aarch64|arm64) echo linux/arm64;;
    *) echo 'Package containers require an AMD64 or ARM64 Linux publisher.' >&2; return 1;;
  esac
}

lasa_alpine_image_for_platform() {
  case "$1" in
    linux/amd64) echo "$lasa_container_alpine";;
    linux/arm64) echo "$lasa_container_alpine_arm64";;
    *) echo "Unsupported Alpine platform: $1" >&2; return 1;;
  esac
}

lasa_ubuntu_image_for_platform() {
  case "$1" in
    linux/amd64) echo "$lasa_container_ubuntu";;
    linux/arm64) echo "$lasa_container_ubuntu_arm64";;
    *) echo "Unsupported Ubuntu platform: $1" >&2; return 1;;
  esac
}

lasa_ensure_container_image() {
  local platform=$1 image=$2 actual
  case "$platform" in linux/amd64|linux/arm64) ;; *) echo "Unsupported container platform: $platform" >&2; return 1;; esac
  # An image-index digest can resolve to a cached image for the wrong platform.
  # Inspect its architecture rather than treating existence as sufficient.
  actual=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image" 2>/dev/null) || actual=
  if [ "$actual" != "$platform" ]; then
    printf 'Fetching package container: %s (%s)\n' "$image" "$platform"
    if ! docker pull --platform "$platform" "$image"; then
      printf 'Cannot fetch package container %s for %s. Check registry connectivity and the pinned platform manifest.\n' "$image" "$platform" >&2
      return 1
    fi
    actual=$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image") || return 1
    if [ "$actual" != "$platform" ]; then
      printf 'Package container %s resolved to %s; required %s.\n' "$image" "$actual" "$platform" >&2
      return 1
    fi
  fi
}

lasa_probe_package_container() {
  local platform=$1 image=$2 machine=$3 tool=$4
  lasa_ensure_container_image "$platform" "$image" || return 1
  printf 'Checking package container execution: %s (%s)\n' "$image" "$platform"
  if ! docker run --platform "$platform" --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    "$image" sh -ec 'test "$(uname -m)" = "$1"; "$2" --version' _ "$machine" "$tool" >/dev/null; then
    printf 'Package container execution failed: %s on %s. On ARM64, check the registered static QEMU AMD64 handler; no publishing credentials are needed for this check.\n' "$image" "$platform" >&2
    return 1
  fi
}

lasa_check_package_containers() {
  local native native_image machine
  native=$(lasa_native_container_platform) || return 1
  native_image=$(lasa_alpine_image_for_platform "$native") || return 1
  docker info >/dev/null || { echo 'The guest Docker daemon is unavailable; package-container checks cannot start.' >&2; return 1; }
  if [ "$native" = linux/arm64 ]; then
    if [ "${LASA_TEST_EMULATED_AMD64:-}" != 1 ] || ! grep -qx enabled /proc/sys/fs/binfmt_misc/qemu-x86_64 || ! grep -Eq '^flags:.*F' /proc/sys/fs/binfmt_misc/qemu-x86_64; then
      echo 'AMD64 package clients on ARM64 require explicit emulation and an enabled static QEMU handler with the fix-binary (F) flag. Guest preparation must register it before verification.' >&2
      return 1
    fi
    machine=aarch64
    echo 'Package clients: emulated AMD64 on ARM64; this does not establish native ARM64 client compatibility.'
  else
    machine=x86_64
  fi
  # Repository generation uses native Alpine; clients deliberately use AMD64.
  lasa_probe_package_container "$native" "$native_image" "$machine" apk || return 1
  lasa_probe_package_container linux/amd64 "$lasa_container_fedora" x86_64 dnf || return 1
  lasa_probe_package_container linux/amd64 "$lasa_container_suse" x86_64 zypper || return 1
  lasa_probe_package_container linux/amd64 "$lasa_container_arch" x86_64 pacman || return 1
  if [ "$native" != linux/amd64 ]; then
    lasa_probe_package_container linux/amd64 "$lasa_container_alpine" x86_64 apk || return 1
  fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  [[ $# = 0 ]] || { echo 'Usage: bash scripts/package-containers.sh' >&2; exit 1; }
  lasa_check_package_containers
fi
