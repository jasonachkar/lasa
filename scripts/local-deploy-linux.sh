#!/usr/bin/env bash
# Runs only inside the disposable Ubuntu publisher created by deploy-local.py.
set -Eeuo pipefail
umask 077
stage=initialization
trap 'printf "Local Linux publisher failed during %s (line %s).\n" "$stage" "$LINENO" >&2' ERR
verification_step() {
  stage=$1
  shift
  printf 'Local verification: %s\n' "$stage"
  "$@"
}
cd "$(dirname "$0")/.."
[[ $# = 1 && $1 =~ ^(prepare|verify|publish)$ ]] || { echo 'Usage: local-deploy-linux.sh prepare|verify|publish' >&2; exit 1; }
if [ "$(uname -s)" != Linux ] || ! systemd-detect-virt --vm >/dev/null; then
  echo 'A disposable Linux VM is required; no host packages were changed.' >&2
  exit 1
fi
# shellcheck disable=SC1091
source /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'The local publisher requires its Ubuntu 24.04 guest.' >&2; exit 1; }
tools=/opt/lasa-local-tools
docs_python="$tools/docs-venv/bin/python3"
case "$1" in
  prepare)
    test "$(id -u)" = 0 || { echo 'VM preparation requires sudo inside the guest.' >&2; exit 1; }
    stage='installing guest dependencies'
    apt-get update -o APT::Update::Error-Mode=any
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl git gh jq gnupg gpgv openssh-client python3 python3-venv build-essential sudo \
      apt-utils dpkg-dev shellcheck createrepo-c rpm pacman-package-manager makepkg libarchive-tools gettext-base zstd docker.io
    systemctl start docker
    install -d -m 0755 "$tools/bin"
    # Multipass's ubuntu user already has passwordless guest sudo. No Mac Docker
    # socket, host filesystem or persistent host agent is exposed to the guest.
    printf '#!/bin/sh\nexec sudo -n /usr/bin/docker "$@"\n' > "$tools/bin/docker"
    chmod 0755 "$tools/bin/docker"
    case "$(uname -m)" in
      x86_64) arch=amd64;;
      aarch64|arm64)
        arch=arm64
        stage='registering static AMD64 emulation in the ARM64 guest'
        apt-get install -y --no-install-recommends qemu-user-static
        # Ubuntu 24.04 ships systemd binfmt.d rules (OPF), rather than a
        # qemu-x86_64 entry managed by the legacy update-binfmts database.
        test -s /usr/lib/binfmt.d/qemu-x86_64.conf || { echo 'The Ubuntu QEMU package lacks its AMD64 binfmt rule.' >&2; exit 1; }
        systemctl restart systemd-binfmt.service
        if ! grep -qx enabled /proc/sys/fs/binfmt_misc/qemu-x86_64 || ! grep -Eq '^flags:.*F' /proc/sys/fs/binfmt_misc/qemu-x86_64; then
          echo 'Static AMD64 emulation was not registered with the required fix-binary (F) flag; check the guest systemd-binfmt service.' >&2
          exit 1
        fi
        ;;
      *) echo 'The publisher supports AMD64 and ARM64 guests.' >&2; exit 1;;
    esac
    stage='installing checksum-verified Go 1.27.3'
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --max-time 90 --max-filesize 8388608 \
      'https://go.dev/dl/?mode=json&include=all' -o "$tools/go-releases.json"
    python3 - "$tools/go-releases.json" "$arch" > "$tools/go.sha256" <<'PY'
import json, re, sys
filename = 'go1.27.3.linux-' + sys.argv[2] + '.tar.gz'
for release in json.load(open(sys.argv[1])):
    for artifact in release.get('files', []):
        if artifact.get('filename') == filename and re.fullmatch('[a-f0-9]{64}', artifact.get('sha256', '')):
            print(artifact['sha256'] + '  go.tar.gz')
            raise SystemExit(0)
raise SystemExit('Pinned Go archive is missing from the official HTTPS manifest')
PY
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --max-time 240 --max-filesize 268435456 \
      "https://go.dev/dl/go1.27.3.linux-$arch.tar.gz" -o "$tools/go.tar.gz"
    (cd "$tools" && sha256sum -c go.sha256 && tar -xzf go.tar.gz)
    stage='installing GitHub CLI with attestation verification support'
    # Ubuntu 24.04's base CLI predates gh attestation verify. Pin the official
    # release and pin its official SHA-256 for each builder architecture.
    gh_version=2.83.2
    case "$arch" in
      amd64) gh_digest=ca6e7641214fbd0e21429cec4b64a7ba626fd946d8f9d6d191467545b092015e;;
      arm64) gh_digest=b1a0c0a0fcf18524e36996caddc92a062355ed014defc836203fe20fba75a38e;;
    esac
    gh_archive="gh_${gh_version}_linux_${arch}.tar.gz"
    printf '%s  %s\n' "$gh_digest" "$gh_archive" > "$tools/gh.sha256"
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --max-time 240 --max-filesize 67108864 \
      "https://github.com/cli/cli/releases/download/v$gh_version/$gh_archive" -o "$tools/$gh_archive"
    (cd "$tools" && sha256sum -c gh.sha256 && tar -xzf "$gh_archive")
    ln -s "$tools/gh_${gh_version}_linux_${arch}/bin/gh" "$tools/bin/gh"
    stage='installing pinned documentation dependencies'
    bash scripts/install-public-docs-venv.sh "$tools/docs-venv" requirements-docs.txt
    stage='checking documentation tools as the ordinary publisher user'
    sudo -u ubuntu -- bash "$PWD/scripts/check-docs-environment.sh" "$docs_python"
    ;;
  verify)
    test "$(id -u)" != 0 || { echo 'Verification runs as the guest user, before owner credentials arrive.' >&2; exit 1; }
    stage='invalidating previous verification approval'
    rm -f .build/local-verification.json
    export PATH="$tools/docs-venv/bin:$tools/bin:$tools/go/bin:$PATH" GOTOOLCHAIN=local VERSION=0.0.0
    export PYTHON="$docs_python" VIRTUAL_ENV="$tools/docs-venv"
    stage='checking the prepared Python environment'
    bash scripts/check-docs-environment.sh "$PYTHON"
    go_path=$(go env GOPATH)
    export PATH="$go_path/bin:$PATH"
    case "$(uname -m)" in aarch64|arm64) export LASA_TEST_EMULATED_AMD64=1;; esac
    # Fail on platform/registry/emulator problems before long compilation or any
    # owner credential transfer. Never reuse a successful record after a failure.
    verification_step 'package container platforms and execution' bash scripts/package-containers.sh
    verification_step 'guest verification failure boundaries' bash test/local-deploy-worker.sh
    verification_step 'installing pinned Go verification tools' make tools
    verification_step 'Go checks and current vulnerability scan' make check
    verification_step 'bounded parser fuzzing' make fuzz
    verification_step 'reproducible release binaries' make reproducible
    verification_step 'release package generation' make packages
    verification_step 'Python deployment and signing tests' "$PYTHON" -m unittest discover -s test -p 'test_*.py'
    verification_step 'documentation build and preservation' bash test/docs.sh
    verification_step 'distribution bootstrap and key preservation' bash test/bootstrap-distribution.sh
    verification_step 'automatic release versioning' bash test/versioning.sh
    verification_step 'documentation domain configuration' bash test/domain.sh
    verification_step 'release provenance and tamper rejection' bash test/release-provenance.sh
    verification_step 'signed repositories and package-client install/upgrade/tamper checks' bash test/distribution.sh
    verification_step 'shell lint' shellcheck scripts/*.sh test/*.sh
    verification_step 'source tree integrity' git diff --exit-code
    test -z "$(git status --porcelain)"
    "$PYTHON" - <<'PY'
import json, pathlib, platform, subprocess
pathlib.Path('.build').mkdir(exist_ok=True)
pathlib.Path('.build/local-verification.json').write_text(json.dumps({
    'schema': 'lasa.local-verification/v1', 'verified': True,
    'source_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'architecture': platform.machine(),
    'package_clients': 'native AMD64' if platform.machine() == 'x86_64' else 'emulated AMD64; not native ARM64 validation',
}) + '\n')
PY
    ;;
  publish)
    test "$(id -u)" != 0 || { echo 'Publication runs as the guest user.' >&2; exit 1; }
    stage='publishing verified artifacts'
    export PATH="$tools/docs-venv/bin:$tools/bin:$tools/go/bin:$PATH" GOTOOLCHAIN=local
    export PYTHON="$docs_python" VIRTUAL_ENV="$tools/docs-venv"
    bash scripts/check-docs-environment.sh "$PYTHON"
    go_path=$(go env GOPATH)
    export PATH="$go_path/bin:$PATH"
    "$PYTHON" scripts/local-release.py /home/ubuntu/.lasa-local/credentials.json
    ;;
esac
