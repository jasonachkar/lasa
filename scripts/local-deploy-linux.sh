#!/usr/bin/env bash
# Runs only inside the disposable Ubuntu publisher created by deploy-local.py.
set -euo pipefail
umask 077
stage=initialization
trap 'printf "Local Linux publisher failed during %s (line %s).\n" "$stage" "$LINENO" >&2' ERR
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
        apt-get install -y --no-install-recommends qemu-user-static binfmt-support
        update-binfmts --enable qemu-x86_64
        ;;
      *) echo 'The publisher supports AMD64 and ARM64 guests.' >&2; exit 1;;
    esac
    stage='installing checksum-verified Go 1.27.2'
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --max-time 90 --max-filesize 8388608 \
      'https://go.dev/dl/?mode=json&include=all' -o "$tools/go-releases.json"
    python3 - "$tools/go-releases.json" "$arch" > "$tools/go.sha256" <<'PY'
import json, re, sys
filename = 'go1.27.2.linux-' + sys.argv[2] + '.tar.gz'
for release in json.load(open(sys.argv[1])):
    for artifact in release.get('files', []):
        if artifact.get('filename') == filename and re.fullmatch('[a-f0-9]{64}', artifact.get('sha256', '')):
            print(artifact['sha256'] + '  go.tar.gz')
            raise SystemExit(0)
raise SystemExit('Pinned Go archive is missing from the official HTTPS manifest')
PY
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --retry 3 --max-time 240 --max-filesize 268435456 \
      "https://go.dev/dl/go1.27.2.linux-$arch.tar.gz" -o "$tools/go.tar.gz"
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
    python3 -m venv "$tools/docs-venv"
    "$tools/docs-venv/bin/python" -m pip install --disable-pip-version-check -r requirements-docs.txt
    ;;
  verify)
    test "$(id -u)" != 0 || { echo 'Verification runs as the guest user, before owner credentials arrive.' >&2; exit 1; }
    export PATH="$tools/bin:$tools/go/bin:$tools/docs-venv/bin:$PATH" GOTOOLCHAIN=local VERSION=0.0.0
    go_path=$(go env GOPATH)
    export PATH="$go_path/bin:$PATH"
    case "$(uname -m)" in aarch64|arm64) export LASA_TEST_EMULATED_AMD64=1;; esac
    stage='verification and reproducibility'
    make tools
    make check fuzz reproducible packages
    python -m unittest discover -s test -p 'test_*.py'
    bash test/docs.sh
    bash test/bootstrap-distribution.sh
    bash test/versioning.sh
    bash test/domain.sh
    bash test/release-provenance.sh
    bash test/distribution.sh
    shellcheck scripts/*.sh test/*.sh
    git diff --exit-code
    test -z "$(git status --porcelain)"
    python - <<'PY'
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
    export PATH="$tools/bin:$tools/go/bin:$tools/docs-venv/bin:$PATH" GOTOOLCHAIN=local
    go_path=$(go env GOPATH)
    export PATH="$go_path/bin:$PATH"
    python scripts/local-release.py /home/ubuntu/.lasa-local/credentials.json
    ;;
esac
