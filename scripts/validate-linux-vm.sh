#!/usr/bin/env bash
# This harness installs tools and creates short-lived fixtures only inside an authorized disposable VM.
set -euo pipefail
umask 077
[[ $# = 1 && $1 = --disposable-vm ]] || { echo 'Run only on an authorized disposable VM: scripts/validate-linux-vm.sh --disposable-vm' >&2; exit 1; }
[ "$(id -u)" = 0 ] || { echo 'The disposable VM harness requires root to validate namespaces, DAC and eBPF. The scanner never elevates itself.' >&2; exit 1; }
if ! command -v systemd-detect-virt >/dev/null || ! systemd-detect-virt --vm >/dev/null; then
  echo 'A detected virtual machine is required; this harness refuses a bare-metal or container host.' >&2
  exit 1
fi
cd "$(dirname "$0")/.."
results="$PWD/.build/validation-results"
mkdir -p "$results"
fixture="/opt/lasa-validation-$$"
unit="a-lasa-validation-$$"
cleanup() {
  status=$?
  trap - EXIT INT TERM
  systemctl stop "$unit.service" >/dev/null 2>&1 || true
  systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  rm -rf -- "$fixture"
  python3 - "$results/result.json" "$status" "${LASA_VALIDATION_REVISION:-unknown}" <<'PY'
import json, platform, sys
from datetime import datetime, timezone
with open(sys.argv[1], 'w') as target:
    json.dump({'schema': 'lasa.validation/v1', 'completed_at': datetime.now(timezone.utc).isoformat(), 'exit_code': int(sys.argv[2]), 'source_revision': sys.argv[3], 'architecture': platform.machine(), 'kernel': platform.release(), 'scope': 'This VM only; results do not establish support for other distributions, architectures or kernels.'}, target, indent=2)
PY
  if id ubuntu >/dev/null 2>&1; then chown ubuntu:ubuntu "$PWD/.build"; chown -R ubuntu:ubuntu "$results"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
exec > >(tee "$results/harness.log") 2>&1
if command -v apt-get >/dev/null; then
  apt-get update -o APT::Update::Error-Mode=any
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl python3 build-essential openssh-server sudo nftables iproute2 acl util-linux
elif command -v dnf >/dev/null; then
  dnf install -y --setopt=install_weak_deps=False ca-certificates curl python3 gcc gcc-c++ make openssh-server sudo nftables iproute acl util-linux
else
  echo "The disposable VM harness needs apt-get or dnf; no package manager was found." >&2
  exit 1
fi
case "$(uname -m)" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) echo 'Unsupported native validation architecture' >&2; exit 1;; esac
version=1.27.2
tools="$PWD/.build/validation-tools"
mkdir -p "$tools"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 60 --max-filesize 8388608 'https://go.dev/dl/?mode=json&include=all' -o "$tools/go-releases.json"
python3 - "$tools/go-releases.json" "$version" "$arch" > "$tools/go.sha256" <<'PY'
import json, sys
filename = f'go{sys.argv[2]}.linux-{sys.argv[3]}.tar.gz'
for release in json.load(open(sys.argv[1])):
    for file in release.get('files', []):
        if file.get('filename') == filename:
            print(file['sha256'] + '  go.tar.gz')
            raise SystemExit(0)
raise SystemExit('Pinned Go archive is missing from the official release manifest')
PY
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --max-time 180 --max-filesize 268435456 "https://go.dev/dl/go$version.linux-$arch.tar.gz" -o "$tools/go.tar.gz"
(cd "$tools" && sha256sum -c go.sha256 && tar -xzf go.tar.gz)
export PATH="$tools/go/bin:$PATH" GOTOOLCHAIN=local
export GOCACHE="$tools/go-cache" GOMODCACHE="$tools/modules"
export LASA_PRIVILEGED_TESTS=1
go version | tee "$results/toolchain.txt"
uname -a | tee "$results/kernel.txt"
if [ ! -r /sys/kernel/btf/vmlinux ]; then echo 'VM kernel BTF is unavailable; privileged validation cannot pass.' >&2; exit 1; fi
if [ ! -r /sys/kernel/tracing/events/sched/sched_process_exec/format ]; then
  mount -t tracefs tracefs /sys/kernel/tracing
fi
go test -count=1 -json ./... > "$results/tests.jsonl"
go test -race -count=1 ./... > "$results/race.txt" 2>&1
go vet ./...
make build
mkdir -p "$fixture"
printf '#!/bin/sh\nexec /usr/bin/sleep 300\n' > "$fixture/job.sh"
chmod 0755 "$fixture"
chmod 0777 "$fixture/job.sh"
install -m 0755 ./bin/lasa "$fixture/lasa"
systemd-run --unit "$unit" --property=User=root --property=NoNewPrivileges=no "$fixture/job.sh"
./bin/lasa scan --profile deep --inspect systemd,ssh,sudo,permissions,scheduler --max-inspection-items 1024 --timeout 2m --format json --output "$results/configuration.report.json"
python3 - "$results/configuration.report.json" "$unit" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
labels = {asset['id']: asset['label'] for asset in report.get('assets', [])}
assert any(f['rule_id'] == 'LASA-101' and labels.get(f['subject']) == sys.argv[2] + '.service' for f in report['findings']), 'Known writable root service was not detected'
PY
# Anonymous network namespace: no changes to the VM's own firewall or interfaces.
unshare --net -- bash scripts/validate-network-namespace.sh "$results/network.report.json"
bash scripts/validate-isolation.sh "$fixture/lasa" "$results"
unshare --mount -- bash scripts/validate-disk-pressure.sh "$fixture/lasa" "$fixture" "$results"
./bin/lasa scan --profile sensor --sensor-duration 3s --roots "$fixture" --format json --output "$results/sensor.report.json"
python3 - "$results/sensor.report.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
assert any(c['collector'] == 'ebpf' and c['complete'] for c in report['coverage']), 'Runtime sensor coverage was incomplete'
PY
echo 'PASS: native VM unit/race tests, privileged DAC and eBPF, real service inspection, isolated nftables, hidepid/user namespaces, bounded process pressure and atomic disk-full recovery.'
