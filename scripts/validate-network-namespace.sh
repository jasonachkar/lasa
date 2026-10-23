#!/usr/bin/env bash
# Invoked only in an anonymous network namespace by the disposable VM harness.
set -euo pipefail
[[ $# = 1 && ${LASA_PRIVILEGED_TESTS:-} = 1 ]] || { echo 'Use the disposable VM validation harness.' >&2; exit 1; }
# Refuse the VM's initial network namespace before making any interface/rule changes.
self_ns=$(readlink /proc/self/ns/net)
init_ns=$(readlink /proc/1/ns/net)
[ "$self_ns" != "$init_ns" ] || { echo 'An isolated network namespace is required.' >&2; exit 1; }
output=$1
ip link set lo up
ip link add lasa-lab type dummy
ip addr add 192.0.2.1/24 dev lasa-lab
ip link set lasa-lab up
nft add table inet lasa_validation
nft 'add chain inet lasa_validation input { type filter hook input priority 0; policy drop; }'
nft add rule inet lasa_validation input tcp dport 6379 accept
python3 -m http.server 6379 --bind 0.0.0.0 >/dev/null 2>&1 &
listener=$!
trap 'kill "$listener" 2>/dev/null || true; wait "$listener" 2>/dev/null || true' EXIT
python3 - "$listener" <<'PY'
import os, socket, sys, time
for _ in range(100):
    os.kill(int(sys.argv[1]), 0)
    try:
        with socket.create_connection(('192.0.2.1', 6379), timeout=.1):
            break
    except OSError:
        time.sleep(.05)
else:
    raise SystemExit('Isolated fixture listener did not start')
PY
./bin/lasa scan --inspect firewall --roots /usr/bin/true --timeout 30s --network-source 198.51.100.5 --network-destination 192.0.2.1 --network-interface lasa-lab --format json --output "$output"
python3 - "$output" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
assert any(f['rule_id'] == 'LASA-140' for f in report['findings']), 'Known nftables management permit was not detected'
PY
