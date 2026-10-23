#!/usr/bin/env bash
# Synthetic visibility/pressure checks in child namespaces of the disposable VM.
set -euo pipefail
[[ $# = 2 && ${LASA_PRIVILEGED_TESTS:-} = 1 ]] || { echo 'Use the disposable VM validation harness.' >&2; exit 1; }
scanner=$1
results=$2
# Expansion occurs inside the child namespace shell.
# shellcheck disable=SC2016
unshare --mount --pid --fork --mount-proc -- bash -c '
  set -euo pipefail
  mount --make-rprivate /
  mount -o remount,hidepid=2 /proc
  /usr/bin/sleep 60 &
  exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs "$1" scan --profile container --roots /usr/bin/true --format json
' _ "$scanner" > "$results/hidepid.report.json"
unshare --user --map-root-user --pid --fork --mount-proc -- "$scanner" scan --profile container --roots /usr/bin/true --format json > "$results/userns.report.json"
# Expansion occurs inside the child namespace shell.
# shellcheck disable=SC2016
unshare --mount --pid --fork --mount-proc -- bash -c '
  set -euo pipefail
  for _ in $(seq 1 64); do /usr/bin/sleep 60 & done
  exec "$1" scan --profile container --max-processes 8 --max-files 1 --roots /usr/bin/true --format json
' _ "$scanner" > "$results/pressure.report.json"
python3 - "$results" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
hidden = json.load(open(root / 'hidepid.report.json'))
assert hidden['profile'] == 'container'
assert all(p['identity']['uid'][1] != 0 for p in hidden['processes']), 'hidepid concealed scope was treated as host-root visibility'
userns = json.load(open(root / 'userns.report.json'))
assert not any(o['key'] == 'privilege.host_root' and o['state'] == 'observed' and o.get('value') == 'true' for o in userns['observations']), 'user-namespace root was treated as initial-namespace root'
pressure = json.load(open(root / 'pressure.report.json'))
assert not pressure['complete'] and len(pressure['processes']) <= 8
assert any(d['code'] == 'RESOURCE_LIMIT' for d in pressure['diagnostics']), 'process-budget truncation was hidden'
PY
