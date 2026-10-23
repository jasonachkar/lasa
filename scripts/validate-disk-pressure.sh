#!/usr/bin/env bash
# Invoked only in an anonymous mount namespace; failure must preserve old output.
set -euo pipefail
[[ $# = 3 && ${LASA_PRIVILEGED_TESTS:-} = 1 ]] || { echo 'Use the disposable VM validation harness.' >&2; exit 1; }
[ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ] || { echo 'An isolated mount namespace is required.' >&2; exit 1; }
scanner=$1
fixture=$2
results=$3
mount --make-rprivate /
mkdir -p "$fixture/full"
mount -t tmpfs -o size=1m,mode=0700 tmpfs "$fixture/full"
trap 'umount "$fixture/full"' EXIT
printf 'previous-private-output' > "$fixture/full/report.json"
python3 - "$fixture/full/filler" <<'PY'
import errno, sys
try:
    with open(sys.argv[1], 'wb', buffering=0) as target:
        while True:
            target.write(b'x' * 65536)
except OSError as error:
    if error.errno != errno.ENOSPC:
        raise
PY
set +e
"$scanner" scan --profile container --roots /usr/bin/true --format json --output "$fixture/full/report.json" --diagnostics-format json > "$results/disk-full.stdout" 2> "$results/disk-full.diagnostic.json"
status=$?
set -e
[ "$status" = 2 ] || { echo "Expected fatal persistence status 2, got $status" >&2; exit 1; }
python3 - "$fixture/full" "$results/disk-full.diagnostic.json" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
assert (root / 'report.json').read_text() == 'previous-private-output', 'ENOSPC replaced valid old output'
assert not list(root.glob('.lasa-*.tmp')), 'interrupted atomic output left its temporary file'
diagnostic = json.load(open(sys.argv[2]))
assert diagnostic['code'] == 'OUTPUT_WRITE_FAILED' and diagnostic.get('errno') == 28
assert diagnostic['target'] and diagnostic['cause'] and diagnostic['remediation']
PY
