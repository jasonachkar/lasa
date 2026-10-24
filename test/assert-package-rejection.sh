#!/bin/sh
# An expected verification failure must not be a crash or an unrelated success.
set -eu
pattern=${1:?Missing expected rejection pattern}
shift
log=$(mktemp)
trap 'rm -f "$log"' EXIT
status=0
"$@" > "$log" 2>&1 || status=$?
cat "$log"
if [ "$status" = 0 ]; then
  echo 'Package client accepted deliberately tampered metadata.' >&2
  exit 1
fi
if [ "$status" -ge 128 ] || grep -Eiq 'QEMU.*(SIG|fatal|error)|Segmentation fault|core dumped' "$log"; then
  echo 'Package client crashed during rejection testing; this is not evidence of signature enforcement.' >&2
  exit 1
fi
if ! grep -Eiq "$pattern" "$log"; then
  echo 'Package client failed without the expected signature/metadata rejection diagnostic.' >&2
  exit 1
fi
