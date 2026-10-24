#!/usr/bin/env bash
# Bounded public-fixture execution; never used to mount owner credentials.
set -euo pipefail
seconds=${1:?Missing container time budget}
label=${2:?Missing fixture label}
shift 2
[[ $seconds =~ ^[1-9][0-9]{0,2}$ && $seconds -le 900 ]] || { echo 'Container time budget must be 1-900 seconds.' >&2; exit 1; }
temp=$(mktemp -d)
cleanup() {
  local cid
  if [ -s "$temp/cid" ]; then
    cid=$(cat "$temp/cid")
    if [[ $cid =~ ^[a-f0-9]{12,64}$ ]]; then
      timeout --signal=TERM --kill-after=5s 15s docker rm --force "$cid" >/dev/null 2>&1 || true
    fi
  fi
  rm -rf "$temp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'Package check: %s (execution limit %s seconds)\n' "$label" "$seconds"
status=0
# The VM's Docker CLI runs through sudo. Capture stdout into a file opened by
# this user, rather than asking that root CLI to create an unreadable CID file.
timeout --signal=TERM --kill-after=5s 30s docker create --env TERM=dumb --env NO_COLOR=1 "$@" > "$temp/cid" || status=$?
if [ "$status" = 0 ]; then
  cid=$(cat "$temp/cid")
  [[ $cid =~ ^[a-f0-9]{12,64}$ ]] || { echo 'Docker returned an invalid container ID; verification failed.' >&2; exit 1; }
  timeout --signal=TERM --kill-after=10s "${seconds}s" docker start --attach "$cid" || status=$?
fi
if [ "$status" != 0 ]; then
  if [ "$status" = 124 ]; then
    printf 'Package check timed out: %s. Its disposable container is being removed; verification did not pass.\n' "$label" >&2
  elif [ "$status" = 137 ]; then
    printf 'Package check was killed: %s (exit 137). Check the execution deadline or guest memory pressure; verification did not pass.\n' "$label" >&2
  elif [ "$status" -ge 128 ]; then
    printf 'Package check crashed: %s (exit %s). A signal or emulator crash is not a successful security rejection.\n' "$label" "$status" >&2
  else
    printf 'Package check failed: %s (exit %s). See the preceding tool error.\n' "$label" "$status" >&2
  fi
  exit "$status"
fi
