#!/usr/bin/env bash
# Run the unchanged worker's failure paths in real Ubuntu, without provisioning
# packages, using owner credentials, or claiming a complete VM deployment.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=scripts/package-containers.sh
source "$root/scripts/package-containers.sh"
platform=$(lasa_native_container_platform)
image=$(lasa_ubuntu_image_for_platform "$platform")
lasa_ensure_container_image "$platform" "$image"
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
chmod 0755 "$temp"
mkdir -p "$temp/source/scripts" "$temp/source/test" "$temp/source/.build" "$temp/tools/bin"
cp "$root/scripts/local-deploy-linux.sh" "$temp/source/scripts/"
cat > "$temp/source/scripts/check-docs-environment.sh" <<'SH'
#!/bin/sh
test "$FAIL_STEP" != docs
SH
cat > "$temp/source/scripts/package-containers.sh" <<'SH'
#!/bin/sh
echo containers >> /home/ubuntu/lasa/commands
test "$FAIL_STEP" != containers
SH
cat > "$temp/source/test/local-deploy-worker.sh" <<'SH'
#!/bin/sh
exit 0
SH
cat > "$temp/tools/bin/systemd-detect-virt" <<'SH'
#!/bin/sh
# Only the fixture boundary is simulated: Docker is not a VM.
exit 0
SH
cat > "$temp/tools/bin/go" <<'SH'
#!/bin/sh
test "$1 $2" = 'env GOPATH'
echo /tmp/go
SH
cat > "$temp/tools/bin/make" <<'SH'
#!/bin/sh
echo "make $*" >> /home/ubuntu/lasa/commands
test "$*" != "$FAIL_STEP"
SH
chmod 0755 "$temp/tools/bin/"*
for step in docs containers check; do
  printf stale > "$temp/source/.build/local-verification.json"
  : > "$temp/source/commands"
  if docker run --platform "$platform" --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only \
    --user "$(id -u):$(id -g)" --env "FAIL_STEP=$step" --env PATH=/opt/lasa-local-tools/bin:/usr/bin:/bin \
    -v "$temp/tools:/opt/lasa-local-tools:ro" -v "$temp/source:/home/ubuntu/lasa:rw" \
    "$image" bash /home/ubuntu/lasa/scripts/local-deploy-linux.sh verify > "$temp/output" 2>&1; then
    echo "Worker ignored the injected $step failure." >&2; exit 1
  fi
  test ! -e "$temp/source/.build/local-verification.json"
  if [ "$step" = docs ]; then
    grep -Fq 'failed during checking the prepared Python environment' "$temp/output"
    : > "$temp/expected"
  elif [ "$step" = containers ]; then
    grep -Fq 'failed during package container platforms and execution' "$temp/output"
    printf 'containers\n' > "$temp/expected"
  else
    grep -Fq 'failed during Go checks and current vulnerability scan' "$temp/output"
    printf 'containers\nmake tools\nmake check\n' > "$temp/expected"
  fi
  cmp "$temp/expected" "$temp/source/commands"
done
echo 'PASS: original Ubuntu worker stops at the failed preflight/check, identifies the stage and removes stale verification approval before compilation/publication can proceed.'
