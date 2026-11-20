#!/usr/bin/env bash
# Local release tests exercise inert fixtures and an isolated GitHub API mock.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
mkdir "$temp/bin" "$temp/assets"
export GITHUB_REPOSITORY=example/lasa GITHUB_REF=refs/heads/main GITHUB_EVENT_NAME=workflow_dispatch
GITHUB_SHA=$(git rev-parse HEAD)
export GITHUB_SHA
export PATH="$temp/bin:$PATH"
cat > "$temp/bin/gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'api repos/example/lasa/commits/refs/tags/v1.2.3 --jq .sha')
    echo "${TAG_SHA:-$GITHUB_SHA}";;
  'api --method GET repos/example/lasa/actions/workflows/ci.yml/runs -f event=push -f branch=main -f head_sha='"$GITHUB_SHA"' -F per_page=20 --jq '*)
    echo "${CI_RUN-42}";;
  'api repos/example/lasa/actions/runs/42 --jq '*)
    echo "example/lasa $GITHUB_SHA main push ${RUN_RESULT-success} .github/workflows/ci.yml";;
  'api repos/example/lasa/actions/runs/42/jobs?filter=latest&per_page=100 --jq '*)
    echo "${GATE_RESULT-success}";;
  *)
    echo 'Unexpected GitHub command' >&2
    exit 90;;
esac
MOCK
chmod +x "$temp/bin/gh"
reject() {
  if "$@" > "$temp/rejected" 2>&1; then
    echo 'Unexpected release verification success' >&2
    exit 1
  fi
}
verify() { bash "$root/scripts/security/verify-release-source.sh" "$@"; }
verify v1.2.3
GITHUB_REF=refs/heads/feature reject verify v1.2.3
GITHUB_EVENT_NAME=push reject verify v1.2.3
reject verify v1.2.3-extra
TAG_SHA=0000000000000000000000000000000000000000 reject verify v1.2.3
CI_RUN='' reject verify v1.2.3
RUN_RESULT=failure reject verify v1.2.3
GATE_RESULT=skipped reject verify v1.2.3
GATE_RESULT='success success' reject verify v1.2.3
python3 - "$temp/assets" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
(root / "lasa-1.2.3-licenses.tar.gz").write_text("licenses")
for arch in ["amd64", "arm64"]:
    for name in [f"lasa-1.2.3-linux-{arch}", f"lasa-1.2.3-linux-{arch}.tar.gz", f"lasa_1.2.3_{arch}.deb"]:
        (root / name).write_text(name)
    sbom = {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"name": "example/lasa", "version": "v1.2.3",
                                   "purl": f"pkg:golang/example/lasa?goos=linux&goarch={arch}"}},
        "components": [{"name": x} for x in ["github.com/cilium/ebpf", "github.com/spf13/cobra",
                                           "github.com/spf13/pflag", "golang.org/x/sys", "gopkg.in/yaml.v3", "std"]],
    }
    (root / f"lasa-{arch}.cdx.json").write_text(json.dumps(sbom))
PY
manifest() { python3 "$root/scripts/security/verify-release-assets.py" "$@" "$temp/assets" 1.2.3; }
manifest --write
manifest
printf 'tampered\n' >> "$temp/assets/lasa_1.2.3_amd64.deb"
reject manifest
manifest --write
printf 'bad-record\n' >> "$temp/assets/SHA256SUMS"
reject manifest
manifest --write
touch "$temp/assets/extra"
reject manifest
rm "$temp/assets/extra"
mv "$temp/assets/lasa_1.2.3_amd64.deb" "$temp/package"
ln -s "$temp/package" "$temp/assets/lasa_1.2.3_amd64.deb"
reject manifest
rm "$temp/assets/lasa_1.2.3_amd64.deb"
mv "$temp/package" "$temp/assets/lasa_1.2.3_amd64.deb"
cp "$temp/assets/lasa-amd64.cdx.json" "$temp/assets/lasa-arm64.cdx.json"
reject manifest --write
echo 'PASS: manual main-only release source, exact commit and CI validation, artifact and SBOM rejection.'
