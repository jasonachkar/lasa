#!/usr/bin/env bash
# Local release tests exercise inert fixtures and an isolated GitHub API mock.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
mkdir "$temp/bin" "$temp/assets"
export GITHUB_REPOSITORY=example/lasa GITHUB_REF=refs/heads/main GITHUB_EVENT_NAME=workflow_dispatch
unset GITHUB_ACTIONS
GITHUB_SHA=$(git rev-parse HEAD)
export GITHUB_SHA
export PATH="$temp/bin:$PATH"
cat > "$temp/bin/gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  'api repos/example/lasa --jq .owner.login') echo example;;
  'api user --jq .login') echo "${ACTOR_LOGIN:-example}";;
  'api repos/example/lasa/git/matching-refs/tags/v1.2.3 --jq '*)
    echo "${TAG_EXISTS-1}";;
  'api --method POST repos/example/lasa/git/refs -f ref=refs/tags/v1.2.3 -f sha='"$GITHUB_SHA"' --jq .ref')
    echo refs/tags/v1.2.3; touch "${CREATED_MARKER:?}";;
  'api repos/example/lasa/commits/refs/tags/v1.2.3 --jq .sha')
    echo "${TAG_SHA:-$GITHUB_SHA}";;
  'api repos/example/lasa/compare/'"$GITHUB_SHA"'...main --jq .merge_base_commit.sha')
    echo "${MAIN_BASE:-$GITHUB_SHA}";;
  'api --method GET repos/example/lasa/actions/workflows/ci.yml/runs -f event=push -f branch=main -f head_sha='"$GITHUB_SHA"' -F per_page=20 --jq '*)
    echo "${CI_RUN-42}";;
  'api repos/example/lasa/actions/runs/42 --jq '*)
    echo "example/lasa $GITHUB_SHA main push ${RUN_RESULT-success} .github/workflows/ci.yml";;
  'api repos/example/lasa/actions/runs/42/jobs?filter=latest&per_page=100 --jq '*)
    echo "${GATE_RESULT-success}";;
  'api repos/example/lasa/actions/runs/55')
    printf '{"head_repository":{"full_name":"example/lasa"},"head_sha":"%s","head_branch":"%s","path":".github/workflows/release.yml","event":"push","status":"waiting"}\n' "$GITHUB_SHA" "${APPROVAL_BRANCH:-main}";;
  'api repos/example/lasa/actions/runs/55/jobs?filter=all&per_page=100 --jq '*)
    echo "${BUILD_RESULT-success}";;
  'api repos/example/lasa/contents/CHANGELOG.md?ref='"$GITHUB_SHA"' -H Accept: application/vnd.github.raw')
    printf '# Changelog\n\n## 1.2.3 — release (2026-11-24)\n';;
  'api repos/example/lasa/actions/runs/55/pending_deployments --jq '*)
    echo "${APPROVAL_ENV-7}";;
  'api --method POST repos/example/lasa/actions/runs/55/pending_deployments -F environment_ids[]=7 -f state=approved '*)
    test -e "$CREATED_MARKER"; touch "$APPROVED_MARKER"; echo 1;;
  'attestation verify '*)
    [[ $* == *" --signer-workflow example/lasa/.github/workflows/release.yml --source-ref refs/heads/main --source-digest $GITHUB_SHA --deny-self-hosted-runners" ]]
    [[ ${ATTESTATION_RESULT:-success} == success ]];;
  'api --paginate repos/example/lasa/releases?per_page=100 --jq '*)
    echo 123;;
  'api repos/example/lasa/releases/123 --jq '*)
    echo 'v1.2.3 false false';;
  'release download v1.2.3 --repo example/lasa --dir '*)
    cp "${PUBLISHED_ASSETS:?}/"* "$7/";;
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
export CREATED_MARKER="$temp/created"
export APPROVED_MARKER="$temp/approved"
verify v1.2.3
GITHUB_EVENT_NAME=push verify v1.2.3
GITHUB_REF=refs/heads/feature reject verify v1.2.3
GITHUB_EVENT_NAME=pull_request reject verify v1.2.3
GITHUB_EVENT_NAME=workflow_run reject verify v1.2.3
# Automated releases verify before the tag exists; a missing tag is otherwise fatal.
TAG_EXISTS=0 reject verify v1.2.3
TAG_EXISTS=0 verify v1.2.3 --tag-may-be-absent
TAG_EXISTS=0 TAG_SHA=0000000000000000000000000000000000000000 verify v1.2.3 --tag-may-be-absent
TAG_SHA=0000000000000000000000000000000000000000 reject verify v1.2.3 --tag-may-be-absent
reject verify v1.2.3 --unknown-option
# Tag creation: create when absent, accept an identical retry, refuse a moved tag.
create_tag() { bash "$root/scripts/release/create-tag.sh" "$@"; }
TAG_EXISTS=0 create_tag v1.2.3 "$GITHUB_SHA"
test -e "$CREATED_MARKER"
rm "$CREATED_MARKER"
create_tag v1.2.3 "$GITHUB_SHA"
test ! -e "$CREATED_MARKER"
TAG_SHA=0000000000000000000000000000000000000000 reject create_tag v1.2.3 "$GITHUB_SHA"
reject create_tag v1.2.3-rc1 "$GITHUB_SHA"
reject create_tag v1.2.3 main
ACTOR_LOGIN=github-actions TAG_EXISTS=0 reject create_tag v1.2.3 "$GITHUB_SHA"
GITHUB_ACTIONS=true TAG_EXISTS=0 reject create_tag v1.2.3 "$GITHUB_SHA"
approve() { bash "$root/scripts/release/approve.sh" 55 "$@"; }
APPROVAL_BRANCH=other TAG_EXISTS=0 reject approve v1.2.3
BUILD_RESULT=failure TAG_EXISTS=0 reject approve v1.2.3
APPROVAL_ENV='' TAG_EXISTS=0 reject approve v1.2.3
TAG_EXISTS=0 reject approve v1.2.4
ACTOR_LOGIN=other TAG_EXISTS=0 reject approve v1.2.3
test ! -e "$CREATED_MARKER" && test ! -e "$APPROVED_MARKER"
TAG_EXISTS=0 approve v1.2.3
test -e "$CREATED_MARKER" && test -e "$APPROVED_MARKER"
reject verify v1.2.3-extra
TAG_SHA=0000000000000000000000000000000000000000 reject verify v1.2.3
MAIN_BASE=0000000000000000000000000000000000000000 reject verify v1.2.3
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
PUBLISHED_ASSETS="$temp/published"
export PUBLISHED_ASSETS
mkdir "$PUBLISHED_ASSETS"
cp "$temp/assets/"* "$PUBLISHED_ASSETS/"
publish() { bash "$root/scripts/security/publish-release-assets.sh" v1.2.3 "$temp/assets"; }
publish
# From Actions only the release workflow on main may publish.
GITHUB_ACTIONS=true reject publish
GITHUB_ACTIONS=true GITHUB_WORKFLOW_REF=example/lasa/.github/workflows/ci.yml@refs/heads/main reject publish
GITHUB_ACTIONS=true GITHUB_WORKFLOW_REF=example/lasa/.github/workflows/release.yml@refs/heads/feature reject publish
GITHUB_ACTIONS=true GITHUB_WORKFLOW_REF=example/lasa/.github/workflows/release.yml@refs/heads/main ACTOR_LOGIN=github-actions publish
ACTOR_LOGIN=other reject publish
ATTESTATION_RESULT=denied reject publish
printf '%s\n' 'different fixture bytes' > "$PUBLISHED_ASSETS/lasa_1.2.3_amd64.deb"
python3 "$root/scripts/security/verify-release-assets.py" --write "$PUBLISHED_ASSETS" 1.2.3
reject publish
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
echo 'PASS: main-only release source (push or dispatch), tag creation/immutability, Actions publisher restriction, exact commit and CI validation, artifact and SBOM rejection, immutable retry validation.'
