#!/usr/bin/env bash
# Run on Linux and macOS Bash 3.2. Real GPG/SSH keys; mocked GitHub boundary.
set -euo pipefail
base=$(cd "$(dirname "$0")/.." && pwd)
temp=$(mktemp -d)
cleanup() {
  rm -rf "$temp"
}
trap cleanup EXIT
mkdir -p "$temp/source/scripts" "$temp/source/.github/workflows" "$temp/mock" "$temp/home" "$temp/state"
cp "$base/scripts/bootstrap-distribution.sh" "$temp/source/scripts/"
cp "$base/scripts/next-version.sh" "$temp/source/scripts/"
cat > "$temp/source/scripts/configure-domain.sh" <<'EOF'
#!/bin/sh
touch "$MOCK_STATE/domain-configured"
EOF
cp "$base/.github/workflows/release.yml" "$temp/source/.github/workflows/"
printf 'VERSION := 0.1.0\n' > "$temp/source/Makefile"
git -C "$temp/source" init -q
git -C "$temp/source" add .
git -C "$temp/source" -c user.name=Test -c user.email=test@example.invalid commit -qm fixture
MOCK_COMMIT=$(git -C "$temp/source" rev-parse HEAD)
export MOCK_COMMIT
export MOCK_STATE="$temp/state"
REAL_GIT=$(command -v git)
export REAL_GIT
cat > "$temp/mock/git" <<'EOF'
#!/usr/bin/env bash
for argument in "$@"; do
  if [[ $argument == fetch ]]; then
    [[ $* == *https://github.com/tester/lasa.git* ]] || exit 92
    if [ -f "$MOCK_STATE/tag" ]; then "$REAL_GIT" tag -f v0.1.0 "$MOCK_COMMIT" >/dev/null; fi
    exit
  fi
done
exec "$REAL_GIT" "$@"
EOF
cat > "$temp/mock/uname" <<'EOF'
#!/bin/sh
echo Darwin
EOF
cat > "$temp/mock/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "$1 $2" in
  'auth status') exit 0;;
  'repo list') if [ -f "$MOCK_STATE/repo" ]; then echo tester/homebrew-lasa; fi; exit 0;;
  'repo create') [[ $* == *--public* ]]; touch "$MOCK_STATE/repo"; exit 0;;
  'secret list') for file in "$MOCK_STATE"/secret-*; do [ ! -f "$file" ] || printf '%s\n' "${file##*/secret-}"; done; exit 0;;
  'secret set') cat >/dev/null; touch "$MOCK_STATE/secret-$3"; exit 0;;
  'variable set') touch "$MOCK_STATE/variable-$3"; exit 0;;
  'run list') echo 123; exit 0;;
  'run view') if [ -f "$MOCK_STATE/failed-run" ]; then echo failure; else echo success; fi; exit 0;;
  'run rerun') touch "$MOCK_STATE/rerun"; rm -f "$MOCK_STATE/failed-run"; exit 0;;
  'run watch') touch "$MOCK_STATE/watched"; exit 0;;
esac
[[ $1 == api ]] || { echo "Unexpected mock gh command: $1 $2" >&2; exit 90; }
shift
method=GET
path=
key=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --method) method=$2; shift 2;;
    --jq) shift 2;;
    --paginate) shift;;
    -f|-F) case "$2" in key=*) key=${2#key=};; esac; shift 2;;
    *) path=$1; shift;;
  esac
done
case "$method $path" in
  'GET repos/tester/lasa') echo tester/lasa;;
  'GET repos/tester/lasa/environments/release') :;;
  'GET repos/tester/lasa/commits/'*) echo "$MOCK_COMMIT";;
  'GET repos/tester/lasa/contents/'*) echo file;;
  'GET repos/tester/lasa/git/matching-refs/'*) if [ -f "$MOCK_STATE/tag" ]; then echo "$MOCK_COMMIT"; fi;;
  'POST repos/tester/lasa/git/refs') touch "$MOCK_STATE/tag";;
  'GET repos/tester/homebrew-lasa')
    # Query differentiates these two calls in the real script. Alternate their
    # expected results per invocation; no API output includes private material.
    if [ -f "$MOCK_STATE/visibility-read" ]; then rm "$MOCK_STATE/visibility-read"; echo main; else touch "$MOCK_STATE/visibility-read"; echo public; fi;;
  'GET repos/tester/homebrew-lasa/keys') if [ -f "$MOCK_STATE/public-key" ]; then cat "$MOCK_STATE/public-key"; fi;;
  'POST repos/tester/homebrew-lasa/keys') printf '%s\n' "$key" > "$MOCK_STATE/public-key";;
  'GET repos/tester/homebrew-lasa/pages')
    if [ -f "$MOCK_STATE/pages" ]; then echo 'legacy main /'; else echo 'gh: Not Found (HTTP 404)' >&2; exit 1; fi;;
  'POST repos/tester/homebrew-lasa/pages') touch "$MOCK_STATE/pages";;
  *) echo "Unexpected mock API request: $method $path" >&2; exit 91;;
esac
EOF
chmod +x "$temp/mock/"*
run_bootstrap() {
  HOME="$temp/home" PATH="$temp/mock:$PATH" bash "$temp/source/scripts/bootstrap-distribution.sh" --repo tester/lasa "$@"
}
run_bootstrap --configure-only
state="$temp/home/Library/Application Support/lasa-distribution/tester_lasa"
fingerprint=$(cat "$state/signing-fingerprint")
deploy=$(cat "$MOCK_STATE/public-key")
[[ ${#fingerprint} -eq 40 ]]
test -s "$state/deploy-key"
for name in APT_SIGNING_KEY DISTRIBUTION_DEPLOY_KEY; do test -f "$MOCK_STATE/secret-$name"; done
for name in APT_SIGNING_FINGERPRINT DISTRIBUTION_REPOSITORY DISTRIBUTION_BRANCH APT_REPOSITORY_URL DOCS_SITE_URL; do test -f "$MOCK_STATE/variable-$name"; done
run_bootstrap --configure-only
[[ $(cat "$state/signing-fingerprint") == "$fingerprint" ]]
[[ $(cat "$MOCK_STATE/public-key") == "$deploy" ]]
run_bootstrap
test -f "$MOCK_STATE/tag"
test -f "$MOCK_STATE/domain-configured"
test -f "$MOCK_STATE/watched"
touch "$MOCK_STATE/failed-run"
run_bootstrap
test -f "$MOCK_STATE/rerun"
# Missing local identities must never cause a silent remote key replacement.
mv "$state/signing-fingerprint" "$temp/saved-fingerprint"
if run_bootstrap --configure-only > "$temp/rejection" 2>&1; then exit 1; fi
grep -q 'automatic key rotation would break' "$temp/rejection"
mv "$temp/saved-fingerprint" "$state/signing-fingerprint"
printf '\nchange\n' >> "$temp/source/Makefile"
if run_bootstrap --configure-only > "$temp/rejection" 2>&1; then exit 1; fi
grep -q 'uncommitted changes' "$temp/rejection"
echo 'PASS: macOS bootstrap provisioning, tag/run orchestration and failed-run retries, repeat setup, stable real keys, missing-state and dirty-checkout rejection (external APIs mocked)'
