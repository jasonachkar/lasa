#!/usr/bin/env bash
# Run on Linux and macOS Bash 3.2. Real fixture GPG keys and mocked GitHub.
set -euo pipefail
base=$(cd "$(dirname "$0")/.." && pwd)
temp=$(mktemp -d)
cleanup() {
  rm -rf "$temp"
}
trap cleanup EXIT
mkdir -p "$temp/source/scripts" "$temp/source/.github/workflows" "$temp/mock" "$temp/home" "$temp/state"
cp "$base/scripts/bootstrap-distribution.sh" "$temp/source/scripts/"
cat > "$temp/source/scripts/configure-domain.sh" <<'EOF'
#!/bin/sh
touch "$MOCK_STATE/domain-configured"
EOF
cp "$base/.github/workflows/release.yml" "$temp/source/.github/workflows/"
printf 'VERSION := 0.1.0\n' > "$temp/source/Makefile"
git -C "$temp/source" init -q
git -C "$temp/source" add .
git -C "$temp/source" -c user.name=Test -c user.email=test@example.invalid commit -qm fixture
export MOCK_STATE="$temp/state"
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
  'variable list') if [ -f "$MOCK_STATE/variable-APT_SIGNING_FINGERPRINT" ]; then cat "$MOCK_STATE/variable-APT_SIGNING_FINGERPRINT"; fi; exit 0;;
  'variable set') printf '%s\n' "$7" > "$MOCK_STATE/variable-$3"; exit 0;;
esac
[[ $1 == api ]] || { echo "Unexpected mock gh command: $1 $2" >&2; exit 90; }
shift
method=GET
path=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --method) method=$2; shift 2;;
    --jq) shift 2;;
    --paginate) shift;;
    -f|-F) shift 2;;
    *) path=$1; shift;;
  esac
done
case "$method $path" in
  'GET repos/tester/lasa') echo tester/lasa;;
  'GET repos/tester/homebrew-lasa')
    # Query differentiates these two calls in the real script. Alternate their
    # expected results per invocation; no API output includes private material.
    if [ -f "$MOCK_STATE/visibility-read" ]; then rm "$MOCK_STATE/visibility-read"; echo main; else touch "$MOCK_STATE/visibility-read"; echo public; fi;;
  'GET repos/tester/homebrew-lasa/pages')
    if [ -f "$MOCK_STATE/pages" ]; then echo 'legacy main /'; else echo 'gh: Not Found (HTTP 404)' >&2; exit 1; fi;;
  'POST repos/tester/homebrew-lasa/pages') touch "$MOCK_STATE/pages";;
  *) echo "Unexpected mock API request: $method $path" >&2; exit 91;;
esac
EOF
# Suppress interactive pinentry for the throwaway test key.
MOCK_GPG=$(command -v gpg)
export MOCK_GPG
cat > "$temp/mock/gpg" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1-} == --quick-generate-key ]]; then
  exec "$MOCK_GPG" --batch --pinentry-mode loopback --passphrase '' "$@"
fi
exec "$MOCK_GPG" "$@"
EOF
chmod +x "$temp/mock/"*
run_bootstrap() {
  HOME="$temp/home" PATH="$temp/mock:$PATH" bash "$temp/source/scripts/bootstrap-distribution.sh" --repo tester/lasa "$@"
}
run_bootstrap --configure-only
state="$temp/home/Library/Application Support/lasa-distribution/tester_lasa"
fingerprint=$(cat "$state/signing-fingerprint")
[[ ${#fingerprint} -eq 40 ]]
test ! -e "$state/deploy-key"
for name in APT_SIGNING_FINGERPRINT DISTRIBUTION_REPOSITORY DISTRIBUTION_BRANCH APT_REPOSITORY_URL DOCS_SITE_URL; do test -f "$MOCK_STATE/variable-$name"; done
run_bootstrap --configure-only
[[ $(cat "$state/signing-fingerprint") == "$fingerprint" ]]
[[ $(cat "$MOCK_STATE/variable-APT_SIGNING_FINGERPRINT") == "$fingerprint" ]]
# A different remote pin may require restoring the key already trusted by users.
different=0000000000000000000000000000000000000000
printf '%s\n' "$different" > "$MOCK_STATE/variable-APT_SIGNING_FINGERPRINT"
if run_bootstrap --configure-only > "$temp/rejection" 2>&1; then exit 1; fi
grep -q 'fingerprints differ' "$temp/rejection"
[[ $(cat "$MOCK_STATE/variable-APT_SIGNING_FINGERPRINT") == "$different" ]]
[[ $(cat "$state/signing-fingerprint") == "$fingerprint" ]]
printf '%s\n' "$fingerprint" > "$MOCK_STATE/variable-APT_SIGNING_FINGERPRINT"
run_bootstrap
[[ ! -f "$MOCK_STATE/domain-configured" ]]
run_bootstrap --configure-domain
test -f "$MOCK_STATE/domain-configured"
# Missing local identities must never cause a silent remote key replacement.
mv "$state/signing-fingerprint" "$temp/saved-fingerprint"
if run_bootstrap --configure-only > "$temp/rejection" 2>&1; then exit 1; fi
grep -q 'Restore the original state' "$temp/rejection"
mv "$temp/saved-fingerprint" "$state/signing-fingerprint"
printf '\nchange\n' >> "$temp/source/Makefile"
if run_bootstrap --configure-only > "$temp/rejection" 2>&1; then exit 1; fi
grep -q 'uncommitted changes' "$temp/rejection"
echo 'PASS: owner publishing bootstrap, no remote credential writes, stable local signing identity, conflicting pins, missing state and dirty checkout'
