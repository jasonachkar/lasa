#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
mkdir "$temp/mock"
export MOCK_STATE="$temp"
cat > "$temp/mock/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=
method=GET
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --insecure|-k) echo 'TLS verification must not be disabled' >&2; exit 95;;
    --output) output=$2; shift 2;;
    --request) method=$2; shift 2;;
    --data-binary) jq -e '.[0] == {type:"CNAME",name:"lasa",data:"tester.github.io",ttl:600}' "${2#@}" >/dev/null; shift 2;;
    https://*) url=$1; shift;;
    --header|--write-out|--data-urlencode|--proto) shift 2;;
    *) shift;;
  esac
done
case "$url" in
  https://lasa.secureobs.com/)
    case "${MOCK_MODE:-new}" in
      caa|untrusted) echo 'curl: (60) certificate verification failed' >&2; exit 60;;
      delayed)
        if [ ! -f "$MOCK_STATE/tls-probed" ]; then touch "$MOCK_STATE/tls-probed"; echo 'curl: (60) certificate verification failed' >&2; exit 60; fi;;
    esac;;
  https://dns.google/resolve)
    case "${MOCK_MODE:-new}" in
      existing) echo '{"Answer":[{"type":5,"data":"tester.github.io."}]}' ;;
      conflict) echo '{"Answer":[{"type":5,"data":"other.github.io."}]}' ;;
      *) echo '{"Status":0}' ;;
    esac;;
  https://api.godaddy.com/v1/domains/secureobs.com/records*)
    if [[ ${MOCK_MODE:-} == denied ]]; then echo '{"message":"ACCESS_DENIED"}' > "$output"; printf 403; exit; fi
    if [[ $method == GET ]]; then echo '[]' > "$output"; else touch "$MOCK_STATE/dns-created"; echo '{}' > "$output"; fi
    printf 200;;
  *) exit 98;;
esac
EOF
cat > "$temp/mock/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $* == *repos/tester/homebrew-lasa/pages* ]] || exit 97
case "$*" in
  *pages/health*)
    if [[ ${MOCK_MODE:-} == caa ]]; then
      echo '{"domain":{"dns_resolves":true,"is_valid":true,"is_https_eligible":false,"caa_error":"Fixture CAA policy excludes the issuer"}}'
    else echo '{"domain":{"dns_resolves":true,"is_valid":true,"is_https_eligible":true}}'; fi;;
  *certificate:.https_certificate*)
    case "${MOCK_MODE:-new}" in
      delayed)
        if [ ! -f "$MOCK_STATE/polled" ]; then
          touch "$MOCK_STATE/polled"
          echo '{"certificate":{"state":"authorization_pending","description":"Waiting for DNS"},"https_enforced":false}'
        else echo '{"certificate":{"state":"approved"},"https_enforced":false}'; fi;;
      rejected) echo '{"certificate":{"state":"errored","description":"Certificate authority policy rejected issuance"},"https_enforced":false}';;
      caa) echo '{"certificate":null,"https_enforced":false}';;
      hidden) echo '{"certificate":null,"https_enforced":false}';;
      existing) echo '{"certificate":{"state":"approved"},"https_enforced":true}';;
      *) echo '{"certificate":{"state":"approved"},"https_enforced":false}';;
    esac;;
  *'cname //'* ) if [[ ${MOCK_MODE:-} == existing ]]; then echo lasa.secureobs.com; else echo ''; fi;;
  *'cname=lasa.secureobs.com'*) touch "$MOCK_STATE/pages-domain";;
  *'https_enforced=true'*) touch "$MOCK_STATE/https-enabled";;
  *) exit 96;;
esac
EOF
cat > "$temp/mock/sleep" <<'EOF'
#!/bin/sh
if [ "${MOCK_MODE:-}" = untrusted ]; then exit 99; fi
exit 0
EOF
chmod +x "$temp/mock/"*
run_domain() {
  PATH="$temp/mock:$PATH" GODADDY_API_KEY=fixture-key GODADDY_API_SECRET=fixture-secret bash "$root/scripts/configure-domain.sh" tester/homebrew-lasa
}
run_domain
test -f "$temp/dns-created"
test -f "$temp/pages-domain"
test -f "$temp/https-enabled"
rm "$temp/pages-domain" "$temp/https-enabled"
MOCK_MODE=existing run_domain
test ! -e "$temp/pages-domain"
test ! -e "$temp/https-enabled"
MOCK_MODE=delayed run_domain > "$temp/progress" 2>&1
grep -q 'Certificate status: authorization_pending' "$temp/progress"
grep -q 'Certificate status: approved' "$temp/progress"
grep -q 'GitHub DNS health: resolves=true' "$temp/progress"
# Missing optional API metadata must not block a verified certificate.
MOCK_MODE=hidden run_domain > "$temp/hidden" 2>&1
grep -q 'HTTPS enabled and its certificate verified' "$temp/hidden"
rm -f "$temp/https-enabled"
if MOCK_MODE=untrusted run_domain > "$temp/error" 2>&1; then exit 1; fi
grep -q 'certificate verification failed' "$temp/error"
test ! -e "$temp/https-enabled"
if MOCK_MODE=rejected run_domain > "$temp/error" 2>&1; then exit 1; fi
grep -q 'Certificate authority policy rejected issuance' "$temp/error"
if MOCK_MODE=caa run_domain > "$temp/error" 2>&1; then exit 1; fi
grep -q 'Fixture CAA policy excludes the issuer' "$temp/error"
if MOCK_MODE=conflict run_domain > "$temp/error" 2>&1; then exit 1; fi
grep -q 'Refusing to overwrite' "$temp/error"
if MOCK_MODE=denied run_domain > "$temp/error" 2>&1; then exit 1; fi
grep -q 'HTTP 403' "$temp/error"
if grep -q 'fixture-secret' "$temp/error"; then echo 'Secret leaked into output' >&2; exit 1; fi
echo 'PASS: GoDaddy DNS creation, domain/HTTPS reuse, certificate progress and rejection details, conflicts and account denial (external APIs mocked)'
