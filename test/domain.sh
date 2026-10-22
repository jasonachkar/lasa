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
headers=
method=GET
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --insecure|-k) echo 'TLS verification must not be disabled' >&2; exit 95;;
    --output) output=$2; shift 2;;
    --dump-header) headers=$2; shift 2;;
    --request) method=$2; shift 2;;
    --data-binary) jq -e '.[0] == {type:"CNAME",name:"lasa",data:"tester.github.io",ttl:600}' "${2#@}" >/dev/null; shift 2;;
    https://*|http://*) url=$1; shift;;
    --header|--write-out|--data-urlencode|--proto) shift 2;;
    *) shift;;
  esac
done
case "$url" in
  https://lasa.secureobs.com/)
    case "${MOCK_MODE:-new}" in
      repair|restore|cooldown|pending-health|health-delay)
        if [ ! -f "$MOCK_STATE/rebound" ]; then echo 'curl: (60) certificate verification failed' >&2; exit 60; fi;;
      proxy) echo 'curl: (56) CONNECT tunnel failed' >&2; exit 56;;
      caa|untrusted) echo 'curl: (60) certificate verification failed' >&2; exit 60;;
      delayed)
        if [ ! -f "$MOCK_STATE/tls-probed" ]; then touch "$MOCK_STATE/tls-probed"; echo 'curl: (60) certificate verification failed' >&2; exit 60; fi;;
    esac;;
  http://lasa.secureobs.com/)
    if [[ ${MOCK_MODE:-} == redirect && ! -f "$MOCK_STATE/redirect-probed" ]]; then
      touch "$MOCK_STATE/redirect-probed"
      printf 'HTTP/1.1 200 OK\r\n\r\n' > "$headers"
      printf 200
    else
      printf 'HTTP/1.1 301 Moved Permanently\r\nLocation: https://lasa.secureobs.com/\r\n\r\n' > "$headers"
      printf 301
    fi;;
  https://dns.google/resolve)
    case "${MOCK_MODE:-new}" in
      existing|repair|restore|cooldown|pending-health|health-delay|proxy|redirect) echo '{"Status":0,"Answer":[{"type":5,"data":"tester.github.io."}]}' ;;
      conflict) echo '{"Status":0,"Answer":[{"type":5,"data":"other.github.io."}]}' ;;
      dnsfail) echo '{"Status":2}' ;;
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
if [[ $1 == auth && $2 == status ]]; then exit 0; fi
[[ $* == *repos/tester/homebrew-lasa/pages* ]] || exit 97
case "$*" in
  *pages/health*)
    if [[ ${MOCK_MODE:-} == health-delay && ! -f "$MOCK_STATE/health-probed" ]]; then touch "$MOCK_STATE/health-probed"; echo '{}'
    elif [[ ${MOCK_MODE:-} == pending-health ]]; then echo '{}'
    elif [[ ${MOCK_MODE:-} == caa ]]; then
      echo '{"domain":{"dns_resolves":true,"is_valid":true,"is_https_eligible":false,"caa_error":"Fixture CAA policy excludes the issuer"}}'
    else echo '{"domain":{"dns_resolves":true,"is_valid":true,"is_https_eligible":true}}'; fi;;
  *certificate:.https_certificate*)
    case "${MOCK_MODE:-new}" in
      repair|restore|cooldown|pending-health|health-delay)
        if [ -f "$MOCK_STATE/rebound" ]; then echo '{"certificate":{"state":"approved"},"https_enforced":false}'; else echo '{"certificate":null,"https_enforced":false}'; fi;;
      delayed)
        if [ ! -f "$MOCK_STATE/polled" ]; then
          touch "$MOCK_STATE/polled"
          echo '{"certificate":{"state":"authorization_pending","description":"Waiting for DNS"},"https_enforced":false}'
        else echo '{"certificate":{"state":"approved"},"https_enforced":false}'; fi;;
      rejected) echo '{"certificate":{"state":"errored","description":"Certificate authority policy rejected issuance"},"https_enforced":false}';;
      caa) echo '{"certificate":null,"https_enforced":false}';;
      hidden) echo '{"certificate":null,"https_enforced":false}';;
      existing|redirect) echo '{"certificate":{"state":"approved"},"https_enforced":true}';;
      *) echo '{"certificate":{"state":"approved"},"https_enforced":false}';;
    esac;;
  *'cname //'* )
    case "${MOCK_MODE:-}" in existing|repair|restore|cooldown|pending-health|health-delay|proxy|redirect) echo lasa.secureobs.com;; *) echo '';; esac;;
  *--input*)
    for argument; do input=$argument; done
    jq -e '. == {cname:null}' "$input" >/dev/null
    touch "$MOCK_STATE/unbound";;
  *'cname=lasa.secureobs.com'*)
    if [ -f "$MOCK_STATE/unbound" ]; then
      if [[ ${MOCK_MODE:-} == restore && ! -f "$MOCK_STATE/restore-failed" ]]; then touch "$MOCK_STATE/restore-failed"; echo 'fixture transient restore failure' >&2; exit 1; fi
      touch "$MOCK_STATE/rebound"
    fi
    touch "$MOCK_STATE/pages-domain";;
  *'https_enforced=true'*) touch "$MOCK_STATE/https-enabled";;
  *) exit 96;;
esac
EOF
cat > "$temp/mock/sleep" <<'EOF'
#!/bin/sh
case "${MOCK_MODE:-}" in untrusted|cooldown|pending-health) exit 99;; esac
exit 0
EOF
chmod +x "$temp/mock/"*
run_domain() {
  PATH="$temp/mock:$PATH" GODADDY_API_KEY=fixture-key GODADDY_API_SECRET=fixture-secret LASA_HTTPS_REPAIR_STATE="$temp/repair-time" bash "$root/scripts/configure-domain.sh" tester/homebrew-lasa "$@"
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
# Repair a stalled certificate only after positive DNS health and a TLS error.
rm -f "$temp/unbound" "$temp/rebound" "$temp/repair-time"
MOCK_MODE=repair run_domain --repair-certificate > "$temp/repair" 2>&1
test -f "$temp/unbound"
test -f "$temp/rebound"
test -s "$temp/repair-time"
grep -q 'Restarting certificate provisioning once' "$temp/repair"
grep -q 'HTTP redirects to HTTPS' "$temp/repair"
# Repeated runs preserve recent issuance rather than restarting it each time.
rm -f "$temp/unbound" "$temp/rebound"
if MOCK_MODE=cooldown run_domain --repair-certificate > "$temp/cooldown" 2>&1; then exit 1; fi
test ! -e "$temp/unbound"
grep -q 'within the last hour' "$temp/cooldown"
# An interrupted/failed rebind restores the same domain through the EXIT trap.
rm -f "$temp/repair-time"
if MOCK_MODE=restore run_domain --repair-certificate > "$temp/restore" 2>&1; then exit 1; fi
test -f "$temp/rebound"
grep -q 'Restored the Pages domain' "$temp/restore"
# Unknown DNS health and local proxy errors must never clear a working binding.
rm -f "$temp/unbound" "$temp/rebound" "$temp/repair-time"
if MOCK_MODE=pending-health run_domain --repair-certificate > "$temp/pending" 2>&1; then exit 1; fi
test ! -e "$temp/unbound"
grep -q 'pending or not eligible' "$temp/pending"
if MOCK_MODE=proxy run_domain --repair-certificate > "$temp/proxy" 2>&1; then exit 1; fi
test ! -e "$temp/unbound"
grep -q 'connection/resolver/proxy problem' "$temp/proxy"
if MOCK_MODE=dnsfail run_domain > "$temp/dnsfail" 2>&1; then exit 1; fi
grep -q 'DNS lookup failed' "$temp/dnsfail"
# An accepted setting alone is insufficient: wait for the actual HTTP redirect.
MOCK_MODE=redirect run_domain > "$temp/redirect" 2>&1
grep -q 'HTTP still returns 200' "$temp/redirect"
grep -q 'HTTP redirects to HTTPS' "$temp/redirect"
# An initially empty asynchronous DNS response becomes usable without another run.
rm -f "$temp/unbound" "$temp/rebound" "$temp/repair-time"
MOCK_MODE=health-delay run_domain --repair-certificate > "$temp/health-delay" 2>&1
test -f "$temp/rebound"
grep -q 'asynchronous result' "$temp/health-delay"
# The owner-local wrapper supplies persistent cooldown state without signing keys.
rm -f "$temp/unbound" "$temp/rebound"
# Keep the wrapper state isolated on both Linux and macOS CI.
printf '#!/bin/sh\necho Linux\n' > "$temp/mock/uname"
chmod +x "$temp/mock/uname"
PATH="$temp/mock:$PATH" XDG_STATE_HOME="$temp/wrapper-state" MOCK_MODE=repair bash "$root/scripts/repair-docs-https.sh" tester/homebrew-lasa > "$temp/wrapper" 2>&1
rm "$temp/mock/uname"
test -s "$temp/wrapper-state/lasa-distribution/tester_homebrew-lasa.certificate-repair"
grep -q 'HTTP redirects to HTTPS' "$temp/wrapper"
# Healthy HTTPS never reprovisions, even when repair mode was requested.
rm -f "$temp/unbound" "$temp/rebound"
MOCK_MODE=existing run_domain --repair-certificate > "$temp/healthy" 2>&1
test ! -e "$temp/unbound"
grep -q 'no reprovisioning is needed' "$temp/healthy"
echo 'PASS: GoDaddy/Pages reuse, TLS and redirect verification, stalled-certificate repair, cooldown, rebind recovery, DNS failures and secret-safe errors (external APIs mocked)'
