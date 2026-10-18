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
    --output) output=$2; shift 2;;
    --request) method=$2; shift 2;;
    --data-binary) jq -e '.[0] == {type:"CNAME",name:"lasa",data:"tester.github.io",ttl:600}' "${2#@}" >/dev/null; shift 2;;
    https://*) url=$1; shift;;
    --header|--write-out|--data-urlencode|--proto) shift 2;;
    *) shift;;
  esac
done
case "$url" in
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
  *https_certificate.state*) echo approved;;
  *'cname //'* ) echo '';;
  *'cname=lasa.secureobs.com'*) touch "$MOCK_STATE/pages-domain";;
  *'https_enforced=true'*) touch "$MOCK_STATE/https-enabled";;
  *) exit 96;;
esac
EOF
chmod +x "$temp/mock/"*
run_domain() {
  PATH="$temp/mock:$PATH" GODADDY_API_KEY=fixture-key GODADDY_API_SECRET=fixture-secret bash "$root/scripts/configure-domain.sh" tester/homebrew-lasa
}
run_domain
test -f "$temp/dns-created"
test -f "$temp/pages-domain"
test -f "$temp/https-enabled"
MOCK_MODE=existing run_domain
if MOCK_MODE=conflict run_domain > "$temp/error" 2>&1; then exit 1; fi
grep -q 'Refusing to overwrite' "$temp/error"
if MOCK_MODE=denied run_domain > "$temp/error" 2>&1; then exit 1; fi
grep -q 'HTTP 403' "$temp/error"
if grep -q 'fixture-secret' "$temp/error"; then echo 'Secret leaked into output' >&2; exit 1; fi
echo 'PASS: GoDaddy DNS creation, existing CNAME reuse, HTTPS enforcement, conflict and account-denial handling (external APIs mocked)'
