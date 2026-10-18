#!/usr/bin/env bash
# macOS Bash 3.2 compatible. DNS credentials are used locally and not persisted.
set -euo pipefail
umask 077
distribution=${1:?Usage: configure-domain.sh OWNER/DISTRIBUTION-REPO}
domain=lasa.secureobs.com
trap 'printf "Domain setup failed for %s at line %s; see the preceding network/API error.\n" "$domain" "$LINENO" >&2' ERR
target="$(printf '%s' "${distribution%/*}" | tr '[:upper:]' '[:lower:]').github.io"
[[ $distribution =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || exit 1
for tool in gh jq curl; do command -v "$tool" >/dev/null || { echo "Missing domain setup tool: $tool" >&2; exit 1; }; done
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
fail() { printf '%s\n' "$*" >&2; exit 1; }
# Skip the registrar API if the right public CNAME is already configured.
curl --proto '=https' --tlsv1.2 -fsS --get 'https://dns.google/resolve' --data-urlencode "name=$domain" --data-urlencode type=CNAME > "$temp/dns.json"
current=$(jq -r '[.Answer[]? | select(.type==5) | .data | rtrimstr(".")] | unique | join(" ")' "$temp/dns.json")
if [[ $current != "$target" ]]; then
  if [ -n "$current" ]; then fail "$domain already points to $current. Refusing to overwrite an existing site automatically."; fi
  if [ -z "${GODADDY_API_KEY:-}" ] || [ -z "${GODADDY_API_SECRET:-}" ]; then
    [ -t 0 ] || fail 'GoDaddy DNS access is required. Supply GODADDY_API_KEY and GODADDY_API_SECRET securely in the local environment, or run from a terminal for masked prompts. Create production credentials at https://developer.godaddy.com/keys if your account has DNS API access.'
    echo 'GoDaddy production DNS API credentials are needed once. They will not be saved or uploaded.' >&2
    read -r -s -p 'GoDaddy API key: ' GODADDY_API_KEY; printf '\n' >&2
    read -r -s -p 'GoDaddy API secret: ' GODADDY_API_SECRET; printf '\n' >&2
  fi
  [[ -n $GODADDY_API_KEY && -n $GODADDY_API_SECRET ]] || fail 'Empty GoDaddy credentials'
  case "$GODADDY_API_KEY$GODADDY_API_SECRET" in *$'\r'*|*$'\n'*) fail 'Invalid newline in GoDaddy credentials';; esac
  # Headers are read from a private file, not exposed in curl's process arguments.
  printf 'Authorization: sso-key %s:%s\nContent-Type: application/json\n' "$GODADDY_API_KEY" "$GODADDY_API_SECRET" > "$temp/headers"
  unset GODADDY_API_KEY GODADDY_API_SECRET
  request() {
    local method=$1 path=$2
    shift 2
    local status
    status=$(curl --proto '=https' --tlsv1.2 --silent --show-error --header "@$temp/headers" --request "$method" "https://api.godaddy.com/v1/domains/secureobs.com$path" --output "$temp/response.json" --write-out '%{http_code}' "$@")
    case "$status" in
      2??) ;;
      *) jq -r '.message // .code // "GoDaddy API rejected the request"' "$temp/response.json" >&2 || true
         fail "GoDaddy DNS API returned HTTP $status. Verify production credentials, domain access and account DNS API eligibility. No unrelated records were changed.";;
    esac
  }
  request GET '/records?name=lasa&limit=500'
  records=$(jq -c '[.[] | select(.name=="lasa")]' "$temp/response.json")
  count=$(jq length <<< "$records")
  if [ "$count" -gt 0 ]; then
    matching=$(jq --arg target "$target" '[.[] | select(.type=="CNAME" and (.data | rtrimstr("."))==$target)] | length' <<< "$records")
    [[ $count == 1 && $matching == 1 ]] || fail 'GoDaddy already contains conflicting records for lasa.secureobs.com. They were not overwritten. Use a fresh hostname or resolve the existing site ownership first.'
  else
    jq -n --arg target "$target" '[{type:"CNAME",name:"lasa",data:$target,ttl:600}]' > "$temp/record.json"
    request PATCH /records --data-binary "@$temp/record.json"
  fi
  rm -f "$temp/headers"
fi
pages_domain=$(gh api "repos/$distribution/pages" --jq '.cname // ""')
[[ -z $pages_domain || $pages_domain == "$domain" ]] || fail "Pages already uses $pages_domain; it was not changed."
if [ -z "$pages_domain" ]; then
  gh api --method PUT "repos/$distribution/pages" -f "cname=$domain" >/dev/null
else
  echo "Reusing the existing Pages domain: $domain"
fi
echo "DNS record configured: $domain -> $target. Waiting for GitHub's HTTPS certificate."
wait_started=$SECONDS
previous_state=
dns_details='No DNS health result is available yet.'
for ((attempt=0; attempt<120; attempt++)); do
  certificate=$(gh api "repos/$distribution/pages" --jq '{certificate:.https_certificate,https_enforced:.https_enforced}')
  state=$(jq -r '.certificate.state // "pending"' <<< "$certificate")
  details=$(jq -r '.certificate.description // "GitHub has not provided a certificate description."' <<< "$certificate")
  if [[ $state != "$previous_state" ]] || (( attempt % 4 == 0 )); then
    printf 'Certificate status: %s (%s seconds elapsed; 30-minute polling window). %s\n' "$state" "$((SECONDS-wait_started))" "$details"
  fi
  previous_state=$state
  case "$state" in
    errored|bad_authz|authorization_revoked|certificate_revoked)
      fail "GitHub certificate issuance failed ($state): $details";;
  esac
  # Certificate metadata is optional in GitHub's API. A verified TLS handshake
  # also proves readiness; never wait indefinitely just because that field is null.
  if [[ $state == approved ]] || (( attempt % 4 == 0 )); then
    if curl --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 10 --silent --show-error --head --output /dev/null "https://$domain/" 2> "$temp/tls-error"; then
      if [[ $(jq -r '.https_enforced' <<< "$certificate") == true ]]; then
        echo "HTTPS is already enabled and its certificate verifies for https://$domain"
        exit 0
      fi
      if gh api --method PUT "repos/$distribution/pages" -F https_enforced=true > /dev/null 2> "$temp/enforce-error"; then
        echo "HTTPS enabled and its certificate verified for https://$domain"
        exit 0
      elif grep -q 'HTTP 422' "$temp/enforce-error"; then
        printf 'TLS verifies, but GitHub is not yet allowing HTTPS enforcement: %s\n' "$(cat "$temp/enforce-error")"
      else
        cat "$temp/enforce-error" >&2
        fail 'GitHub rejected HTTPS enforcement; the existing domain and keys were preserved.'
      fi
    else
      printf 'HTTPS certificate is not ready from this machine: %s\n' "$(cat "$temp/tls-error")"
    fi
  fi
  if (( attempt % 4 == 0 )); then
    if gh api "repos/$distribution/pages/health" > "$temp/health.json" 2> "$temp/health-error"; then
      if jq -e '.domain | type=="object"' "$temp/health.json" >/dev/null 2>&1; then
        dns_details=$(jq -r '.domain | "resolves=\(.dns_resolves), valid=\(.is_valid), HTTPS eligible=\(.is_https_eligible). \(.reason // "No DNS error reported.") \(.https_error // "")"' "$temp/health.json")
        printf 'GitHub DNS health: %s\n' "$dns_details"
        caa_error=$(jq -r '.domain.caa_error // empty' "$temp/health.json")
        [ -z "$caa_error" ] || fail "GitHub reports a CAA policy error for $domain: $caa_error. Existing DNS security policies were not changed."
      else
        echo 'GitHub DNS health check is still pending.'
      fi
    else
      printf 'GitHub DNS health check is unavailable: %s\n' "$(cat "$temp/health-error")" >&2
    fi
  fi
  sleep 15
done
fail "DNS/Pages are configured, but GitHub has not issued the HTTPS certificate within the 30-minute polling window (state: $state). Last DNS health: $dns_details. Rerun bootstrap after resolving the reported cause; no TLS verification was bypassed."
