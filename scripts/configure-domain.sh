#!/usr/bin/env bash
# macOS Bash 3.2 compatible. DNS credentials are used locally and not persisted.
set -euo pipefail
umask 077
distribution=${1:?Usage: configure-domain.sh OWNER/DISTRIBUTION-REPO [--repair-certificate]}
repair=false
if [ "${2:-}" = --repair-certificate ]; then repair=true; fi
[[ $# -eq 1 || ($# -eq 2 && $repair == true) ]] || { echo 'Unexpected domain setup argument' >&2; exit 1; }
domain=lasa.secureobs.com
trap 'printf "Domain setup failed for %s at line %s; see the preceding network/API error.\n" "$domain" "$LINENO" >&2' ERR
target="$(printf '%s' "${distribution%/*}" | tr '[:upper:]' '[:lower:]').github.io"
[[ $distribution =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || exit 1
for tool in gh jq curl; do command -v "$tool" >/dev/null || { echo "Missing domain setup tool: $tool" >&2; exit 1; }; done
temp=$(mktemp -d)
rebinding=false
reprovisioned=false
repair_pending_file=
# Restore this same domain if certificate reprovisioning is interrupted.
# shellcheck disable=SC2317
cleanup() {
  if $rebinding; then
    if gh api --method PUT "repos/$distribution/pages" -f "cname=$domain" >/dev/null; then
      echo "Restored the Pages domain after interrupted certificate repair: $domain" >&2
    else
      echo "Could not restore $domain after interrupted repair. Rerun the HTTPS repair command with working GitHub access." >&2
    fi
  fi
  if [ -n "$repair_pending_file" ]; then rm -f "$repair_pending_file"; fi
  rm -rf "$temp"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
fail() { printf '%s\n' "$*" >&2; exit 1; }
# Skip the registrar API if the right public CNAME is already configured.
curl --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 -fsS --get 'https://dns.google/resolve' --data-urlencode "name=$domain" --data-urlencode type=CNAME > "$temp/dns.json"
jq -e '.Status == 0' "$temp/dns.json" >/dev/null || fail 'The public DNS lookup failed. No registrar records were changed; check DNS/DNSSEC and retry.'
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

# Removing and restoring the same custom domain is GitHub's supported way to
# restart stalled issuance. Only do this in repair mode, with positive DNS health,
# a genuine TLS provisioning error and HTTPS enforcement still disabled.
if $repair && [ -n "$pages_domain" ]; then
  if curl --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 10 --silent --show-error --head --output /dev/null "https://$domain/" 2> "$temp/tls-error"; then
    echo 'The current HTTPS certificate already verifies; no reprovisioning is needed.'
  else
    tls_status=$?
    case "$tls_status" in
      35|51|60) ;;
      *) cat "$temp/tls-error" >&2; fail "The HTTPS probe failed with curl code $tls_status, indicating a connection/resolver/proxy problem. The domain was not reset.";;
    esac
    snapshot=$(gh api "repos/$distribution/pages" --jq '{certificate:.https_certificate,https_enforced:.https_enforced}')
    state=$(jq -r '.certificate.state // "pending"' <<< "$snapshot")
    enforced=$(jq -r '.https_enforced' <<< "$snapshot")
    if [[ $enforced == false && $state != approved ]]; then
      for ((health_attempt=0; health_attempt<12; health_attempt++)); do
        gh api "repos/$distribution/pages/health" > "$temp/health.json"
        if jq -e '.domain | type == "object"' "$temp/health.json" >/dev/null; then break; fi
        echo 'GitHub DNS health is pending or not eligible for a reset yet; waiting for its asynchronous result.'
        if (( health_attempt < 11 )); then sleep 5; fi
      done
      caa_error=$(jq -r '.domain.caa_error // empty' "$temp/health.json")
      [ -z "$caa_error" ] || fail "GitHub reports a CAA policy error for $domain: $caa_error. Existing DNS security policies were not changed."
      if jq -e '.domain | .dns_resolves == true and .is_valid == true and .is_https_eligible == true' "$temp/health.json" >/dev/null; then
        : "${LASA_HTTPS_REPAIR_STATE:?Use scripts/repair-docs-https.sh so certificate repairs have a cooldown record}"
        now=$(date +%s)
        last=0
        if [ -f "$LASA_HTTPS_REPAIR_STATE" ]; then
          last=$(cat "$LASA_HTTPS_REPAIR_STATE")
          [[ $last =~ ^(0|[1-9][0-9]{0,9})$ ]] || fail "Invalid certificate repair timestamp: $LASA_HTTPS_REPAIR_STATE"
        fi
        (( last <= now )) || fail "The certificate repair timestamp is in the future. Check this machine's clock: $LASA_HTTPS_REPAIR_STATE"
        if (( now - last < 3600 )); then
          echo 'A certificate refresh was requested within the last hour. Preserving that request and waiting for issuance.'
        else
          # Save before writing Pages settings so reruns after interruption do not
          # repeatedly reset issuance. Rebinding on the next run also repairs an
          # interrupted process that could not execute its EXIT trap.
          mkdir -p "$(dirname "$LASA_HTTPS_REPAIR_STATE")"
          repair_pending_file="$LASA_HTTPS_REPAIR_STATE.tmp.$$"
          printf '%s\n' "$now" > "$repair_pending_file"
          mv "$repair_pending_file" "$LASA_HTTPS_REPAIR_STATE"
          repair_pending_file=
          printf '{"cname":null}\n' > "$temp/clear-domain.json"
          echo "Restarting certificate provisioning once for $domain in $distribution."
          rebinding=true
          gh api --method PUT "repos/$distribution/pages" --input "$temp/clear-domain.json" >/dev/null
          gh api --method PUT "repos/$distribution/pages" -f "cname=$domain" >/dev/null
          rebinding=false
          reprovisioned=true
        fi
      else
        echo 'GitHub DNS health is pending or not eligible; the existing domain binding was preserved.'
        jq -c '.domain // {}' "$temp/health.json"
      fi
    else
      echo 'GitHub already reports an approved certificate or enforced HTTPS. Preserving its binding and checking delivery.'
    fi
  fi
fi

verify_http_redirect() {
  local status location
  if ! status=$(curl --proto '=http' --connect-timeout 5 --max-time 10 --silent --show-error --head --dump-header "$temp/http-headers" --output /dev/null --write-out '%{http_code}' "http://$domain/"); then
    http_details='HTTP redirect probe could not connect; see the curl error above.'
    return 1
  fi
  location=$(awk 'tolower($1)=="location:" {sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit}' "$temp/http-headers")
  http_details="HTTP $status, Location: ${location:-missing}"
  case "$status" in 301|302|303|307|308) ;; *) echo "HTTP still returns $status rather than redirecting to HTTPS."; return 1;; esac
  [[ $location == "https://$domain/"* ]] || { echo "Unexpected HTTP redirect destination: $location"; return 1; }
}
echo "DNS record configured: $domain -> $target. Waiting for GitHub's HTTPS certificate."
wait_started=$SECONDS
previous_state=
dns_details='No DNS health result is available yet.'
tls_details='Not checked yet.'
http_details='Not checked yet.'
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
      if $reprovisioned && (( attempt < 4 )); then
        echo 'Waiting for the previous certificate error to be replaced after reprovisioning.'
      else
        fail "GitHub certificate issuance failed ($state): $details"
      fi;;
  esac
  # Certificate metadata is optional in GitHub's API. A verified TLS handshake
  # also proves readiness; never wait indefinitely just because that field is null.
  if [[ $state == approved ]] || (( attempt % 4 == 0 )); then
    if curl --proto '=https' --tlsv1.2 --connect-timeout 5 --max-time 10 --silent --show-error --head --output /dev/null "https://$domain/" 2> "$temp/tls-error"; then
      tls_details='Hostname and CA verification succeeded.'
      if [[ $(jq -r '.https_enforced' <<< "$certificate") == true ]]; then
        if verify_http_redirect; then
          echo "HTTPS is already enabled and its certificate verifies for https://$domain; HTTP redirects to HTTPS."
          exit 0
        fi
      elif gh api --method PUT "repos/$distribution/pages" -F https_enforced=true > /dev/null 2> "$temp/enforce-error"; then
        if verify_http_redirect; then
          echo "HTTPS enabled and its certificate verified for https://$domain; HTTP redirects to HTTPS."
          exit 0
        fi
      elif grep -q 'HTTP 422' "$temp/enforce-error"; then
        printf 'TLS verifies, but GitHub is not yet allowing HTTPS enforcement: %s\n' "$(cat "$temp/enforce-error")"
      else
        cat "$temp/enforce-error" >&2
        fail 'GitHub rejected HTTPS enforcement; the existing domain and keys were preserved.'
      fi
    else
      tls_details=$(cat "$temp/tls-error")
      printf 'HTTPS certificate is not ready from this machine: %s\n' "$tls_details"
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
fail "DNS/Pages are configured, but verified HTTPS and its HTTP redirect did not become ready within 30 minutes (certificate state: $state). Last DNS health: $dns_details. Last TLS check: $tls_details. Last redirect check: $http_details. No TLS verification was bypassed."
