#!/usr/bin/env bash
# Owner-only bootstrap. Never replace a published Alpine trust key automatically.
set -euo pipefail
umask 077
state=${1:?Usage: prepare-apk-key.sh PRIVATE_STATE OWNER/REPO}
repository=${2:?Missing source repository}
mkdir -p "$state"
chmod 0700 "$state"
key="$state/apk-signing-key.pem"
public="$state/apk-signing-key.rsa.pub"
names=$(gh secret list --repo "$repository" --env release --json name --jq '.[].name')
repository_names=$(gh secret list --repo "$repository" --json name --jq '.[].name')
if [ ! -s "$key" ]; then
  if printf '%s\n%s\n' "$names" "$repository_names" | grep -qx APK_SIGNING_KEY; then
    echo "APK_SIGNING_KEY already exists remotely; restore $key from backup. No trust key was regenerated." >&2
    exit 1
  fi
  temp=$(mktemp -d "$state/apk-key.XXXXXX")
  trap 'rm -rf "$temp"' EXIT
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$temp/private.pem" 2> "$temp/generation.log" || { cat "$temp/generation.log" >&2; exit 1; }
  mv "$temp/private.pem" "$key"
fi
chmod 0600 "$key"
openssl pkey -in "$key" -check -noout >/dev/null
openssl pkey -in "$key" -pubout -out "$public.new"
if [ -s "$public" ] && ! cmp -s "$public" "$public.new"; then
  rm -f "$public.new"
  echo 'Saved Alpine public/private keys disagree. Restore the matching state; nothing was rotated.' >&2
  exit 1
fi
mv "$public.new" "$public"
digest=$(openssl dgst -sha256 "$public" | awk '{print $NF}')
if [ -s "$state/apk-public-key.sha256" ] && [ "$(cat "$state/apk-public-key.sha256")" != "$digest" ]; then
  echo 'Saved Alpine public-key pin disagrees with the key. Restore the original state.' >&2
  exit 1
fi
printf '%s\n' "$digest" > "$state/apk-public-key.sha256"
gh secret set APK_SIGNING_KEY --repo "$repository" --env release < "$key"
gh variable set APK_PUBLIC_KEY_SHA256 --repo "$repository" --body "$digest"
printf 'Alpine public-key SHA-256: %s\n' "$digest"
