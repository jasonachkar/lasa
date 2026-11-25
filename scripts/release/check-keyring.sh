#!/usr/bin/env bash
# Verify an armored APT keyring: exactly one primary key with the pinned
# fingerprint, and optionally a specific usable signing subkey.
# Usage: check-keyring.sh KEYRING.asc PRIMARY_FPR [SIGNING_SUBKEY_FPR]
set -euo pipefail
keyring=${1:?Usage: check-keyring.sh KEYRING.asc PRIMARY_FPR [SUBKEY_FPR]}
primary=${2:?Missing primary fingerprint}
subkey=${3:-}
[[ $primary =~ ^[A-F0-9]{40}$ ]] || { echo 'Primary fingerprint must be 40 uppercase hex characters' >&2; exit 1; }
[[ -z $subkey || $subkey =~ ^[A-F0-9]{40}$ ]] || { echo 'Subkey fingerprint must be 40 uppercase hex characters' >&2; exit 1; }
command -v gpg >/dev/null || { echo 'Missing dependency: gpg' >&2; exit 1; }
home=$(mktemp -d)
trap 'gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true; rm -rf "$home"' EXIT
listing=$(gpg --batch --homedir "$home" --with-colons --fixed-list-mode --show-keys "$keyring" 2>/dev/null)
primaries=$(awk -F: '$1=="pub"{p=1;next} p&&$1=="fpr"{print $10;p=0}' <<< "$listing")
[[ $primaries == "$primary" ]] || { echo "Keyring $keyring must contain exactly primary key $primary (found: ${primaries:-none})" >&2; exit 1; }
# Secret material must never be committed or packaged.
if grep -q 'PRIVATE KEY' "$keyring"; then echo "Keyring $keyring contains private key material" >&2; exit 1; fi
if [[ -n $subkey ]]; then
  # sub record fields: 2=validity, 12=capabilities; fpr follows its sub record.
  record=$(awk -F: '$1=="sub"{v=$2;c=$12;s=1;next} s&&$1=="fpr"{print $10":"v":"c;s=0}' <<< "$listing" | grep "^$subkey:" || true)
  [[ -n $record ]] || { echo "Keyring $keyring lacks signing subkey $subkey" >&2; exit 1; }
  IFS=: read -r _ validity capabilities <<< "$record"
  [[ $capabilities == *s* ]] || { echo "Subkey $subkey cannot sign" >&2; exit 1; }
  case $validity in r|e|i|n|d) echo "Subkey $subkey is not usable (validity $validity)" >&2; exit 1;; esac
fi
