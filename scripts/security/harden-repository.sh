#!/usr/bin/env bash
# Use the existing gh login. Without --apply this prints the proposed API writes.
set -euo pipefail
exec python3 "$(dirname "$0")/repository-settings.py" harden "$@"
