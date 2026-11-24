#!/usr/bin/env bash
set -euo pipefail
exec python3 "$(dirname "$0")/repository-settings.py" verify "$@"
