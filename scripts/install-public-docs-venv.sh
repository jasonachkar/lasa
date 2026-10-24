#!/usr/bin/env bash
# Public build dependencies only; publishing credentials never enter this tree.
set -euo pipefail
[[ $# = 2 ]] || { echo 'Usage: install-public-docs-venv.sh NEW_DIRECTORY REQUIREMENTS_FILE' >&2; exit 1; }
destination=$1
requirements=$2
if [ -e "$destination" ] || [ -L "$destination" ]; then
  echo 'The public documentation environment already exists; use a fresh publisher VM. No existing directory was changed.' >&2
  exit 1
fi
test -f "$requirements" || { echo 'Documentation requirements file is missing.' >&2; exit 1; }
# Root prepares these shared dependencies; the ubuntu user must be able to
# traverse/import them. This child process leaves the caller's private umask intact.
umask 022
python3 -m venv "$destination"
"$destination/bin/python3" -m pip install --disable-pip-version-check -r "$requirements"
