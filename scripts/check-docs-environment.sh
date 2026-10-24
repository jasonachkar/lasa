#!/usr/bin/env bash
# Run as the ordinary publisher user before builds or credential loading.
set -euo pipefail
[[ $# = 1 ]] || { echo 'Usage: check-docs-environment.sh PREPARED_PYTHON3' >&2; exit 1; }
python_command=$1
if [ ! -x "$python_command" ]; then
  echo "Prepared documentation Python is missing or inaccessible: $python_command. Guest setup must make its public tool environment accessible to the publisher user." >&2
  exit 1
fi
if ! "$python_command" -c 'import sys; assert sys.prefix != sys.base_prefix, "a prepared virtual environment is required"; import mkdocs, mike, yaml'; then
  echo 'The prepared documentation Python cannot import MkDocs, Mike or PyYAML; check the guest setup output and public tool permissions.' >&2
  exit 1
fi
binary_directory=$(dirname "$python_command")
for tool in mkdocs mike; do
  if [ ! -x "$binary_directory/$tool" ] || ! "$binary_directory/$tool" --version; then
    echo "Prepared documentation command is unavailable or unusable: $tool. Guest setup must complete before verification." >&2
    exit 1
  fi
done
