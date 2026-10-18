#!/usr/bin/env bash
set -euo pipefail
script=$(cd "$(dirname "$0")/.." && pwd)/scripts/next-version.sh
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
git -C "$temp" init -q
git -C "$temp" config user.name Test
git -C "$temp" config user.email test@example.invalid
cd "$temp"
git commit --allow-empty -qm initial
[[ $(bash "$script") == 0.1.0 ]]
git tag v0.1.0
[[ $(bash "$script") == 0.1.0 ]]
git commit --allow-empty -qm 'fix: handle a disappearing process'
[[ $(bash "$script") == 0.1.1 ]]
git tag v0.1.1
git commit --allow-empty -qm 'feat(report): add an output mode'
[[ $(bash "$script") == 0.2.0 ]]
git tag -am release v0.2.0
[[ $(bash "$script") == 0.2.0 ]]
git commit --allow-empty -qm 'feat!: change the public command contract'
[[ $(bash "$script") == 1.0.0 ]]
git tag v1.0.0
git commit --allow-empty -qm 'refactor: update implementation' -m 'BREAKING CHANGE: report contract changes'
[[ $(bash "$script") == 2.0.0 ]]
git tag v2.0.0
git commit --allow-empty -qm 'docs: explain an error'
[[ $(bash "$script") == 2.0.1 ]]
echo 'PASS: initial, same-commit, patch, minor, breaking major, annotated tags and breaking footers'
