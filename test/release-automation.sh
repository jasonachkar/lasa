#!/usr/bin/env bash
# Release planning, CHANGELOG preparation and release notes against real Git
# history in throwaway repositories. Compatible with macOS's system Bash 3.2.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
reject() { if "$@" > "$temp/rejected" 2>&1; then fail "unexpected success: $*"; fi; }

repo="$temp/repo"
mkdir -p "$repo/scripts"
cp -R "$root/scripts/release" "$repo/scripts/release"
cd "$repo"
git init -q -b main
git config user.name Test
git config user.email test@example.invalid
commit() { git add -A && git commit -qm "$1" && git rev-parse HEAD; }
changelog() { printf '# Changelog\n\n%s\n' "$1" > CHANGELOG.md; }
plan() { bash scripts/release/plan.sh "$@"; }
prepare() { bash scripts/release/prepare.sh "$@"; }

changelog $'## 0.1.0 — first (2026-01-01)\n\n- Initial.'
first=$(commit 'Release 0.1.0')
[ "$(plan push "$first")" = 0.1.0 ] || fail 'first release commit not planned'

changelog $'## Unreleased\n\n- Pending change.\n\n## 0.1.0 — first (2026-01-01)\n\n- Initial.'
pending=$(commit 'Describe pending change')
[ -z "$(plan push "$pending")" ] || fail 'an Unreleased-only change must not release'

# prepare refuses bad input and leaves the file alone.
cp CHANGELOG.md "$temp/before"
reject prepare 0.1.0 'same version'
reject prepare 0.0.9 'older version'
reject prepare 1.0 'not semver'
reject prepare 0.2.0 'bad (title)'
reject prepare 0.2.0 ''
reject prepare 0.2.0 title --date 2026-1-1
cmp CHANGELOG.md "$temp/before" || fail 'a rejected prepare modified CHANGELOG.md'

prepare 0.2.0 'second release' --date 2026-02-03 >/dev/null
grep -qx '## 0.2.0 — second release (2026-02-03)' CHANGELOG.md || fail 'heading not written'
grep -q '^## Unreleased' CHANGELOG.md && fail 'Unreleased heading kept'
second=$(commit 'Release 0.2.0 (#2)')
[ "$(plan push "$second")" = 0.2.0 ] || fail 'release PR merge not planned'
[ "$(bash scripts/release/notes.sh 0.2.0)" = $'\n- Pending change.' ] || fail 'notes for 0.2.0 wrong'
[ "$(bash scripts/release/notes.sh 0.1.0)" = $'\n- Initial.' ] || fail 'notes for 0.1.0 wrong'
reject bash scripts/release/notes.sh 9.9.9

# Without an Unreleased section, or with an empty one, prepare refuses.
reject prepare 0.3.0 next
changelog $'## Unreleased\n\n## 0.2.0 — second release (2026-02-03)\n\n- Pending change.'
reject prepare 0.3.0 next
git checkout -q CHANGELOG.md

# Ordinary commits after a release do not release again.
echo change > file
later=$(commit 'Unrelated change')
[ -z "$(plan push "$later")" ] || fail 'non-release commit planned'

# Lowering the version heading never releases.
changelog $'## 0.1.5 — downgrade (2026-03-01)\n\n- x.'
downgrade=$(commit 'Bad downgrade')
[ -z "$(plan push "$downgrade")" ] || fail 'downgrade planned'
git reset -q --hard "$later"

# Tags: an existing tag on the same commit is a retry; elsewhere it is fatal.
git tag v0.2.0 "$second"
[ "$(plan push "$second")" = 0.2.0 ] || fail 'retry with existing tag not planned'
git tag -d v0.2.0 >/dev/null
git tag v0.2.0 "$first"
reject plan push "$second"
git tag -d v0.2.0 >/dev/null

# Dispatch retries must name the commit's newest release exactly.
[ "$(plan dispatch "$later" 0.2.0)" = 0.2.0 ] || fail 'dispatch retry rejected'
reject plan dispatch "$later" 0.1.0
reject plan dispatch "$later" 0.3.0
reject plan dispatch "$later" 'v0.2.0'
reject plan unknown "$later"

# The real CHANGELOG parses and every released heading has notes.
cd "$root"
grep -E '^## [0-9]+\.[0-9]+\.[0-9]+ — ' CHANGELOG.md | sed -E 's/^## ([0-9.]+) — .*/\1/' | while read -r version; do
  bash scripts/release/notes.sh "$version" >/dev/null || fail "CHANGELOG $version has no notes"
done
first_section=$(grep -m 1 '^## ' CHANGELOG.md)
case $first_section in
  '## Unreleased'|'## '[0-9]*' — '*' ('[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')') ;;
  *) fail "The first CHANGELOG section must be '## Unreleased' or a dated release: $first_section";;
esac
echo 'PASS: release planning from merged release PRs, retries, downgrade/tag guards, CHANGELOG preparation and notes'
