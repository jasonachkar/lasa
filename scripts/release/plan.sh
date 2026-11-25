#!/usr/bin/env bash
# Decide whether a main commit is a release commit and print its version.
#
#   plan.sh push COMMIT        release when COMMIT raised the newest versioned
#                              CHANGELOG heading (a merged release PR)
#   plan.sh dispatch COMMIT V  manual retry: V must be COMMIT's newest heading
#
# Prints MAJOR.MINOR.PATCH for a release and nothing otherwise. A tag for the
# version may already exist only if it points at COMMIT (an interrupted run).
set -euo pipefail
mode=${1:?Usage: plan.sh push|dispatch COMMIT [VERSION]}
commit=$(git rev-parse --verify "${2:?Missing commit}^{commit}")
semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
newest() {
  git show "$1:CHANGELOG.md" 2>/dev/null |
    sed -n -E "s/^## ($semver) — .+ \\([0-9]{4}-[0-9]{2}-[0-9]{2}\\)\$/\\1/p" | head -n 1
}
greater() { [[ $1 != "$2" && $(printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1) == "$1" ]]; }
current=$(newest "$commit")
case $mode in
  push)
    [[ -n $current ]] || exit 0
    previous=$(newest "$commit^" || true)
    if [[ -n $previous ]] && ! greater "$current" "$previous"; then
      exit 0
    fi
    ;;
  dispatch)
    requested=${3:?Missing version}
    [[ $requested =~ ^$semver$ ]] || { echo "Invalid version: $requested" >&2; exit 1; }
    [[ $current == "$requested" ]] || { echo "Commit's newest CHANGELOG release is ${current:-none}, not $requested" >&2; exit 1; }
    ;;
  *) echo "Unknown mode: $mode" >&2; exit 1;;
esac
if tagged=$(git rev-parse -q --verify "refs/tags/v$current^{commit}"); then
  [[ $tagged == "$commit" ]] || { echo "Tag v$current already identifies a different commit ($tagged)" >&2; exit 1; }
fi
printf '%s\n' "$current"
