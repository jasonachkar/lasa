#!/usr/bin/env bash
set -euo pipefail
umask 077
version=${1:?Usage: publish-docs.sh VERSION}
# Accept the old command argument without exposing the old product label.
if [ "$version" = preview ]; then version=current; fi
[[ $version == current || $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || { echo "Expected a stable version or current" >&2; exit 1; }
: "${DISTRIBUTION_REPOSITORY:?Run publishing bootstrap first}"
: "${DISTRIBUTION_BRANCH:?Missing branch}"
: "${DISTRIBUTION_DEPLOY_KEY:?Missing deploy key secret}"
[[ $DISTRIBUTION_REPOSITORY =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || exit 1
root=$(cd "$(dirname "$0")/.." && pwd)
if [ -n "${LASA_RELEASE_PROVIDER:-}" ]; then bash "$root/scripts/check-publisher.sh" "$LASA_RELEASE_PROVIDER"; fi
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
printf '%s\n' "$DISTRIBUTION_DEPLOY_KEY" > "$temp/key"
unset DISTRIBUTION_DEPLOY_KEY
gh api meta --jq '.ssh_keys[] | "github.com " + .' > "$temp/known_hosts"
test -s "$temp/known_hosts"
printf -v GIT_SSH_COMMAND 'ssh -i %q -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=%q' "$temp/key" "$temp/known_hosts"
export GIT_SSH_COMMAND
git clone --single-branch --branch "$DISTRIBUTION_BRANCH" "git@github.com:$DISTRIBUTION_REPOSITORY.git" "$temp/site"
git -C "$temp/site" config user.name 'LASA documentation automation'
git -C "$temp/site" config user.email '41898282+github-actions[bot]@users.noreply.github.com'
cd "$temp/site"
touch .nojekyll
git add .nojekyll
if ! git diff --cached --quiet; then git commit -m 'Serve generated LASA documentation without Jekyll'; fi
if ! git show "$DISTRIBUTION_BRANCH:versions.json" > "$temp/versions.json" 2>/dev/null; then printf '[]\n' > "$temp/versions.json"; fi
alias=$(python "$root/scripts/check-docs-version.py" "$version" "$temp/versions.json")
python "$root/scripts/prepare-docs.py"
# Mike updates the branch tree directly and preserves apt/, Formula/, CNAME,
# .nojekyll and all previously published documentation versions.
# Migrate the previous documentation channel out of the selector, preserving
# bookmarked URLs as redirects. All changes become visible in one Git push.
legacy=false
if python - "$temp/versions.json" <<'PYINDEX'
import json, sys
sys.exit(0 if any(item["version"] == "preview" for item in json.load(open(sys.argv[1]))) else 1)
PYINDEX
then
  legacy=true
  mike delete --config-file "$root/mkdocs.yml" --branch "$DISTRIBUTION_BRANCH" --remote origin preview
fi
title=$version
if [ "$version" = current ]; then title='Current documentation'; fi
mike deploy --config-file "$root/mkdocs.yml" --branch "$DISTRIBUTION_BRANCH" --remote origin --alias-type redirect --update-aliases --title "$title" "$version" "$alias"
if [ "$legacy" = true ]; then
  mike alias --config-file "$root/mkdocs.yml" --branch "$DISTRIBUTION_BRANCH" --remote origin --alias-type redirect --update-aliases "$version" preview
fi
mike set-default --config-file "$root/mkdocs.yml" --branch "$DISTRIBUTION_BRANCH" --remote origin latest
if [ -n "${LASA_RELEASE_PROVIDER:-}" ]; then bash "$root/scripts/check-publisher.sh" "$LASA_RELEASE_PROVIDER"; fi
git push origin "$DISTRIBUTION_BRANCH:$DISTRIBUTION_BRANCH"
# Verify deployment, not just the Git push. Use Pages' effective domain/base URL.
pages_url=${DOCS_SITE_URL:-https://${DISTRIBUTION_REPOSITORY%/*}.github.io/${DISTRIBUTION_REPOSITORY#*/}/}
[[ $pages_url == https://* ]] || { echo 'Documentation verification requires an HTTPS URL' >&2; exit 1; }
for ((attempt=0; attempt<80; attempt++)); do
  if curl --proto '=https' --tlsv1.2 -fsSL "${pages_url%/}/versions.json" -o "$temp/served" && cmp -s "$temp/served" <(git show "$DISTRIBUTION_BRANCH:versions.json") && \
     curl --proto '=https' --tlsv1.2 -fsSL "${pages_url%/}/$version/build-info.json" -o "$temp/build-info" && cmp -s "$temp/build-info" <(git show "$DISTRIBUTION_BRANCH:$version/build-info.json"); then
    echo "Versioned documentation deployed: ${pages_url%/}/$version/ ($version)"
    exit 0
  fi
  sleep 10
done
echo "Docs were pushed, but Pages did not serve the new version index in time. Check https://github.com/$DISTRIBUTION_REPOSITORY/actions and rerun the workflow." >&2
exit 1
