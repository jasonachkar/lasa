#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
python scripts/prepare-docs.py
mkdocs build --strict
test -s .build/docs-site/index.html
test -s .build/docs-site/search/search_index.json
if find .build/docs-site -iname '*maintainer*' | grep -q .; then echo 'Maintainer content leaked into the site' >&2; exit 1; fi
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
git init -q --bare "$temp/remote"
git init -q "$temp/site"
git -C "$temp/site" checkout -qb pages
git -C "$temp/site" config user.name Test
git -C "$temp/site" config user.email test@example.invalid
mkdir -p "$temp/site/apt" "$temp/site/Formula"
printf 'keep-package\n' > "$temp/site/apt/package.deb"
printf 'keep-formula\n' > "$temp/site/Formula/lasa.rb"
printf 'lasa.secureobs.com\n' > "$temp/site/CNAME"
touch "$temp/site/.nojekyll"
git -C "$temp/site" add .
git -C "$temp/site" commit -qm initial
git -C "$temp/site" remote add origin "$temp/remote"
git -C "$temp/site" push -qu origin pages
(
  cd "$temp/site"
  mike deploy -F "$root/mkdocs.yml" -b pages -r origin --alias-type redirect -u current latest
  mike set-default -F "$root/mkdocs.yml" -b pages -r origin latest
  git push -q origin pages
)
git clone -q --branch pages "$temp/remote" "$temp/first"
git -C "$temp/first" config user.name Test
git -C "$temp/first" config user.email test@example.invalid
bash "$root/scripts/publish-docs.sh" "$temp/first" 0.1.0
test "$(git -C "$temp/first" ls-remote origin refs/heads/pages | awk '{print $1}')" != "$(git -C "$temp/first" rev-parse HEAD)"
git -C "$temp/first" push -q origin pages
git clone -q --branch pages "$temp/remote" "$temp/second"
git -C "$temp/second" config user.name Test
git -C "$temp/second" config user.email test@example.invalid
bash "$root/scripts/publish-docs.sh" "$temp/second" 0.2.0
(
  cd "$temp/second"
  git show pages:versions.json > "$temp/versions.json"
  git show pages:apt/package.deb | grep -qx keep-package
  git show pages:Formula/lasa.rb | grep -qx keep-formula
  git show pages:CNAME | grep -qx lasa.secureobs.com
  git cat-file -e pages:.nojekyll
  git cat-file -e pages:0.1.0/index.html
  git cat-file -e pages:0.2.0/index.html
  git cat-file -e pages:latest/index.html
  git show pages:current/index.html | grep -q '0.2.0'
)
python - "$temp/versions.json" <<'PY'
import json, sys
versions = {v['version']: v for v in json.load(open(sys.argv[1]))}
# The original "current" version became an alias of the newest release.
assert set(versions) == {'0.1.0', '0.2.0'}, versions
assert sorted(versions['0.2.0']['aliases']) == ['current', 'latest'], versions
assert not versions['0.1.0']['aliases']
PY
python scripts/check-docs-version.py 0.2.0 "$temp/versions.json"
if python scripts/check-docs-version.py 0.1.0 "$temp/versions.json" > "$temp/error" 2>&1; then exit 1; fi
grep -q 'Refusing to roll back documentation' "$temp/error"
echo 'PASS: strict customer-only site, search and real two-version Mike deployments preserve packages, formula, domain and old documentation'
