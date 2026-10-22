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
  mike deploy -F "$root/mkdocs.yml" -b pages -r origin --alias-type redirect -u 0.1.0 latest
  mike set-default -F "$root/mkdocs.yml" -b pages -r origin latest
  git push -q origin pages
)
# Each publishing job starts with a new checkout, as this second deployment does.
git clone -q --branch pages "$temp/remote" "$temp/second"
git -C "$temp/second" config user.name Test
git -C "$temp/second" config user.email test@example.invalid
(
  cd "$temp/second"
  mike deploy -F "$root/mkdocs.yml" -b pages -r origin --alias-type redirect -u 0.2.0 latest
  mike set-default -F "$root/mkdocs.yml" -b pages -r origin latest
  git show pages:versions.json > "$temp/versions.json"
  git show pages:apt/package.deb | grep -qx keep-package
  git show pages:Formula/lasa.rb | grep -qx keep-formula
  git show pages:CNAME | grep -qx lasa.secureobs.com
  git cat-file -e pages:.nojekyll
  git cat-file -e pages:0.1.0/index.html
  git cat-file -e pages:0.2.0/index.html
  git cat-file -e pages:latest/index.html
)
python - "$temp/versions.json" <<'PY'
import json, sys
versions = {v['version']: v for v in json.load(open(sys.argv[1]))}
assert set(versions) == {'0.1.0', '0.2.0'}
assert versions['0.2.0']['aliases'] == ['latest']
assert not versions['0.1.0']['aliases']
PY
# Current product docs refresh the default site without losing release archives.
test "$(python scripts/check-docs-version.py current "$temp/versions.json")" = latest
printf '[]\n' > "$temp/empty.json"
test "$(python scripts/check-docs-version.py current "$temp/empty.json")" = latest
# Previously deployed channel metadata remains readable during migration.
printf '[{"version":"preview","aliases":["latest"]}]\n' > "$temp/legacy.json"
test "$(python scripts/check-docs-version.py current "$temp/legacy.json")" = latest
test "$(python scripts/check-docs-version.py 0.1.0 "$temp/legacy.json")" = latest
# An old environment setting cannot inject the removed product warning.
LASA_DOCS_PREVIEW=1 python scripts/prepare-docs.py
(
  cd "$temp/second"
  # Reproduce an existing deployment with the former named channel.
  mike deploy -F "$root/mkdocs.yml" -b pages -r origin --alias-type redirect -u preview
  mike delete -F "$root/mkdocs.yml" -b pages -r origin preview
  mike deploy -F "$root/mkdocs.yml" -b pages -r origin --alias-type redirect -u --title 'Current documentation' current latest
  mike alias -F "$root/mkdocs.yml" -b pages -r origin --alias-type redirect -u current preview
  mike set-default -F "$root/mkdocs.yml" -b pages -r origin latest
  git show pages:versions.json > "$temp/versions.json"
  git show pages:current/index.html > "$temp/current.html"
  if grep -Eq 'Unreleased preview|This documentation describes development code|Packages may not yet be available' "$temp/current.html"; then exit 1; fi
  git show pages:preview/installation/index.html | grep -q 'current/installation/'
  git cat-file -e pages:0.1.0/index.html
  git cat-file -e pages:0.2.0/index.html
  git show pages:apt/package.deb | grep -qx keep-package
  git show pages:Formula/lasa.rb | grep -qx keep-formula
  git show pages:CNAME | grep -qx lasa.secureobs.com
)
python - "$temp/versions.json" <<'PYTEST'
import json, sys
versions = {item['version']: item for item in json.load(open(sys.argv[1]))}
assert set(versions) == {'0.1.0', '0.2.0', 'current'}
assert versions['current']['title'] == 'Current documentation'
assert set(versions['current']['aliases']) == {'latest', 'preview'}
assert not versions['0.2.0']['aliases']
PYTEST
python scripts/check-docs-version.py 0.2.0 "$temp/versions.json"
if python scripts/check-docs-version.py 0.1.0 "$temp/versions.json" > "$temp/error" 2>&1; then exit 1; fi
grep -q 'Refusing to roll back documentation' "$temp/error"
echo 'PASS: strict customer site, search, release archives, current docs, legacy redirects, package/domain preservation and rollback guards'
