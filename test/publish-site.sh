#!/usr/bin/env bash
# End-to-end test of CI site publication (scripts/release/publish-site.sh)
# with real GnuPG keys, real packages, a real Git remote and a real isolated
# APT client. Only Mike (documentation) is replaced by a recording stub.
# Requires built packages: VERSION=0.0.0 make packages
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
version=$(make -s print-version)
for tool in apt-ftparchive dpkg-scanpackages gpgv apt-get git; do command -v "$tool" >/dev/null || { echo "Missing test dependency: $tool" >&2; exit 1; }; done
[ -s "dist/lasa-$version-linux-amd64" ] || { echo "Build packages first: VERSION=$version make packages" >&2; exit 1; }
temp=$(mktemp -d)
cleanup() { for home in "$temp"/gnupg-*; do gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true; done; rm -rf "$temp"; }
trap cleanup EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# ---- fixture keys: passphrase-protected primary plus a CI signing subkey
owner="$temp/gnupg-owner"
mkdir -m 0700 "$owner"
G() { gpg --homedir "$owner" --batch --pinentry-mode loopback --passphrase fixture-pass "$@"; }
G --quick-generate-key 'LASA publish-site fixture <test@example.invalid>' rsa3072 sign 0 2>/dev/null
primary=$(G --with-colons --list-keys | awk -F: '$1=="fpr"{print $10; exit}')
G --armor --export "$primary" > "$temp/old-keyring.asc"
G --quick-add-key "$primary" rsa3072 sign 1y 2>/dev/null
subkey=$(G --with-colons --fixed-list-mode --list-keys "$primary" | awk -F: '$1=="sub"{s=1;next} s&&$1=="fpr"{print $10; exit}')
G --armor --export "$primary" > "$temp/new-keyring.asc"
# CI secret: only the subkey, passphrase removed (as setup-ci-publishing.sh does).
scratch="$temp/gnupg-scratch"
mkdir -m 0700 "$scratch"
G --armor --export-secret-subkeys "$subkey!" | gpg --homedir "$scratch" --batch --quiet --pinentry-mode loopback --passphrase fixture-pass --import 2>/dev/null
printf 'key 1\npasswd\nfixture-pass\n\n\nsave\n' | gpg --homedir "$scratch" --batch --pinentry-mode loopback --command-fd 0 --edit-key "$primary" >/dev/null 2>&1 || true
ci_secret=$(gpg --homedir "$scratch" --batch --armor --export-secret-subkeys "$subkey!")
full_secret=$(G --armor --export-secret-keys "$primary")

# ---- source tree copy carrying the fixture keyring, with packages rebuilt
make_source() { # make_source DIR KEYRING
  mkdir -p "$1"
  git ls-files -co --exclude-standard -z | tar --null -T - -cf - | tar -xf - -C "$1"
  cp -R dist "$1/dist"
  cp "$2" "$1/deploy/apt/lasa-archive-keyring.asc"
  printf '%s\n' "$primary" > "$1/deploy/apt/primary-fingerprint"
  git -C "$1" init -q
  git -C "$1" -c user.name=Test -c user.email=test@example.invalid add -A
  git -C "$1" -c user.name=Test -c user.email=test@example.invalid commit -qm fixture
  (cd "$1" && SOURCE_DATE_EPOCH=1700000000 bash scripts/package-release.sh "$version" >/dev/null 2>&1)
}
make_source "$temp/src" "$temp/new-keyring.asc"
assets="$temp/src/dist"

# ---- distribution remote mirroring the live layout (a version named "current")
git init -q --bare "$temp/remote.git"
git -C "$temp/remote.git" symbolic-ref HEAD refs/heads/main
git init -q -b main "$temp/seed"
printf 'lasa.secureobs.com\n' > "$temp/seed/CNAME"
touch "$temp/seed/.nojekyll"
printf '[{"version": "current", "title": "Current", "aliases": ["latest", "preview"]}]\n' > "$temp/seed/versions.json"
git -C "$temp/seed" -c user.name=Test -c user.email=test@example.invalid add -A
git -C "$temp/seed" -c user.name=Test -c user.email=test@example.invalid commit -qm seed
git -C "$temp/seed" push -q "$temp/remote.git" main

# ---- recording Mike stub: writes the version tree and commits like Mike would
mkdir "$temp/bin"
cat > "$temp/bin/mike" <<'MIKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MIKE_LOG"
command=$1; shift
positional=()
while [ "$#" -gt 0 ]; do
  case $1 in --config-file|--branch|--remote|--alias-type) shift 2;; --*) shift;; *) positional+=("$1"); shift;; esac
done
case $command in
  delete) rm -rf "${positional[0]}"; python3 -c 'import json,sys; v=[x for x in json.load(open("versions.json")) if x["version"]!=sys.argv[1]]; json.dump(v,open("versions.json","w"))' "${positional[0]}";;
  deploy)
    mkdir -p "${positional[0]}"; printf 'docs %s\n' "${positional[0]}" > "${positional[0]}/index.html"
    for alias in "${positional[@]:1}"; do mkdir -p "$alias"; printf 'redirect to %s\n' "${positional[0]}" > "$alias/index.html"; done
    python3 -c 'import json,sys; v=[x for x in json.load(open("versions.json")) if x["version"]!=sys.argv[1]]; [x.__setitem__("aliases",[a for a in x["aliases"] if a not in sys.argv[2:]]) for x in v]; v.append({"version":sys.argv[1],"title":sys.argv[1],"aliases":sys.argv[2:]}); json.dump(v,open("versions.json","w"))' "${positional[@]}";;
  set-default) ;;
  *) echo "unexpected mike command $command" >&2; exit 1;;
esac
git add -A && git commit -qm "mike $command" || true
MIKE
chmod +x "$temp/bin/mike"
export PATH="$temp/bin:$PATH" MIKE_LOG="$temp/mike.log"

publish() { # publish SOURCE_DIR [extra env...]
  local source=$1; shift
  env APT_SIGNING_SUBKEY="$ci_secret" DISTRIBUTION_DEPLOY_KEY='unused-for-local-remote' \
    APT_SIGNING_FINGERPRINT="$primary" APT_SIGNING_SUBKEY_FINGERPRINT="$subkey" \
    DISTRIBUTION_REPOSITORY=example/homebrew-lasa DISTRIBUTION_BRANCH=main \
    APT_REPOSITORY_URL=https://lasa.secureobs.com/apt GITHUB_REPOSITORY=example/lasa \
    DISTRIBUTION_REMOTE="$temp/remote.git" SERVED_SITE_URL= "$@" \
    bash "$source/scripts/release/publish-site.sh" "$version" "$source/dist"
}
reject() { if "$@" > "$temp/rejected" 2>&1; then fail "unexpected success: $*"; fi; }

# ---- refusals happen before anything is pushed
before=$(git -C "$temp/remote.git" rev-parse main)
reject publish "$temp/src" APT_SIGNING_SUBKEY="$full_secret"
grep -q 'contains the primary private key' "$temp/rejected" || fail 'full primary secret not refused'
reject publish "$temp/src" APT_SIGNING_FINGERPRINT=0000000000000000000000000000000000000000
reject publish "$temp/src" APT_SIGNING_SUBKEY_FINGERPRINT=0000000000000000000000000000000000000000
reject publish "$temp/src" DISTRIBUTION_REPOSITORY='bad repo'
make_source "$temp/src-old" "$temp/old-keyring.asc"
reject publish "$temp/src-old"
grep -q 'lacks signing subkey' "$temp/rejected" || fail 'package keyring without the subkey not refused'
# A package whose keyring differs from the committed one is refused.
cp -R "$temp/src" "$temp/src-tampered"
cp "$temp/src-old/dist/lasa_${version}_amd64.deb" "$temp/src-tampered/dist/lasa_${version}_amd64.deb"
reject publish "$temp/src-tampered"
grep -q 'does not carry the committed APT keyring' "$temp/rejected" || fail 'tampered package keyring not refused'
[ "$(git -C "$temp/remote.git" rev-parse main)" = "$before" ] || fail 'a refused publication changed the remote'

# ---- successful publication
publish "$temp/src" > "$temp/publish.log"
git clone -q "$temp/remote.git" "$temp/published"
site="$temp/published"
for arch in amd64 arm64; do cmp "$site/apt/pool/main/l/lasa/lasa_${version}_${arch}.deb" "$assets/lasa_${version}_${arch}.deb"; done
status=$(gpg --homedir "$scratch" --batch --status-fd 1 --verify "$site/apt/dists/stable/InRelease" 2>/dev/null)
grep -q "VALIDSIG $subkey .* $primary\$" <<< "$status" || fail 'InRelease is not signed by the CI subkey'
python3 -I scripts/release/dearmor.py "$temp/new-keyring.asc" "$temp/new-keyring.gpg"
python3 -I scripts/release/dearmor.py "$temp/old-keyring.asc" "$temp/old-keyring.gpg"
gpgv --keyring "$temp/new-keyring.gpg" "$site/apt/dists/stable/InRelease" 2>/dev/null || fail 'packaged keyring cannot verify the index'
if gpgv --keyring "$temp/old-keyring.gpg" "$site/apt/dists/stable/InRelease" 2>/dev/null; then
  fail 'the pre-subkey keyring unexpectedly verifies a subkey-only signature'
fi
bash scripts/release/check-keyring.sh "$site/apt/lasa-signing-key.asc" "$primary" "$subkey"
grep -qx "APT_FINGERPRINT=$primary" "$site/install-apt.sh" || fail 'installer does not pin the primary fingerprint'
grep -q "version \"$version\"" "$site/Formula/lasa.rb" || fail 'formula not updated'
git -C "$site" show HEAD:CNAME | grep -qx lasa.secureobs.com || fail 'CNAME lost'
grep -q '^delete .* current$' "$MIKE_LOG" || fail 'legacy "current" version not migrated'
grep -q "^deploy .* $version latest current\$" "$MIKE_LOG" || fail 'docs not deployed with latest/current aliases'
python3 - "$site/versions.json" "$version" <<'PY'
import json, sys
versions = {v["version"]: v for v in json.load(open(sys.argv[1]))}
assert set(versions) == {sys.argv[2]}, versions
assert sorted(versions[sys.argv[2]]["aliases"]) == ["current", "latest"], versions
PY
git -C "$site" log --format=%an | grep -qx 'LASA release automation' || fail 'commits not attributed to release automation'

# ---- real APT client trusting only the packaged keyring downloads the packages
mkdir -p "$temp/apt/lists/partial" "$temp/apt/cache/archives/partial" "$temp/apt/parts" "$temp/downloads"
: > "$temp/apt/main"
printf 'Dir::Etc::parts "%s/apt/parts";\nDir::Etc::main "%s/apt/main";\n' "$temp" "$temp" > "$temp/apt/conf"
printf 'deb [arch=amd64,arm64 signed-by=%s] file:%s/apt stable main\n' "$temp/new-keyring.gpg" "$site" > "$temp/apt/sources"
apt_run() {
  APT_CONFIG="$temp/apt/conf" apt-get -o "Dir::Etc::sourcelist=$temp/apt/sources" -o Dir::Etc::sourceparts=- \
    -o "Dir::State::lists=$temp/apt/lists" -o Dir::State::status=/dev/null -o "Dir::Cache=$temp/apt/cache" \
    -o Debug::NoLocking=1 -o "APT::Sandbox::User=$(id -un)" -o APT::Update::Error-Mode=any "$@"
}
apt_run update > "$temp/apt.log" 2>&1 || { cat "$temp/apt.log" >&2; fail 'APT rejected the CI-signed repository'; }
(cd "$temp/downloads" && apt_run download "lasa:amd64=$version" > /dev/null 2>&1) || fail 'APT could not download the package'
cmp "$temp/downloads/lasa_${version}_amd64.deb" "$assets/lasa_${version}_amd64.deb"

# ---- retry is a no-op and never rewrites history
pushed=$(git -C "$temp/remote.git" rev-parse main)
publish "$temp/src" > "$temp/retry.log"
grep -q 'nothing to push\|Pushed' "$temp/retry.log" || fail 'retry produced no outcome'
git -C "$temp/remote.git" merge-base --is-ancestor "$pushed" main || fail 'retry rewrote distribution history'
echo 'PASS: CI publication signs with only the subkey, refuses primary secrets, foreign or stale keyrings and tampered packages, keeps history fast-forward, migrates /current/ docs, and serves a repository real APT trusts through the packaged keyring'
