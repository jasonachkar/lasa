#!/usr/bin/env bash
# End-to-end test of the owner's one-time setup (scripts/setup-ci-publishing.sh)
# against a stateful GitHub CLI mock backed by real local Git repositories,
# real GnuPG keys and, on Linux, a real isolated APT client.
# Compatible with macOS's system Bash 3.2.
set -euo pipefail
umask 077
unset GITHUB_ACTIONS
cd "$(dirname "$0")/.."
root=$PWD
temp=$(mktemp -d /tmp/lasa-setup-test.XXXXXX)
cleanup() { for home in "$temp"/gnupg-*; do gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true; done; rm -rf "$temp"; }
trap cleanup EXIT
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
for tool in gpg git jq python3 ssh-keygen; do command -v "$tool" >/dev/null || fail "missing $tool"; done

# ---- the owner's keyring: passphrase-protected primary key, as bootstrap made it
owner="$temp/gnupg-owner"
mkdir -m 0700 "$owner"
gpg --homedir "$owner" --batch --pinentry-mode loopback --passphrase 'owner pass' \
  --quick-generate-key 'LASA packages (jasonachkar/lasa) <test@example.invalid>' rsa3072 sign 0 2>/dev/null
primary=$(gpg --homedir "$owner" --batch --with-colons --list-keys | awk -F: '$1=="fpr"{print $10; exit}')
gpg --homedir "$owner" --batch --armor --export "$primary" > "$temp/original-keyring.asc"

# ---- repositories
repos="$temp/repos"
mkdir -p "$repos"
seed() { # seed REPO DIR
  git -C "$2" init -q -b main
  git -C "$2" -c user.name=Seed -c user.email=seed@example.invalid add -A
  git -C "$2" -c user.name=Seed -c user.email=seed@example.invalid commit -qm seed
  git clone -q --bare "$2" "$repos/${1//\//__}.git"
}
src="$temp/seed-src"
mkdir -p "$src/deploy/apt" "$src/scripts"
cp -R "$root/scripts/release" "$src/scripts/release"
printf '%s\n' "$primary" > "$src/deploy/apt/primary-fingerprint"
cp "$temp/original-keyring.asc" "$src/deploy/apt/lasa-archive-keyring.asc"
printf '# Changelog\n\n## 0.2.1 — bounded memory (2026-11-24)\n\n- Fix.\n' > "$src/CHANGELOG.md"
seed jasonachkar/lasa "$src"
git --git-dir "$repos/jasonachkar__lasa.git" tag v0.2.1 main
site="$temp/seed-site"
mkdir -p "$site/apt/dists/stable/main/binary-amd64"
printf 'Package: lasa\nVersion: 0.2.1\nArchitecture: amd64\n' > "$site/apt/dists/stable/main/binary-amd64/Packages"
printf 'Origin: LASA\nVersion: 0.2.1\n' > "$site/apt/dists/stable/Release"
gpg --homedir "$owner" --batch --pinentry-mode loopback --passphrase 'owner pass' --local-user "$primary" \
  --clearsign --output "$site/apt/dists/stable/InRelease" "$site/apt/dists/stable/Release"
seed jasonachkar/homebrew-lasa "$site"

# ---- GitHub state before setup (mirrors the live repositories)
export GH_MOCK_STATE="$temp/state.json" GH_MOCK_REPOS="$repos"
python3 - "$primary" > "$GH_MOCK_STATE" <<'PY'
import json, sys
print(json.dumps({
  "login": "jasonachkar", "auto_merge": False, "secret_writes": 0, "log_keys": [],
  "environment": {"can_admins_bypass": False,
                  "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
                  "protection_rules": [{"type": "required_reviewers", "prevent_self_review": False,
                                        "reviewers": [{"type": "User", "reviewer": {"login": "jasonachkar"}}]}]},
  "deployment_branches": [{"name": "main", "type": "branch"}],
  "vars": {"APT_SIGNING_FINGERPRINT": sys.argv[1], "DISTRIBUTION_REPOSITORY": "jasonachkar/homebrew-lasa",
           "DISTRIBUTION_BRANCH": "main", "APT_REPOSITORY_URL": "https://jasonachkar.github.io/homebrew-lasa/apt",
           "PUBLISHING_PROVIDER": "local"},
  "secrets": {}, "deploy_keys": [{"id": 5, "title": "unrelated", "key": "ssh-ed25519 AAAA", "read_only": True}],
  "prs": {}, "runs": {},
  "rulesets": {
    "jasonachkar/lasa": [
      {"id": 1, "name": "LASA release tag creation", "target": "tag", "enforcement": "active",
       "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
       "rules": [{"type": "creation"}], "bypass_actors": [{"actor_id": 83395276, "actor_type": "User", "bypass_mode": "always"}]},
      {"id": 2, "name": "LASA release tag integrity", "target": "tag", "enforcement": "active",
       "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
       "rules": [{"type": "update"}, {"type": "deletion"}], "bypass_actors": []}],
    "jasonachkar/homebrew-lasa": [
      {"id": 3, "name": "LASA owner-only branch writes", "target": "branch", "enforcement": "active",
       "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
       "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
       "bypass_actors": [{"actor_id": 83395276, "actor_type": "User", "bypass_mode": "always"}]},
      {"id": 4, "name": "LASA distribution integrity", "target": "branch", "enforcement": "active",
       "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
       "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}], "bypass_actors": []}]}}))
PY
mkdir "$temp/bin"
cp "$root/test/fixtures/gh-mock.py" "$temp/bin/gh"
chmod +x "$temp/bin/gh"
export PATH="$temp/bin:$PATH" GNUPGHOME="$owner" SETUP_SERVED_SITE_URL='' SETUP_POLL_SECONDS=0
setup() { bash "$root/scripts/setup-ci-publishing.sh" "$@"; }
state() { jq -r "$1" "$GH_MOCK_STATE"; }

# ---- refusals change nothing
cp "$GH_MOCK_STATE" "$temp/pristine.json"
if printf 'wrong pass\n' | setup --yes > "$temp/out" 2>&1; then fail 'wrong passphrase accepted'; fi
grep -q 'does not unlock' "$temp/out" || { cat "$temp/out" >&2; fail 'wrong passphrase not explained'; }
cmp <(jq -S . "$GH_MOCK_STATE") <(jq -S . "$temp/pristine.json") || fail 'a refused run changed GitHub state'
jq '.login = "someone-else"' "$temp/pristine.json" > "$GH_MOCK_STATE"
if printf 'owner pass\n' | setup --yes > "$temp/out" 2>&1; then fail 'non-owner accepted'; fi
grep -q 'log in as the repository owner' "$temp/out" || fail 'non-owner not explained'
cp "$temp/pristine.json" "$GH_MOCK_STATE"
if printf 'owner pass\n' | GNUPGHOME="$temp/gnupg-empty" setup --yes > "$temp/out" 2>&1; then fail 'missing key accepted'; fi
grep -q 'is not in' "$temp/out" || fail 'missing key not explained'
cp "$temp/pristine.json" "$GH_MOCK_STATE"
if printf 'owner pass\n' | setup --unknown > "$temp/out" 2>&1; then fail 'unknown option accepted'; fi
jq '.environment.can_admins_bypass = true' "$temp/pristine.json" > "$GH_MOCK_STATE"
if printf 'owner pass\n' | setup --yes > "$temp/out" 2>&1; then fail 'bypassable environment accepted'; fi
grep -q 'sole reviewer and disable bypasses' "$temp/out" || fail 'unsafe environment not explained'
jq '.deploy_keys[0].read_only = false' "$temp/pristine.json" > "$GH_MOCK_STATE"
if printf 'owner pass\n' | setup --yes > "$temp/out" 2>&1; then fail 'unrelated write access accepted'; fi
grep -q 'unrelated writable deploy key' "$temp/out" || fail 'unrelated deploy key not explained'
cp "$temp/pristine.json" "$GH_MOCK_STATE"

# ---- the real run
printf 'owner pass\n' | setup --yes > "$temp/run.log" 2>&1 || { cat "$temp/run.log" >&2; fail 'setup failed'; }
subkey=$(state '.vars.APT_SIGNING_SUBKEY_FINGERPRINT')
[[ $subkey =~ ^[A-F0-9]{40}$ ]] || fail 'subkey fingerprint variable not set'

# The uploaded secret: stub primary, the subkey only, usable without a passphrase.
check="$temp/gnupg-check"
mkdir -m 0700 "$check"
state '.secrets.APT_SIGNING_SUBKEY' | gpg --homedir "$check" --batch --quiet --import 2>/dev/null
listing=$(gpg --homedir "$check" --batch --with-colons --fixed-list-mode --list-secret-keys)
[ "$(printf '%s\n' "$listing" | awk -F: '$1=="sec"{print $15}')" = '#' ] || fail 'uploaded secret contains the primary private key'
[ "$(printf '%s\n' "$listing" | awk -F: '$1=="ssb" && $15!="#"' | wc -l | tr -d ' ')" = 1 ] || fail 'uploaded secret must hold exactly one usable subkey'
printf 'x\n' | gpg --homedir "$check" --batch --pinentry-mode error --local-user "$subkey!" --clearsign > /dev/null 2>&1 || fail 'uploaded subkey needs a passphrase'
# The owner's keyring still protects its keys with the passphrase.
if printf 'x\n' | gpg --homedir "$owner" --batch --pinentry-mode error --local-user "$primary!" --clearsign > /dev/null 2>&1; then
  gpgconf --homedir "$owner" --kill gpg-agent
  printf 'x\n' | gpg --homedir "$owner" --batch --pinentry-mode error --local-user "$primary!" --clearsign > /dev/null 2>&1 && fail 'owner primary key lost its passphrase'
fi

# Deploy key: one writable key titled for automation; the secret is its private half.
[ "$(state '[.deploy_keys[] | select(.title == "LASA release automation" and .read_only == false)] | length')" = 1 ] || fail 'writable deploy key missing'
[ "$(state '[.deploy_keys[] | select(.title == "unrelated")] | length')" = 1 ] || fail 'unrelated deploy key touched'
state '.secrets.DISTRIBUTION_DEPLOY_KEY' > "$temp/deploy"
chmod 0600 "$temp/deploy"
[ "$(ssh-keygen -y -f "$temp/deploy" | cut -d' ' -f1-2)" = "$(state '.deploy_keys[] | select(.title == "LASA release automation") | .key' | cut -d' ' -f1-2)" ] || fail 'deploy key secret does not match the registered key'

# Rulesets: only the intended bypasses were added; rules untouched.
[ "$(state '.rulesets["jasonachkar/lasa"][0].bypass_actors | map(.actor_type + ":" + (.actor_id|tostring)) | join(",")')" = 'User:83395276' ] || fail 'tag creation must remain owner-only'
[ "$(state '.rulesets["jasonachkar/lasa"][1].bypass_actors | length')" = 0 ] || fail 'tag integrity ruleset must keep no bypass'
[ "$(state '.rulesets["jasonachkar/homebrew-lasa"][0].bypass_actors | map(.actor_type) | sort | join(",")')" = 'DeployKey,User' ] || fail 'deploy key bypass wrong'
[ "$(state '.rulesets["jasonachkar/homebrew-lasa"][1].bypass_actors | length')" = 0 ] || fail 'distribution integrity ruleset must keep no bypass'
[ "$(state '.rulesets["jasonachkar/lasa"][0].rules | length')" = 1 ] || fail 'ruleset rules changed'

# Variables.
[ "$(state '.vars.PUBLISHING_PROVIDER')" = github-actions ] || fail 'automation not enabled'
[ "$(state '.vars.APT_REPOSITORY_URL')" = https://lasa.secureobs.com/apt ] || fail 'APT URL not set'
[ "$(state '.vars.DOCS_SITE_URL')" = https://lasa.secureobs.com/ ] || fail 'docs URL not set'

# main now packages the subkey, and the release PR produced a dated heading.
git --git-dir "$repos/jasonachkar__lasa.git" show main:deploy/apt/lasa-archive-keyring.asc > "$temp/main-keyring.asc"
bash "$root/scripts/release/check-keyring.sh" "$temp/main-keyring.asc" "$primary" "$subkey"
git --git-dir "$repos/jasonachkar__lasa.git" show main:CHANGELOG.md | grep -Eq '^## 0\.2\.2 — automated publishing \([0-9]{4}-[0-9]{2}-[0-9]{2}\)$' || fail 'release heading missing'
git --git-dir "$repos/jasonachkar__lasa.git" show main:CHANGELOG.md | grep -q 'signed in CI by a dedicated signing subkey' || fail 'release notes missing'
git --git-dir "$repos/jasonachkar__lasa.git" rev-parse -q --verify refs/tags/v0.2.2 > /dev/null || fail 'release not tagged'
awk '/owner created tag v0.2.2/ {tagged=1} /approved run/ && tagged {approved=1} END {exit !approved}' "$temp/state.log" ||
  fail 'owner must create the tag before approving deployment'

# The published index is co-signed by the primary key; the original keyring accepts it.
git clone -q "$repos/jasonachkar__homebrew-lasa.git" "$temp/published"
python3 -I "$root/scripts/release/dearmor.py" "$temp/original-keyring.asc" "$temp/original.gpg"
release_dir="$temp/published/apt/dists/stable"
status=$(gpg --homedir "$owner" --batch --status-fd 1 --verify "$release_dir/InRelease" 2>/dev/null)
for signer in "$primary" "$subkey"; do
  grep -Fq "VALIDSIG $signer " <<< "$status" || fail 'InRelease does not have both signatures'
done
status=$(gpg --homedir "$owner" --batch --status-fd 1 --verify "$release_dir/Release.gpg" "$release_dir/Release" 2>/dev/null)
for signer in "$primary" "$subkey"; do
  grep -Fq "VALIDSIG $signer " <<< "$status" || fail 'Release.gpg does not have both signatures'
done
grep -q 'Version: 0.2.2' "$temp/published/apt/dists/stable/Release" || fail 'co-signed the wrong index'
if command -v apt-get >/dev/null && command -v apt-ftparchive >/dev/null; then
  # Real APT, trusting only the keyring installed before this setup.
  apt_site="$temp/apt-site"
  mkdir -p "$apt_site/pool" "$apt_site/dists/stable/main/binary-amd64" "$temp/apt/lists/partial" "$temp/apt/cache/archives/partial" "$temp/apt/parts"
  : > "$apt_site/dists/stable/main/binary-amd64/Packages"
  : > "$temp/apt/main"
  printf 'Dir::Etc::parts "%s/apt/parts";\nDir::Etc::main "%s/apt/main";\n' "$temp" "$temp" > "$temp/apt/conf"
  (cd "$apt_site" && APT_CONFIG="$temp/apt/conf" apt-ftparchive -o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Components=main -o APT::FTPArchive::Release::Architectures=amd64 release dists/stable > "$temp/Release" && mv "$temp/Release" dists/stable/Release)
  # Same signatures the setup produced: CI subkey first, then the primary co-signature.
  gpg --homedir "$check" --batch --yes --pinentry-mode error --local-user "$subkey!" --clearsign --output "$apt_site/dists/stable/InRelease" "$apt_site/dists/stable/Release"
  printf 'deb [arch=amd64 signed-by=%s] file:%s stable main\n' "$temp/original.gpg" "$apt_site" > "$temp/apt/sources"
  apt_update() {
    rm -rf "$temp/apt/lists"; mkdir -p "$temp/apt/lists/partial"
    APT_CONFIG="$temp/apt/conf" apt-get -o "Dir::Etc::sourcelist=$temp/apt/sources" -o Dir::Etc::sourceparts=- \
      -o "Dir::State::lists=$temp/apt/lists" -o Dir::State::status=/dev/null -o "Dir::Cache=$temp/apt/cache" \
      -o Debug::NoLocking=1 -o "APT::Sandbox::User=$(id -un)" -o APT::Update::Error-Mode=any update > "$temp/apt.log" 2>&1
  }
  if apt_update; then fail 'original keyring accepted a subkey-only index; the co-signature would be unnecessary'; fi
  gpg --homedir "$owner" --batch --yes --pinentry-mode loopback --passphrase 'owner pass' --local-user "$primary!" --local-user "$subkey!" --clearsign --output "$apt_site/dists/stable/InRelease" "$apt_site/dists/stable/Release"
  apt_update || { cat "$temp/apt.log" >&2; fail 'real APT with the original keyring rejected the primary co-signature'; }
fi

# ---- a second run is a no-op: no new secrets, keys, PRs, releases or pushes
writes=$(state '.secret_writes')
prs=$(state '.prs | length')
runs=$(state '.runs | length')
keys=$(state '.deploy_keys | length')
site_head=$(git --git-dir "$repos/jasonachkar__homebrew-lasa.git" rev-parse main)
printf 'owner pass\n' | setup --yes > "$temp/rerun.log" 2>&1 || { cat "$temp/rerun.log" >&2; fail 'rerun failed'; }
[ "$(state '.secret_writes')" = "$writes" ] || fail 'rerun rewrote secrets'
[ "$(state '.prs | length')" = "$prs" ] || fail 'rerun opened PRs'
[ "$(state '.runs | length')" = "$runs" ] || fail 'rerun started a release'
[ "$(state '.deploy_keys | length')" = "$keys" ] || fail 'rerun changed deploy keys'
[ "$(git --git-dir "$repos/jasonachkar__homebrew-lasa.git" rev-parse main)" = "$site_head" ] || fail 'rerun pushed the site'
grep -q 'Reusing subkey' "$temp/rerun.log" || fail 'rerun did not reuse the subkey'

# ---- --rotate replaces the subkey and deploy key, and ships the new subkey
printf 'owner pass\n' | setup --yes --rotate --skip-release > "$temp/rotate.log" 2>&1 || { cat "$temp/rotate.log" >&2; fail 'rotation failed'; }
rotated=$(state '.vars.APT_SIGNING_SUBKEY_FINGERPRINT')
[ "$rotated" != "$subkey" ] || fail 'rotation kept the old subkey'
git --git-dir "$repos/jasonachkar__lasa.git" show main:deploy/apt/lasa-archive-keyring.asc > "$temp/rotated-keyring.asc"
bash "$root/scripts/release/check-keyring.sh" "$temp/rotated-keyring.asc" "$primary" "$rotated"
[ "$(state '[.deploy_keys[] | select(.title == "LASA release automation")] | length')" = 1 ] || fail 'rotation left stale deploy keys'
echo 'PASS: owner setup stores only the signing subkey, verifies owner approval, preserves unrelated keys, ships the keyring and co-signs the approved first release. Rerun and rotation passed.'
