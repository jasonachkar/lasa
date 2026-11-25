#!/usr/bin/env bash
# One-time (and re-runnable) owner setup for fully automated LASA releases.
#
# Run it on the machine that holds the LASA APT signing key, from a checkout
# of jasonachkar/lasa:
#
#   bash scripts/setup-ci-publishing.sh            # set up, or resume where it stopped
#   bash scripts/setup-ci-publishing.sh --rotate   # replace the CI subkey and deploy key
#
# What it does (every step is skipped when already done):
#   1. Adds a signing SUBKEY to the APT key. Only that subkey, without a
#      passphrase, is stored as the `release` environment secret
#      APT_SIGNING_SUBKEY. The primary private key never leaves this machine.
#   2. Creates a write deploy key for the distribution repository and stores
#      its private half as the `release` environment secret
#      DISTRIBUTION_DEPLOY_KEY.
#   3. Lets that deploy key push the package site (force pushes and deletion
#      stay blocked). The owner retains the release tag authority.
#   4. Sets the public repository variables the release workflow reads.
#   5. Opens a PR adding the subkey to the packaged APT keyring and
#      auto-merges it once every required check passes.
#   6. Runs the first automated release through a release PR. After you
#      confirm, your local owner session tags the commit and approves it.
#   7. Co-signs that release's APT index with the primary key, so machines
#      installed with the older keyring upgrade into the new one.
#
# Requires: bash, gh (logged in as the repository owner), GnuPG, git, jq,
# ssh-keygen, curl. Compatible with macOS's system Bash 3.2.
set -euo pipefail
umask 077

repo=jasonachkar/lasa
site_url=${SETUP_SERVED_SITE_URL-https://lasa.secureobs.com/}
poll=${SETUP_POLL_SECONDS:-30}
rotate=false
assume_yes=false
skip_release=false
usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --rotate) rotate=true;;
    --yes) assume_yes=true;;
    --skip-release) skip_release=true;;
    --repo) [ "$#" -ge 2 ] || { echo '--repo needs OWNER/REPO' >&2; exit 1; }; repo=$2; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown argument: $1 (see --help)" >&2; exit 1;;
  esac
  shift
done

stage=initialization
trap 'printf "\nSetup stopped during: %s (line %s). Fix the error above and run the same command again; finished steps are skipped.\n" "$stage" "$LINENO" >&2' ERR
say() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
confirm() {
  if $assume_yes; then return 0; fi
  printf '%s [y/N] ' "$1"
  read -r answer || answer=
  case $answer in y|Y|yes|YES) return 0;; *) return 1;; esac
}
wait_until() { # wait_until DESCRIPTION MAX_MINUTES COMMAND...
  local description=$1 minutes=$2 deadline
  shift 2
  deadline=$(( $(date +%s) + minutes * 60 ))
  until "$@"; do
    [ "$(date +%s)" -lt "$deadline" ] || die "Timed out after $minutes minutes waiting for $description"
    info "Waiting for $description..."
    sleep "$poll"
  done
}

# ---------------------------------------------------------------- preflight
stage='checking tools and GitHub access'
say 'Checking prerequisites'
for tool in gh gpg gpg-connect-agent git jq ssh-keygen curl; do
  command -v "$tool" >/dev/null || die "Missing tool: $tool"
done
[[ $repo =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ ]] || die "Invalid repository: $repo"
gh auth status --hostname github.com >/dev/null 2>&1 || die 'Log in first: gh auth login'
owner=$(gh api "repos/$repo" --jq .owner.login)
login=$(gh api user --jq .login)
[ "$login" = "$owner" ] || die "GitHub CLI is logged in as $login; log in as the repository owner $owner"
distribution=$(gh variable get DISTRIBUTION_REPOSITORY --repo "$repo")
branch=$(gh variable get DISTRIBUTION_BRANCH --repo "$repo")
primary=$(gh variable get APT_SIGNING_FINGERPRINT --repo "$repo")
[[ $distribution =~ ^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+$ && -n $branch ]] || die 'DISTRIBUTION_REPOSITORY / DISTRIBUTION_BRANCH variables are missing; run scripts/bootstrap-distribution.sh first'
[[ $primary =~ ^[A-F0-9]{40}$ ]] || die 'APT_SIGNING_FINGERPRINT variable is missing or invalid'
pinned=$(gh api "repos/$repo/contents/deploy/apt/primary-fingerprint?ref=main" -H 'Accept: application/vnd.github.raw')
[ "$pinned" = "$primary" ] || die "The fingerprint pinned on main ($pinned) differs from APT_SIGNING_FINGERPRINT ($primary)"
info "Repository $repo, package site $distribution ($branch), APT key $primary"

# Verify the controls that keep credentials away from PRs and require approval
# before the release job can use them. A failed preflight never changes settings.
policy=$(gh api "repos/$repo/environments/release")
if ! jq -e --arg owner "$owner" '
  .can_admins_bypass == false and
  .deployment_branch_policy == {protected_branches: false, custom_branch_policies: true} and
  ([.protection_rules[] | select(.type == "required_reviewers") |
    {prevent_self_review, reviewers: [.reviewers[] | {type, login: .reviewer.login}]}] ==
    [{prevent_self_review: false, reviewers: [{type: "User", login: $owner}]}])' <<< "$policy" >/dev/null; then
  die 'The release environment must require the owner as its sole reviewer and disable bypasses'
fi
policies=$(gh api "repos/$repo/environments/release/deployment-branch-policies")
jq -e '[.branch_policies[] | {name, type}] == [{name: "main", type: "branch"}]' <<< "$policies" >/dev/null ||
  die 'The release environment must allow deployments only from main'
title='LASA release automation'
keys=$(gh api "repos/$distribution/keys" --paginate --slurp)
jq -e --arg name "$title" 'all(.[][]; .read_only or .title == $name)' <<< "$keys" >/dev/null ||
  die 'The package site has an unrelated writable deploy key; review it before enabling publishing'

work=$(mktemp -d /tmp/lasa-ci.XXXXXX)
cleanup() {
  for home in "$work"/gnupg-*; do
    if [ -d "$home" ]; then
      gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true
    fi
  done
  rm -rf "$work"
}
trap cleanup EXIT

stage='locating the APT signing key'
# Same keyring the distribution bootstrap uses; honour an explicit GNUPGHOME.
if [ -z "${GNUPGHOME:-}" ]; then
  case "$(uname -s)" in
    Darwin) state="$HOME/Library/Application Support/lasa-distribution/${repo//\//_}/gnupg";;
    *) state="${XDG_STATE_HOME:-$HOME/.local/state}/lasa-distribution/${repo//\//_}/gnupg";;
  esac
  if [ -d "$state" ]; then
    # GnuPG socket paths have a short OS limit; use a short alias.
    ln -s "$state" "$work/keyring"
    export GNUPGHOME="$work/keyring"
  fi
fi
secret=$(gpg --batch --with-colons --with-keygrip --fixed-list-mode --list-secret-keys "$primary" 2>/dev/null || true)
[ -n "$secret" ] || die "The private APT key $primary is not in ${GNUPGHOME:-~/.gnupg}. Run this on the machine that holds it, or set GNUPGHOME to its keyring."
primary_state=$(printf '%s\n' "$secret" | awk -F: '$1=="sec"{print $15; exit}')
[ "$primary_state" != '#' ] || die "Only a stub of primary key $primary is in this keyring; use the keyring that holds the private primary key."
info "Found the private primary key in ${GNUPGHOME:-~/.gnupg}"

printf '    Passphrase of the APT signing key (press Enter if it has none): '
IFS= read -rs passphrase || passphrase=
printf '\n'
# Passphrases travel through a file descriptor, never through argv.
gpg_unlocked() { gpg --batch --pinentry-mode loopback --passphrase-fd 3 "$@" 3< <(printf '%s' "$passphrase"); }
# GnuPG can sign using an unlocked key even when the supplied passphrase is
# wrong. Check the supplied value before creating keys or changing GitHub.
keygrip=$(printf '%s\n' "$secret" | awk -F: '$1=="grp"{print $10; exit}')
[[ $keygrip =~ ^[A-F0-9]{40}$ ]] || die 'Could not identify the primary keygrip'
[ "$(gpg-connect-agent "CLEAR_PASSPHRASE --mode=normal $keygrip" /bye)" = OK ] || die 'Could not clear the cached primary-key passphrase'
printf 'check\n' | gpg_unlocked --local-user "$primary!" --clearsign > /dev/null 2>&1 || die 'That passphrase does not unlock the APT signing key'

# ------------------------------------------------------- 1. signing subkey
stage='creating the CI signing subkey'
say 'CI signing subkey'
list_signing_subkeys() { # fingerprint:validity:expiry, newest last
  gpg --batch --with-colons --fixed-list-mode --list-keys "$primary" |
    awk -F: '$1=="sub"{v=$2;e=$7;c=$12;s=1;next} s&&$1=="fpr"{if (c ~ /s/) print $10":"v":"e; s=0}'
}
secret_names=$(gh secret list --env release --repo "$repo" --json name --jq '.[].name')
has_secret() { printf '%s\n' "$secret_names" | grep -qx "$1"; }
subkey=$(gh variable get APT_SIGNING_SUBKEY_FINGERPRINT --repo "$repo" 2>/dev/null || true)
reuse=false
if [ -n "$subkey" ] && ! $rotate && has_secret APT_SIGNING_SUBKEY; then
  record=$(list_signing_subkeys | grep "^$subkey:" || true)
  if [ -n "$record" ]; then
    validity=$(printf '%s' "$record" | cut -d: -f2)
    expiry=$(printf '%s' "$record" | cut -d: -f3)
    case $validity in r|e|i|n|d) ;; *)
      if [ -z "$expiry" ] || [ "$expiry" -gt $(( $(date +%s) + 120 * 86400 )) ]; then reuse=true; fi;;
    esac
  fi
fi
if $reuse; then
  info "Reusing subkey $subkey (already stored in the release environment)"
else
  before=$(list_signing_subkeys | cut -d: -f1)
  gpg_unlocked --quick-add-key "$primary" rsa3072 sign 2y
  subkey=$(list_signing_subkeys | cut -d: -f1 | grep -vxF "$before" | tail -n 1 || true)
  [[ $subkey =~ ^[A-F0-9]{40}$ ]] || die 'Could not identify the new signing subkey'
  info "Created signing subkey $subkey (expires in 2 years)"

  # Export only that subkey, then remove its passphrase in a scratch keyring.
  export_home="$work/gnupg-export"
  mkdir -m 0700 "$export_home"
  gpg_unlocked --armor --export-secret-subkeys "$subkey!" > "$work/protected.asc"
  gpg --homedir "$export_home" --batch --quiet --pinentry-mode loopback --passphrase-fd 3 --import "$work/protected.asc" 3< <(printf '%s' "$passphrase") 2>/dev/null
  rm -f "$work/protected.asc"
  index=$(gpg --homedir "$export_home" --batch --with-colons --fixed-list-mode --list-keys "$primary" |
    awk -F: -v want="$subkey" '$1=="sub"{n++; s=1; next} s&&$1=="fpr"{if ($10==want) print n; s=0}')
  [ -n "$index" ] || die 'The exported subkey is missing from the scratch keyring'
  if [ -n "$passphrase" ]; then
    printf 'key %s\npasswd\n%s\n\n\nsave\n' "$index" "$passphrase" |
      gpg --homedir "$export_home" --batch --pinentry-mode loopback --command-fd 0 --status-fd 1 --edit-key "$primary" > /dev/null 2>&1 || true
  fi
  gpg --homedir "$export_home" --batch --armor --export-secret-subkeys "$subkey!" > "$work/ci-subkey.asc"

  # Prove the exact bytes CI receives: stub primary, unattended subkey signing.
  verify_home="$work/gnupg-verify"
  mkdir -m 0700 "$verify_home"
  gpg --homedir "$verify_home" --batch --quiet --import "$work/ci-subkey.asc" 2>/dev/null
  check=$(gpg --homedir "$verify_home" --batch --with-colons --fixed-list-mode --list-secret-keys)
  [ "$(printf '%s\n' "$check" | awk -F: '$1=="sec"{print $15; exit}')" = '#' ] || die 'The CI export unexpectedly contains the primary private key; nothing was uploaded'
  printf 'check\n' | gpg --homedir "$verify_home" --batch --pinentry-mode error --local-user "$subkey!" --clearsign > "$work/check.asc" 2>/dev/null ||
    die 'The exported subkey still needs a passphrase; nothing was uploaded'
  gpg --homedir "$verify_home" --batch --status-fd 1 --verify "$work/check.asc" 2>/dev/null | grep -q "VALIDSIG $subkey " ||
    die 'The exported subkey did not produce a valid signature; nothing was uploaded'

  gh secret set APT_SIGNING_SUBKEY --env release --repo "$repo" < "$work/ci-subkey.asc"
  rm -f "$work/ci-subkey.asc"
  gh variable set APT_SIGNING_SUBKEY_FINGERPRINT --repo "$repo" --body "$subkey"
  info 'Stored the subkey (only) as release-environment secret APT_SIGNING_SUBKEY'
fi

# ------------------------------------------------------- 2. deploy key
stage='creating the distribution deploy key'
say 'Distribution deploy key'
deploy_ids=$(gh api "repos/$distribution/keys" --jq ".[] | select(.title == \"$title\") | .id")
deploy_writable=$(gh api "repos/$distribution/keys" --jq "[.[] | select(.title == \"$title\" and .read_only == false)] | length")
if ! $rotate && has_secret DISTRIBUTION_DEPLOY_KEY && [ "$deploy_writable" = 1 ]; then
  info 'Reusing the existing deploy key'
else
  for id in $deploy_ids; do gh api --method DELETE "repos/$distribution/keys/$id" >/dev/null; done
  ssh-keygen -q -t ed25519 -N '' -C "$title" -f "$work/deploy-key"
  gh api --method POST "repos/$distribution/keys" -f title="$title" -f key="$(cat "$work/deploy-key.pub")" -F read_only=false --jq .id >/dev/null
  gh secret set DISTRIBUTION_DEPLOY_KEY --env release --repo "$repo" < "$work/deploy-key"
  rm -f "$work/deploy-key" "$work/deploy-key.pub"
  info "Added a write deploy key to $distribution and stored it as DISTRIBUTION_DEPLOY_KEY"
fi

# ------------------------------------------------------- 3. rulesets
stage='updating repository rulesets'
say 'Repository rulesets'
site_rule=$(gh api "repos/$distribution/rulesets" --jq '.[] | select(.name == "LASA owner-only branch writes") | .id')
[[ $site_rule =~ ^[0-9]+$ ]] || die "Could not identify the package site's branch write ruleset"
rule_api="repos/$distribution/rulesets/$site_rule"
current=$(gh api "$rule_api")
if jq -e '.bypass_actors | any(.actor_type == "DeployKey" and .bypass_mode == "always")' <<< "$current" >/dev/null; then
  info 'Deploy key pushes the package site: already allowed'
else
  updated=$(jq '{name, target, enforcement, conditions, rules,
    bypass_actors: (.bypass_actors + [{actor_type: "DeployKey", actor_id: null, bypass_mode: "always"}])}' <<< "$current")
  # Preserve the API response on failure so GitHub's specific validation error
  # is visible. The separate distribution integrity ruleset still applies.
  if ! result=$(gh api --method PUT "$rule_api" --input - <<< "$updated" 2>&1); then
    printf '%s\n' "$result" >&2
    die "GitHub rejected the deploy-key update for $distribution's branch write ruleset"
  fi
  info 'Deploy key pushes the package site: allowed'
fi

# ------------------------------------------------------- 4. variables
stage='setting repository variables'
say 'Repository variables'
gh variable set APT_REPOSITORY_URL --repo "$repo" --body 'https://lasa.secureobs.com/apt'
gh variable set DOCS_SITE_URL --repo "$repo" --body 'https://lasa.secureobs.com/'
info 'APT_REPOSITORY_URL and DOCS_SITE_URL point at lasa.secureobs.com'

# ------------------------------------------------------- 5. packaged keyring
stage='adding the subkey to the packaged keyring'
say 'Packaged APT keyring'
keyring_has_subkey() {
  gh api "repos/$repo/contents/deploy/apt/lasa-archive-keyring.asc?ref=main" -H 'Accept: application/vnd.github.raw' > "$work/main-keyring.asc"
  gpg --homedir "$work/gnupg-show" --batch --with-colons --fixed-list-mode --show-keys "$work/main-keyring.asc" 2>/dev/null |
    awk -F: '$1=="sub"{s=1;next} s&&$1=="fpr"{print $10; s=0}' | grep -qx "$subkey"
}
mkdir -m 0700 "$work/gnupg-show"
gh repo edit "$repo" --enable-auto-merge >/dev/null
if keyring_has_subkey; then
  info 'main already packages a keyring with the CI subkey'
else
  clone="$work/keyring-pr"
  gh repo clone "$repo" "$clone" -- --quiet --depth 1 --branch main
  pr_branch="ci/apt-keyring-${subkey:32:8}"
  existing=$(gh pr list --repo "$repo" --head "$pr_branch" --state open --json number --jq '.[0].number // empty')
  if [ -z "$existing" ]; then
    git -C "$clone" checkout --quiet -b "$pr_branch"
    gpg --batch --armor --export-options export-clean --export "$primary" > "$clone/deploy/apt/lasa-archive-keyring.asc"
    git -C "$clone" add deploy/apt/lasa-archive-keyring.asc
    git -C "$clone" -c user.name="$login" -c user.email="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')" \
      commit --quiet -m "Package the CI APT signing subkey ${subkey:32:8}" \
      -m 'Installed clients receive the subkey through the packaged keyring before CI-signed metadata relies on it.'
    git -C "$clone" push --quiet origin "$pr_branch"
    existing=$(gh pr create --repo "$repo" --base main --head "$pr_branch" \
      --title "Package the CI APT signing subkey ${subkey:32:8}" \
      --body "Adds signing subkey \`$subkey\` to \`deploy/apt/lasa-archive-keyring.asc\`. Generated by \`scripts/setup-ci-publishing.sh\`." | sed -n 's@.*/pull/\([0-9][0-9]*\).*@\1@p')
  fi
  gh pr merge "$existing" --repo "$repo" --auto --squash >/dev/null || true
  info "PR #$existing will merge automatically when its required checks pass"
  pr_merged() {
    state=$(gh pr view "$existing" --repo "$repo" --json state --jq .state)
    [ "$state" != CLOSED ] || die "PR #$existing was closed without merging; check its CI results"
    [ "$state" = MERGED ]
  }
  wait_until "PR #$existing (checks typically take 20-40 minutes)" 180 pr_merged
  info "PR #$existing merged"
fi
gh variable set PUBLISHING_PROVIDER --repo "$repo" --body github-actions
info 'Release workflow will now publish automatically after your approval'

# ------------------------------------------------------- 6. first release
served_signer() { # prints the fingerprint that signed the served InRelease
  curl --proto '=https' --tlsv1.2 -fsS "${site_url%/}/apt/dists/stable/InRelease" -o "$work/served-InRelease" 2>/dev/null || return 0
  gpg --batch --status-fd 1 --verify "$work/served-InRelease" 2>/dev/null | awk '$2=="VALIDSIG"{print $3}'
}
if $skip_release; then
  say 'Skipping the first automated release (--skip-release)'
else
  stage='publishing the first automated release'
  say 'First automated release'
  semver_sort() { sort -t. -k1,1n -k2,2n -k3,3n; }
  latest=$(gh api "repos/$repo/git/matching-refs/tags/v" --jq '.[].ref | ltrimstr("refs/tags/v")' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | semver_sort | tail -n 1)
  latest=${latest:-0.0.0}
  published=$(gh api "repos/$distribution/contents/apt/dists/stable/main/binary-amd64/Packages?ref=$branch" -H 'Accept: application/vnd.github.raw' 2>/dev/null |
    awk '/^Version:/{print $2}' | semver_sort | tail -n 1)
  tag_packages_subkey() {
    gh api "repos/$repo/contents/deploy/apt/lasa-archive-keyring.asc?ref=v$latest" -H 'Accept: application/vnd.github.raw' > "$work/tag-keyring.asc" 2>/dev/null || return 1
    gpg --homedir "$work/gnupg-show" --batch --with-colons --fixed-list-mode --show-keys "$work/tag-keyring.asc" 2>/dev/null |
      awk -F: '$1=="sub"{s=1;next} s&&$1=="fpr"{print $10; s=0}' | grep -qx "$subkey"
  }
  if [ "$published" = "$latest" ] && tag_packages_subkey; then
    info "APT already serves LASA $latest, which packages this subkey"
  else
    # Resume an earlier release PR for the next version, or open one.
    major=${latest%%.*}; rest=${latest#*.}; minor=${rest%%.*}; patch=${rest#*.}
    version="$major.$minor.$((patch + 1))"
    if tag_packages_subkey; then version=$latest; fi
    release_branch="release/v$version"
    pr=$(gh pr list --repo "$repo" --head "$release_branch" --state all --json number,state --jq '[.[] | select(.state != "CLOSED")][0].number // empty')
    if [ -z "$pr" ]; then
      [ "$version" != "$latest" ] || die "Resume the release workflow for v$latest before creating another release"
      clone="$work/release-pr"
      gh repo clone "$repo" "$clone" -- --quiet --depth 1 --branch main
      git -C "$clone" checkout --quiet -b "$release_branch"
      if ! grep -m 1 '^## ' "$clone/CHANGELOG.md" | grep -qx '## Unreleased'; then
        awk '!done && /^## /{print "## Unreleased\n\n- APT metadata is signed in CI by a dedicated signing subkey; packages carry the APT keyring.\n"; done=1} {print}' "$clone/CHANGELOG.md" > "$work/changelog"
        cat "$work/changelog" > "$clone/CHANGELOG.md"
      fi
      bash "$clone/scripts/release/prepare.sh" "$version" 'automated publishing' > /dev/null
      git -C "$clone" add CHANGELOG.md
      git -C "$clone" -c user.name="$login" -c user.email="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')" commit --quiet -m "Release $version"
      git -C "$clone" push --quiet origin "$release_branch"
      pr=$(gh pr create --repo "$repo" --base main --head "$release_branch" --title "Release $version" \
        --body "Merging publishes LASA $version through the release workflow. Generated by \`scripts/setup-ci-publishing.sh\`." | sed -n 's@.*/pull/\([0-9][0-9]*\).*@\1@p')
      [ -n "$pr" ] || die 'Could not open the release PR'
    fi
    gh pr merge "$pr" --repo "$repo" --auto --squash >/dev/null 2>&1 || true
    info "Release PR #$pr for LASA $version merges automatically when its checks pass"
    release_merged() {
      state=$(gh pr view "$pr" --repo "$repo" --json state --jq .state)
      [ "$state" != CLOSED ] || die "Release PR #$pr was closed without merging"
      [ "$state" = MERGED ]
    }
    wait_until "release PR #$pr (checks typically take 20-40 minutes)" 180 release_merged
    sha=$(gh pr view "$pr" --repo "$repo" --json mergeCommit --jq .mergeCommit.oid)
    run_id() { gh run list --repo "$repo" --workflow release.yml --commit "$sha" --event push --json databaseId --jq '.[0].databaseId // empty'; }
    run_exists() { [ -n "$(run_id)" ]; }
    wait_until 'the release workflow to start' 15 run_exists
    run=$(run_id)
    info "Release run: https://github.com/$repo/actions/runs/$run"
    run_field() { gh api "repos/$repo/actions/runs/$run" --jq ".$1"; }
    # An interrupted earlier attempt (for example an expired approval) is retried.
    if [ "$(run_field status)" = completed ] && [ "$(run_field conclusion)" != success ]; then
      info 'Retrying the failed jobs of the earlier release run'
      gh run rerun "$run" --repo "$repo" --failed
      sleep "$poll"
    fi
    if [ "$(run_field status)" != completed ]; then
      awaiting_approval() {
        [ "$(run_field status)" != completed ] || return 0
        [ "$(gh api "repos/$repo/actions/runs/$run/pending_deployments" --jq 'length')" != 0 ]
      }
      wait_until 'the release build (it waits for CI, then builds; about 30-60 minutes)' 240 awaiting_approval
      if [ "$(run_field status)" != completed ]; then
        if confirm "Tag and approve LASA $version for GitHub Releases, APT and lasa.secureobs.com?"; then
          GITHUB_REPOSITORY="$repo" bash "$(dirname "$0")/release/approve.sh" "$run" "v$version"
        else
          die "Run this script again to tag and approve https://github.com/$repo/actions/runs/$run"
        fi
      fi
      run_done() { [ "$(run_field status)" = completed ]; }
      wait_until 'publication' 60 run_done
    fi
    [ "$(run_field conclusion)" = success ] || die "Publication failed: https://github.com/$repo/actions/runs/$run (fix it, then run this script again)"
    info "LASA $version is published"
  fi

  # ----------------------------------------------------- 7. co-sign
  stage='co-signing the APT index for older keyrings'
  say 'Co-signing the APT index with the primary key'
  site="$work/site"
  gh repo clone "$distribution" "$site" -- --quiet --branch "$branch"
  inrelease="$site/apt/dists/stable/InRelease"
  release="$site/apt/dists/stable/Release"
  status=$(gpg --batch --status-fd 1 --verify "$inrelease" 2>/dev/null || true)
  if printf '%s\n' "$status" | grep -q "VALIDSIG $primary "; then
    info 'The index is already signed by the primary key'
  else
    printf '%s\n' "$status" | grep -q "VALIDSIG $subkey " || die 'The published index is not signed by the CI subkey; refusing to co-sign it'
    gpg --batch --status-fd 1 --verify "$site/apt/dists/stable/Release.gpg" "$release" 2>/dev/null | grep -q "VALIDSIG $subkey " ||
      die 'Release and Release.gpg do not match; refusing to co-sign'
    # Machines installed before this setup trust only the primary key. They
    # need a primary signature to download the release carrying the new keyring.
    signers=(--local-user "$primary!" --local-user "$subkey!")
    gpg_unlocked --yes "${signers[@]}" --digest-algo SHA256 --clearsign --output "$inrelease" "$release"
    gpg_unlocked --yes "${signers[@]}" --digest-algo SHA256 --armor --detach-sign --output "$site/apt/dists/stable/Release.gpg" "$release"
    status=$(gpg --batch --status-fd 1 --verify "$inrelease" 2>/dev/null)
    for signer in "$primary" "$subkey"; do
      grep -Fq "VALIDSIG $signer " <<< "$status" || die 'Co-signature verification failed'
    done
    git -C "$site" add apt/dists/stable/InRelease apt/dists/stable/Release.gpg
    git -C "$site" -c user.name="$login" -c user.email="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')" \
      commit --quiet -m 'Sign the APT index with the primary key for clients upgrading from the original keyring'
    git -C "$site" push --quiet origin "HEAD:$branch"
    info 'Pushed the primary-key signature'
    if [ -n "$site_url" ]; then
      served_by_primary() { served_signer | grep -qx "$primary"; }
      wait_until 'GitHub Pages to serve the co-signed index' 20 served_by_primary
    fi
  fi
fi

stage='finished'
say 'Done'
info "Every release from now on: merge a release PR (bash scripts/release/prepare.sh X.Y.Z 'title'),"
info 'then use the build summary command to tag and approve it. CI builds, attests, publishes'
info 'the GitHub Release, signs and pushes APT/Homebrew, and deploys the documentation.'
info 'Machines installed before this setup pick up the new keyring with their next'
info "  sudo apt-get update && sudo apt-get install --only-upgrade lasa"
info 'If one ever reports NO_PUBKEY for the LASA repository, rerun the installer from lasa.secureobs.com.'
