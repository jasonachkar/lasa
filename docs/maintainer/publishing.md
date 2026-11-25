# Publishing LASA releases

[Maintainer index](README.md) · [Licensing](distribution.md) · [Customer installation](../customer/installation.md)

## Provision the package repository

Run `bash scripts/bootstrap-distribution.sh` from macOS or Linux with GitHub CLI, GnuPG, and jq installed. The source defaults to `jasonachkar/lasa` and the package site to `jasonachkar/homebrew-lasa`. Bootstrap creates or verifies the local APT signing identity, public package metadata, and Pages configuration. On a new machine, restore the original signing identity from the owner's backup. The first generation of a new signing key uses GnuPG pinentry. Add `--configure-domain` when provisioning the custom domain.

## Enable automated publishing

After the publishing workflow is on `main`, run this from that checkout on the machine holding the primary APT key. Sign in to `gh` as the repository owner first.

```bash
bash scripts/setup-ci-publishing.sh
```

The script verifies the protected `release` environment, asks for the APT key passphrase, generates a dedicated signing subkey, and registers a deployment key for the package-site repository. It submits the public keyring update and first release as protected PRs and waits for the required checks. At the prompt, your authenticated owner session tags the tested commit and approves deployment. Run the same command again after a recoverable failure. Use `--rotate` to replace the CI signing subkey and deployment key, or `--skip-release` to configure publishing and defer the first release.

The first automated release carries the new public keyring in its DEBs. The setup script adds a primary-key signature to that release's APT index so existing clients can upgrade using their original keyring. Later releases use the CI subkey. A client that misses the first release may need to rerun the fingerprint-verifying installer at `https://lasa.secureobs.com/install-apt.sh` to refresh its keyring. Rotate the CI subkey before expiry and repeat the migration for the new subkey.

## Artifacts and pipeline

`scripts/package-release.sh` creates one `.deb` and one archive for each Linux architecture, with `/usr/bin/lasa` in the DEB and `bin/lasa` in the archive. The packages include licenses, third-party notices and customer documentation; DEBs also carry systemd examples with `/usr/bin/lasa` paths. They do not create users, install active units, start services or scan during installation. DEBs contain no maintainer scripts. The static binary requires no Go runtime or libc package dependency.

`VERSION=0.0.0 make packages` builds local verification packages and needs Linux, the project's pinned Go and SBOM tools, GNU tar/gzip and `dpkg-deb`. Packages and archives normalize timestamps and ownership using the tagged commit's timestamp. Reports, local state and maintainer documents are not included. Customer Markdown is provided as reference files; the online documentation provides the complete navigation links.

The GitHub-hosted build requires a new version in `CHANGELOG.md` and a successful canonical CI push run for that exact `main` commit. It builds both architectures, archives, SBOMs and a checksum manifest with read-only credentials. The owner creates the immutable version tag and approves the `release` environment. CI verifies the tag, attests the manifest, verifies the provenance and publishes the assets.

`scripts/publish-distribution.sh` retains prior DEB bytes, signs indexes for both architectures, and generates the key-pinning installer and the checksum-pinned Homebrew formula. The release workflow stages the packages and versioned docs together, pushes one fast-forward update and verifies the signed index and version list served by Pages.

## Trust and storage

| Item | Location | Purpose |
| --- | --- | --- |
| Owner's local GnuPG keyring | Mac: `~/Library/Application Support/lasa-distribution/OWNER_REPO/gnupg`. Linux: `${XDG_STATE_HOME:-~/.local/state}/lasa-distribution/OWNER_REPO/gnupg` | APT signing |
| `APT_SIGNING_FINGERPRINT` | Source Actions variable | Public pin for the expected OpenPGP key |
| `APT_SIGNING_SUBKEY_FINGERPRINT` | Source Actions variable | Public fingerprint of the dedicated CI signer |
| `APT_SIGNING_SUBKEY`, `DISTRIBUTION_DEPLOY_KEY` | Protected `release` environment secrets | Sign APT metadata and push the package site after owner approval |
| `DISTRIBUTION_REPOSITORY`, `DISTRIBUTION_BRANCH` | Source Actions variables | Public destination and branch |
| `APT_REPOSITORY_URL`, `DOCS_SITE_URL` | Source Actions variables | Public endpoint configuration |
| DEBs, APT indexes, public key, formula, installer | Public distribution Git repository and Pages | Customer downloads and verification |
| Binaries, notices, SBOMs, hashes, attestations | Source GitHub Releases and attestation service | Immutable release artifacts |

Keep the primary private key and an encrypted backup in owner-controlled storage. The environment gets only the dedicated signing subkey and the package-site deploy key. Protect access to the `release` environment and revoke or rotate either delegated credential if it is compromised.

APT trusts the configured signing key and package/index checksums, while Homebrew pins archive SHA-256 hashes. A freshly downloaded installer and key originate from the same HTTPS site; the initial trust decision is in that site and the reviewed installer. Compare its fingerprint against your independently supplied release channel where your deployment policy requires it. Nothing uses `apt-key` or disables signature checks.

APT metadata can include a signed `Valid-Until` field by setting the local environment variable `APT_VALIDITY_DAYS` to a value from 1 through 90. Enable it only after establishing and testing a signed metadata refresh before expiry and alerting on refresh failure. By default the field is omitted so low-frequency repositories keep working. An attacker with control of a mirror could replay older signed metadata in that default mode. Review the validity and protection of the local signing identity independently of index expiry. Key revocation and rotation require distributing a replacement trust anchor to installed clients.

GitHub Pages has site size, bandwidth and build limits. Packages and historical by-hash indexes are retained; this is suitable for the initial release stream, not an unlimited package CDN. Move the same signed APT layout to managed object storage before approaching the applicable Pages limits. No RPM/YUM repository, native macOS scanner, Windows MSI, WinGet manifest, paid licensing server or upstream distro/core formula review is provided by this automation.

## Customer commands after successful publishing

On Debian/Ubuntu:

```bash
curl --proto '=https' --tlsv1.2 -fsSLo install-lasa.sh https://lasa.secureobs.com/install-apt.sh
bash install-lasa.sh
# Subsequent updates use the ordinary OS package workflow:
sudo apt-get update
sudo apt-get install --only-upgrade lasa
```

The installer fetches the public key, verifies its primary fingerprint, installs a repository-specific keyring and `signed-by` source, then installs LASA. It may require sudo for package installation. It never starts a scan as root.

On a Linux machine with Homebrew:

```bash
brew install jasonachkar/lasa/lasa
brew upgrade lasa
```

That shorthand automatically uses the `jasonachkar/homebrew-lasa` tap. Homebrew running on macOS rejects the formula's Linux requirement. You can **publish** from a Mac; the scanner itself still needs a Linux kernel. WinGet is not configured because a native Windows Linux-kernel scanner would be misleading. WSL users can run the Linux APT installer inside their supported Linux distribution. Upstream APT distribution archives, Homebrew core and WinGet community listings each have review processes that cannot be guaranteed by a script; the independent repository/tap does not require their listing approval.

## Authorize a release from main

Update `CHANGELOG.md` under `## Unreleased`, then run `bash scripts/release/prepare.sh X.Y.Z 'release title'` in the release branch. Open a PR and merge it after the required checks pass. Once the `main` build passes, review the run and use the approval command in its build summary. For example, for run `123456789` and tag `vX.Y.Z`:

```bash
bash scripts/release/approve.sh 123456789 vX.Y.Z
```

The command validates the run and its changelog, creates the tag through your owner login, and approves deployment. To retry the version at the current tip of `main`:

```sh
gh workflow run release.yml --repo jasonachkar/lasa --ref main -f version=X.Y.Z
```

If `main` has advanced since the release commit, use **Re-run failed jobs** on the original release run to retry the exact source commit.

## Manual publication and recovery

With `PUBLISHING_PROVIDER=local`, the workflow stops after building and attesting. Create `vX.Y.Z` through the owner account on the exact successfully verified `main` commit used by the run. The version must already be in that commit's changelog. Wait for the attestation run to succeed and copy its numeric run ID from the Actions URL.

```sh
gh workflow run release.yml --repo jasonachkar/lasa --ref main -f version=X.Y.Z
```

Publish from an owner-controlled Linux environment with Bash, GitHub CLI, GnuPG, jq, `apt-utils`, `dpkg-dev`, and the pinned docs dependencies installed. From a clean checkout at the release tag, set the tag and run ID to the ones you just verified.

```bash
tag=vX.Y.Z
run_id=123456789
export GITHUB_REPOSITORY=jasonachkar/lasa GITHUB_REF=refs/heads/main
GITHUB_SHA=$(git rev-parse HEAD)
export GITHUB_SHA

run_info=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id")
jq -e --arg sha "$GITHUB_SHA" --arg repo "$GITHUB_REPOSITORY" '
  .head_sha == $sha and .head_repository.full_name == $repo and
  .head_branch == "main" and (.event == "workflow_dispatch" or .event == "push") and
  .path == ".github/workflows/release.yml" and .conclusion == "success"
' <<< "$run_info"
GITHUB_EVENT_NAME=$(jq -er .event <<< "$run_info")
export GITHUB_EVENT_NAME
attempt=$(jq -er .run_attempt <<< "$run_info")
assets=$(mktemp -d)
gh run download "$run_id" --repo "$GITHUB_REPOSITORY" \
  --name "release-assets-$attempt" --dir "$assets"
bash scripts/security/verify-release-source.sh "$tag"
python3 scripts/security/verify-release-assets.py "$assets" "${tag#v}"
bash scripts/security/verify-release-attestation.sh "$assets/SHA256SUMS"
```

Run the remaining commands only after those checks pass. Point `GNUPGHOME` at the restored local signing keyring and configure Git to authenticate as the owner. Check the configured fingerprint against your local record.

```bash
APT_SIGNING_FINGERPRINT=$(gh variable get APT_SIGNING_FINGERPRINT --repo "$GITHUB_REPOSITORY")
export APT_SIGNING_FINGERPRINT
site=$(mktemp -d)
git clone --branch main https://github.com/jasonachkar/homebrew-lasa.git "$site"
bash scripts/publish-distribution.sh "$site" "$assets" "${tag#v}" \
  "$GITHUB_REPOSITORY" https://lasa.secureobs.com/apt
git -C "$site" add .
git -C "$site" commit -m "Stage LASA $tag packages"
bash scripts/publish-docs.sh "$site" "${tag#v}"
```

Review the staged commits and confirm that the package and documentation trees match the intended release. Publish the immutable assets first, then push the package site from the owner's session.

```bash
bash scripts/security/publish-release-assets.sh "$tag" "$assets"
git -C "$site" push origin main:main
```

Check GitHub Pages for the new build. Compare served `/apt/dists/stable/InRelease` and `/versions.json` with the committed bytes before announcing availability. To resume an interrupted publication, reuse the same verified artifacts and review the published state. Existing release assets must match the manifest, and the package site only accepts a fast-forward push.

For local package validation use `VERSION=0.0.0 make packages` and `VERSION=0.0.0 bash test/distribution.sh` on Linux. These commands create disposable fixture artifacts, test a local APT repository with a throwaway key, and require no publishing credentials.

## Customer website and documentation versions

The website uses pinned MkDocs 1.6.1, Material 9.7.7 and Mike 2.2.0, with all Python dependencies pinned in `requirements-docs.txt`. `mkdocs.yml` enables local search, mobile navigation, light/dark modes and a release version selector. Fonts are served through the browser's system font stack; no analytics, remote font CDN or account login is included.

`scripts/prepare-docs.py` copies an explicit allowlist: `docs/customer/*.md`, `docs/website/`, public schemas and systemd examples. It never copies `docs/maintainer/` or the root README, and rejects unresolved maintainer links. This prevents accidental publication through this build; it does not make a public Git source repository private. The website contains collection/source paths, exclusions, storage/permissions, reports, all CLI operations, installation/updates, compatibility, troubleshooting and the current SecureObs export boundary.

For a verified release, `scripts/publish-docs.sh` builds the docs in strict mode and uses Mike to stage `/VERSION/`, update the `latest` and `current` redirects, and generate `versions.json`. The domain root redirects to `latest`. Earlier release documentation is retained. Integration tests use actual Git trees to check the APT pool, formula and CNAME through the update.

## GoDaddy custom domain authorization

The DNS provider must actually host the authoritative `secureobs.com` DNS zone. `scripts/configure-domain.sh` creates only the `lasa` CNAME pointing at the distribution owner's `OWNER.github.io`. It does not change nameservers or unrelated records, and refuses existing conflicting records rather than replacing a live site. It checks public CNAME resolution first, so a correctly configured record needs no further GoDaddy credentials.

For a new record, provide `GODADDY_API_KEY` and `GODADDY_API_SECRET` in the local environment or enter them at the script's masked terminal prompts. Production credentials come from [GoDaddy's developer account](https://developer.godaddy.com/keys); the repository cannot issue credentials on behalf of your account. GoDaddy can restrict DNS API access by account eligibility. HTTP 401/403 is reported explicitly with the account/access requirement; no browser automation bypass or unrelated DNS deletion is attempted. This one-time authorization cannot be supplied by an unauthenticated coding environment.

Credentials are used through a temporary `0600` header file inside a private directory, deleted on exit, and never stored in either repository or Actions. GitHub account authorization is independently needed for Pages configuration. The script associates the domain with Pages and waits up to 30 minutes for GitHub's certificate, then enables HTTPS enforcement. DNS propagation/certificate issuance can outlast that window; rerunning the same bootstrap retries without moving a tag or changing signing identity. No TLS checks are disabled. `--configure-only` can prepare the repositories/keys before domain access is available, but does not publish the requested custom-domain site.

To develop the site locally:

```bash
python3 -m venv .build/docs-venv
.build/docs-venv/bin/pip install --require-hashes --only-binary=:all: -r requirements-docs.txt
python3 scripts/prepare-docs.py
.build/docs-venv/bin/mkdocs build --strict
# With the virtual environment activated:
bash test/docs.sh
```

`test/docs.sh` checks strict builds, customer-only content, local search and real multi-version deployments preserving the package repository. `test/domain.sh` tests GoDaddy/Pages creation, reuse, conflicting DNS and API denial through mocked external boundaries. `test/bootstrap-distribution.sh` uses a real fixture signing key with mocked GitHub APIs; CI runs it and domain/version tests using macOS's system Bash. These tests do not prove that your accounts permit a live deployment; the bootstrap/live workflows provide that final evidence.
