# Publishing packages from a Mac

[Maintainer index](README.md) · [Licensing](distribution.md) · [Customer installation](../customer/installation.md)

## Provision the package repository

Run `bash scripts/bootstrap-distribution.sh` with GitHub CLI, GnuPG, jq and SSH tools already installed and GitHub CLI signed in. The source defaults to `jasonachkar/lasa` and the distribution to `jasonachkar/homebrew-lasa`. Setup checks GitHub access, configures the dedicated Pages repository and scopes publishing credentials to the existing `release` environment. Initial provisioning can create the public distribution repository and its single write deploy key. Existing signing and deploy credentials are preserved. `--configure-domain` additionally enables the custom domain through the DNS provider. Provisioning performs no tag creation or workflow dispatch.

Review the GitHub configuration and package publishing decision using [repository security](repository-security.md) before authorizing a production release. The public Homebrew formula references GitHub Release downloads. Consumers therefore require a public source release or a separately designed public artifact repository. GitHub artifact attestations for private repositories require Enterprise Cloud.

## Artifacts and pipeline

`scripts/package-release.sh` creates one `.deb` and one archive for each Linux architecture, with `/usr/bin/lasa` in the DEB and `bin/lasa` in the archive. The packages include licenses, third-party notices and customer documentation; DEBs also carry systemd examples with `/usr/bin/lasa` paths. They do not create users, install active units, start services or scan during installation. DEBs contain no maintainer scripts. The static binary requires no Go runtime or libc package dependency.

`VERSION=0.0.0 make packages` builds local verification packages and needs Linux, the project's pinned Go and SBOM tools, GNU tar/gzip and `dpkg-deb`. Packages and archives normalize timestamps and ownership using the tagged commit's timestamp. Reports, local state and maintainer documents are not included. Customer Markdown is provided as reference files; the online documentation provides the complete navigation links.

The GitHub-hosted build job receives no publishing credentials. It requires an existing stable version tag identifying the exact dispatched `main` commit and a successful canonical CI push run for that commit. It creates both architecture packages, archives, SBOMs and a checksum manifest with an exact asset inventory. Publishing jobs verify the same-run artifact and the signed manifest from the expected GitHub-hosted workflow, default branch and source SHA. Existing drafts may resume by uploading missing files after digest checks. Published release assets must match the verified manifest.

The distribution job verifies downloaded asset checksums and the provenance identity before using its environment credentials to sign APT metadata. It obtains GitHub SSH host keys over HTTPS and authenticates the dedicated destination repository with its scoped SSH key.

`scripts/publish-distribution.sh` retains earlier DEBs, indexes both architectures under `apt/dists/stable/main`, emits compressed indexes and SHA-256/SHA-512 by-hash copies, computes Release checksums and signs `InRelease` and `Release.gpg`. It writes the public key and expected fingerprint, a key-pinning APT installer and an architecture-specific Homebrew formula with exact archive hashes. Source repo scripts validate the generated inputs; no arbitrary website URL or shell fragment is evaluated from repository variables.

All destination files are published in one Git commit. Older version publication is rejected if the tap already advertises a newer version; a same-version DEB with different bytes is rejected. The workflow serializes distribution jobs and never force-pushes. A push made with the SSH deploy key triggers GitHub Pages' branch build, unlike a cross-repository push with the source's `GITHUB_TOKEN`. Publication succeeds only after Pages serves the exact new signed `InRelease`; a cache/build delay beyond the timeout fails with the destination Actions link.

## Trust and storage

| Item | Location | Purpose |
| --- | --- | --- |
| `APT_SIGNING_KEY` | Source `release` environment Actions secret | ASCII-armored private package-signing key |
| `DISTRIBUTION_DEPLOY_KEY` | Source `release` environment Actions secret | Private SSH key for destination writes |
| `APT_SIGNING_FINGERPRINT` | Source Actions variable | Expected primary OpenPGP identity |
| `DISTRIBUTION_REPOSITORY` | Source Actions variable | Destination `OWNER/REPO` |
| `DISTRIBUTION_BRANCH` | Source Actions variable | Destination default branch |
| `APT_REPOSITORY_URL` | Source Actions variable | HTTPS APT URL, normally `https://lasa.secureobs.com/apt` |
| `DOCS_SITE_URL` | Source Actions variable | Effective HTTPS documentation site root |
| Signing/deploy keys and fingerprint | Mac: `~/Library/Application Support/lasa-distribution/OWNER_REPO/`; Linux: `${XDG_STATE_HOME:-~/.local/state}/lasa-distribution/OWNER_REPO/` | Stable local publishing identity |
| DEBs, APT indexes, public key, formula, installer | Public distribution Git repository and Pages | Customer downloads and verification |
| Binaries, notices, SBOMs, hashes, attestations | Source GitHub Releases / attestation service | Versioned immutable distribution |

Local key directories use `0700`, private files `0600` or more restrictive permissions. Private material never enters either Git repository. Back up the local state through your existing encrypted backup system; this script cannot arrange an independent safe backup destination. If GitHub already has signing secrets but local state is missing, setup stops instead of silently rotating identities and breaking installed clients. Restore the original state before rerunning. Compromise of the source repository's Actions administrators can compromise package signing, so restrict repository administration and release environments appropriately.

APT trusts the configured signing key and package/index checksums, while Homebrew pins archive SHA-256 hashes. A freshly downloaded installer and key originate from the same HTTPS site; the initial trust decision is in that site and the reviewed installer. Compare its fingerprint against your independently supplied release channel where your deployment policy requires it. Nothing uses `apt-key` or disables signature checks.

APT metadata can include a signed `Valid-Until` field by setting the Actions variable `APT_VALIDITY_DAYS` to a value from 1 through 90. Enable it only after establishing and testing a signed metadata refresh before expiry and alerting on refresh failure. By default the field is omitted so low-frequency repositories keep working. An attacker with control of a mirror could replay older signed metadata in that default mode. The existing signing key is long-lived and unattended. Key revocation and rotation require distributing a replacement trust anchor to installed clients.

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

Start from the protected, tested commit at the tip of `main`. Use `bash scripts/next-version.sh HEAD` to suggest a semantic version from reachable tags, then check the complete remote tag inventory for reservations before selecting a new stable tag. Create the selected tag through the owner account, binding it to the exact tested commit. Existing version tags are immutable.

The first dispatch below builds and verifies artifacts without publishing. The second dispatch authorizes production publishing and is a separate operator action. Run it only from the same tested main commit and after approving the binary release gate.

```sh
gh workflow run release.yml -R jasonachkar/lasa --ref main -f tag=vX.Y.Z -F publish=false
gh workflow run release.yml -R jasonachkar/lasa --ref main -f tag=vX.Y.Z -F publish=true
```

If publishing was interrupted, rerun failed jobs for the original run while its artifacts are available. If artifacts expired, rerun all jobs from the original run to regenerate them at the same SHA. GitHub refuses replacement of published assets and the workflow compares the recorded digests before proceeding. If a draft contains different bytes, stop and review the draft. The workflow never clobbers asset names or moves a tag. Read deployment controls independently after changing account or repository settings.

For local package validation use `VERSION=0.0.0 make packages` and `VERSION=0.0.0 bash test/distribution.sh` on Linux. These commands create disposable fixture artifacts, test a local APT repository with a throwaway key, and require no publishing credentials.

## Customer website and documentation versions

The website uses pinned MkDocs 1.6.1, Material 9.7.7 and Mike 2.2.0, with all Python dependencies pinned in `requirements-docs.txt`. `mkdocs.yml` enables local search, mobile navigation, light/dark modes and a release version selector. Fonts are served through the browser's system font stack; no analytics, remote font CDN or account login is included.

`scripts/prepare-docs.py` copies an explicit allowlist: `docs/customer/*.md`, `docs/website/`, public schemas and systemd examples. It never copies `docs/maintainer/` or the root README, and rejects unresolved maintainer links. This prevents accidental publication through this build; it does not make a public Git source repository private. The website contains collection/source paths, exclusions, storage/permissions, reports, all CLI operations, installation/updates, compatibility, troubleshooting and the current SecureObs export boundary.

On a verified release, the distribution job builds the docs in strict mode and uses Mike to publish `/VERSION/`, update the `latest` redirect and generate `versions.json`. The domain root redirects to `latest`. Earlier release documentation is retained. Mike preserves the destination's APT pool, formula, CNAME and other release content; integration tests verify this using actual Git trees. Documentation changes flow through the same verified release authorization. An exact served version index and per-version source/content build marker must match before deployment is reported successful.

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

`test/docs.sh` checks strict builds, customer-only content, local search and real multi-version deployments preserving the package repository. `test/domain.sh` tests GoDaddy/Pages creation, reuse, conflicting DNS and API denial through mocked external boundaries. `test/bootstrap-distribution.sh` uses real signing/deploy keys with mocked GitHub APIs; CI runs it and domain/version tests using macOS's system Bash. These tests do not prove that your accounts permit a live deployment; the bootstrap/live workflows provide that final evidence.
