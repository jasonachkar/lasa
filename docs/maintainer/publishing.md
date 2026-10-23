# Publishing packages from a Mac

[Maintainer index](README.md) · [Licensing](distribution.md) · [Customer installation](../customer/installation.md)

## GitHub Actions quota exhausted

Use [Azure publishing and website recovery](azure.md). `bash scripts/bootstrap-azure.sh` automates the private Azure project and pipeline setup for `jasonachkardiab`. `bash scripts/publish-docs-local.sh` immediately publishes MkDocs from your Mac without source Actions minutes. Both reuse the existing signing/deploy state; do not reset keys.

## One command

Run this from a clean checkout containing the publishing changes, after its commit has been pushed:

```bash
bash scripts/bootstrap-distribution.sh
```

The default source is `jasonachkar/lasa`; the generated public repository is `jasonachkar/homebrew-lasa`. The command creates a real release of the **current commit**, using an automatically calculated semantic version. Review that commit before running it. It does not merge your branch into main. You can publish a pushed feature commit because the tag-triggered workflow comes from the tagged commit.

No Linux computer, Docker, Go installation, hand-written workflow configuration, manually generated signing key, pasted access token, hand-created tag or manually uploaded package is needed on the Mac. Intel and Apple Silicon Macs use the same script, including Apple's Bash 3.2. Linux publishing runners do all compilation and indexing.

For a fresh local copy of this branch:

```bash
git clone --branch feature/lasa https://github.com/jasonachkar/lasa.git
cd lasa
bash scripts/bootstrap-distribution.sh
```

The branch name is only relevant before these changes are merged; afterwards a normal default-branch checkout works. Do not run setup from an older checkout without the updated scripts and workflow.

## What the command changes

1. Checks the checkout is clean and its commit is available on GitHub. Existing version tags must identify that exact commit.
2. Installs missing `gh`, `gpg` and `jq` tools. On macOS it finds Homebrew in either standard prefix and, when necessary, runs the official Homebrew installer at a pinned Git commit. On Debian/Ubuntu it uses the signed system APT repositories. Other Linux distributions must already provide the tools.
3. Uses an existing working GitHub login or starts GitHub CLI's browser sign-in with repository/workflow scopes. It never requests a token in chat or writes one into source.
4. Creates the public `homebrew-lasa` repository if absent. An existing private repository is rejected rather than made public. An incompatible Pages configuration is rejected rather than overwritten.
5. Generates a non-expiring RSA-3072 OpenPGP signing key for APT/RPM/Pacman, a separate RSA-3072 PEM key for Alpine and an Ed25519 SSH deploy key. The SSH key has write access only to the distribution repository. The APT private key has no passphrase so the runner can sign unattended; private material is protected by local filesystem permissions and GitHub's encrypted release-environment Actions secrets.
6. Sets source release-environment signing/deploy secrets and public repository/key-pin variables, the destination deploy key and branch-based GitHub Pages publishing. It creates the `release` environment only if missing and keeps secrets scoped to it. It does not change Actions allowlists, branch protections or existing environment approval rules.
7. Configures GoDaddy DNS and GitHub Pages HTTPS for `lasa.secureobs.com`, using local masked credential prompts when necessary. Creates the version tag via GitHub's API, waits for the release/package/documentation workflow and reports its result. A failed existing run can be retried without moving its tag.

Use `--configure-only` to configure repository publishing without DNS changes or tagging. Optional `--repo OWNER/REPO` and `--distribution-repo OWNER/REPO` override the defaults. The latter must be a dedicated public repository under an account you can administer. Full bootstrap configures the requested custom domain; configuration-only mode retains the standard GitHub Pages URL.

## Consent that software cannot supply

Your first GitHub login may require a browser confirmation and organization SSO approval. macOS may request an administrator password or Apple command-line-tools installation approval when Homebrew is absent. These are account/operating-system consent boundaries; the script cannot authorize them for you. Once consent is supplied, it continues the automated setup.

Existing protected deployment environments, organization policies, restricted Actions or Pages availability can also block publication. These controls are preserved. A pending deployment approval can keep `gh run watch` waiting; review the linked GitHub run when your repository requires that approval. A successful local configuration is not evidence of a successful release.

Cloud execution environments may supply Git HTTPS access without GitHub API access. In the environment used to build this change, Git reads/pushes work but API requests are denied by the proxy. Consequently live repository creation, secret installation and Pages publication must run under your own GitHub session on your Mac. They are not claimed as already completed.

## Artifacts and pipeline

`scripts/package-release.sh` creates one `.deb` and one archive for each Linux architecture, with `/usr/bin/lasa` in the DEB and `bin/lasa` in the archive. The packages include licenses, third-party notices and customer documentation; DEBs also carry systemd examples with `/usr/bin/lasa` paths. They do not create users, install active units, start services or scan during installation. DEBs contain no maintainer scripts. The static binary requires no Go runtime or libc package dependency.

`VERSION=0.0.0 make packages` builds local verification packages and needs Linux, the project's pinned Go and SBOM tools, GNU tar/gzip and `dpkg-deb`. Packages and archives normalize timestamps and ownership using the tagged commit's timestamp. Reports, local state and maintainer documents are not included. Customer Markdown is provided as reference files; the online documentation provides the complete navigation links.

The release workflow verifies tag/version consistency, runs the full standard checks and reproducible binary builds, then emits raw binaries, archives, DEBs, exact dependency notices, CycloneDX SBOMs and `SHA256SUMS`. GitHub's OIDC build provenance attests the artifacts and checksum manifest. Uploads happen to a draft release before publication. A retry of an already-published version downloads its existing assets instead of replacing them.

The distribution job verifies the published checksums and checksum manifest attestation, imports the APT signing secret into an ephemeral GnuPG home, obtains GitHub SSH host keys over authenticated HTTPS, then clones the destination through its scoped SSH key. No insecure SSH host-key bypass is used.

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

This implementation intentionally has no `Valid-Until` field or expiring signing key: an unattended low-frequency release repository remains installable between releases without a scheduled secret-bearing workflow. Its signatures establish origin/integrity, **not freshness**. A compromised mirror may replay older signed metadata. Installed APT versions normally do not downgrade automatically, but new installations lack that history. Environments requiring bounded freshness should add a scheduled re-signing workflow, short metadata expiry and alerting before adopting that policy. Key revocation/rotation requires distributing a replacement trust anchor to existing clients; it is not silently performed by bootstrap.

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

## Recovery and subsequent releases

Rerun the same command after resolving a transient network/API/Pages error. It reuses local keys and repository configuration, preserves the tag and reruns failed jobs. It refuses dirty source trees, conflicting version tags, different destination deploy keys and unexpected existing Pages configurations with a specific error. An older GitHub CLI or organization policy can reject an API operation; the reported setup stage and underlying command output identify the failing prerequisite.

SSH deploy keys are compared by algorithm and public key data; optional local/GitHub comments are ignored. A comment-only difference does not require key regeneration or secret deletion. A genuine key-data mismatch still stops without replacing either key.

After bootstrap, code changes pushed/merged to `main` trigger the automatic version workflow. No version constants or package manifests need manual edits. Source builds report `0.1.0-dev`; release builds inject the allocated version into the binary with Go linker flags. Bootstrap can also publish a clean pushed feature commit using the same version allocator. If a release published but its distribution job failed, the release assets remain available; rerun the script to repair distribution using those same assets.

For local verification, first run `VERSION=0.0.0 make packages`, then `VERSION=0.0.0 bash test/distribution.sh` on Linux with `dpkg-dev`, `apt-utils`, GnuPG and the build tools available. It exercises real DEB/archive creation, reproducibility, signed APT indexing, an isolated signature-checked APT update/download, installer key rejection and immutable-version/downgrade failures without changing the machine's trusted keys, installed packages or repositories.


## Automatic semantic versions

`scripts/next-version.sh` selects the highest stable `vMAJOR.MINOR.PATCH` tag reachable from the release commit. With no previous stable tag, the first version is `0.1.0`. A tag already identifying that commit is reused. Otherwise commit messages since the previous tag select the bump: `BREAKING CHANGE:` or a conventional `type!:` header increments major, `feat:`/`feat(scope):` increments minor, and everything else increments patch. A breaking change takes priority over features. Use conventional PR titles when squashing so the intended bump is retained.

`.github/workflows/version.yml` runs on scanner/build/distribution changes to `main` after publishing is configured. It serializes allocations, creates an immutable tag, then **calls** the reusable release workflow. This explicit call matters: tag pushes made with `GITHUB_TOKEN` do not trigger another workflow automatically. A failed allocated version is not silently reused for different code; gaps in published versions can occur. Documentation-only Markdown changes update the existing documentation release without creating a binary version.

`.github/workflows/release.yml` remains tag-triggerable for bootstrap/user-created tags. Its version is validated, passed through `VERSION`, embedded into both architecture binaries and used in package names, DEB metadata, SBOMs, formula URLs and documentation. The report schema remains independently versioned. Published release bytes are immutable; draft uploads are repairable. Package/tap and documentation rollback guards reject older versions becoming current.

## Customer website and documentation versions

The website uses pinned MkDocs 1.6.1, Material 9.7.7 and Mike 2.2.0, with all Python dependencies pinned in `requirements-docs.txt`. `mkdocs.yml` enables local search, mobile navigation, light/dark modes and a release version selector. Fonts are served through the browser's system font stack; no analytics, remote font CDN or account login is included.

`scripts/prepare-docs.py` copies an explicit allowlist: `docs/customer/*.md`, `docs/website/`, public schemas and systemd examples. It never copies `docs/maintainer/` or the root README, and rejects unresolved maintainer links. This prevents accidental publication through this build; it does not make a public Git source repository private. The website contains collection/source paths, exclusions, storage/permissions, reports, all CLI operations, installation/updates, compatibility, troubleshooting and the current SecureObs export boundary.

After packages publish, the reusable docs workflow builds in strict mode and uses Mike to publish `/VERSION/`, update the `latest` redirect and generate `versions.json`. The domain root redirects to `latest`. Earlier release documentation is retained. Mike preserves the destination's APT pool, formula, CNAME and other release content; integration tests verify this using actual Git trees. Documentation-only updates publish fixes to the current release. If scanner code changed since the last release, that release's workflow supplies the matching documentation instead. An exact served version index and per-version source/content build marker must match before deployment is reported successful.

## Repair an HTTP-only documentation site

Run `bash scripts/repair-docs-https.sh` from the owner's checkout. It uses your existing GitHub CLI login, installs missing `gh`/`jq` through Homebrew when needed, checks public DNS, and configures GitHub Pages HTTPS for `lasa.secureobs.com` in `jasonachkar/homebrew-lasa`. No scanner release, signing-key generation, Actions runner or Azure agent is involved. The normal `bash scripts/publish-docs-local.sh` command runs this repair before publishing, so one command applies HTTPS configuration and the website updates.

If a certificate already validates, the repair preserves the binding and enables HTTPS enforcement if needed. When HTTPS is disabled and certificate issuance is stalled, it requires a genuine TLS provisioning failure and a positive GitHub DNS/CAA eligibility result before briefly removing and restoring this same Pages custom-domain binding to request a fresh certificate. It waits for initially empty asynchronous DNS health responses. A private local timestamp limits this refresh to once per hour; reruns preserve an in-progress issuance request. The exit handler restores the domain if a rebind is interrupted. A subsequent run also restores an empty binding if a process was killed before cleanup could run. GitHub certificate issuance can still require time; the script prints progress instead of claiming that a configuration write proves successful deployment.

A successful run requires both hostname/CA-verified HTTPS and an actual HTTP redirect back to HTTPS on this hostname. Local connection/proxy failures, conflicting records, CAA restrictions, rejected API writes and incomplete redirect propagation are reported separately. The repair does not disable TLS checks, change nameservers or parent-zone CAA policy, alter signing/deploy keys, or configure any other GitHub Pages repository. It does not affect `cybersecurity-writeups` or `docs.jasonachkardiab.com`. The cloud workspace cannot administer the destination Pages settings, so the live repair requires the owner's local account session; mocked tests cannot establish that the public certificate has been issued.

## GoDaddy custom domain authorization

The DNS provider must actually host the authoritative `secureobs.com` DNS zone. `scripts/configure-domain.sh` creates only the `lasa` CNAME pointing at the distribution owner's `OWNER.github.io`. It does not change nameservers or unrelated records, and refuses existing conflicting records rather than replacing a live site. It checks public CNAME resolution first, so a correctly configured record needs no further GoDaddy credentials.

For a new record, provide `GODADDY_API_KEY` and `GODADDY_API_SECRET` in the local environment or enter them at the script's masked terminal prompts. Production credentials come from [GoDaddy's developer account](https://developer.godaddy.com/keys); the repository cannot issue credentials on behalf of your account. GoDaddy can restrict DNS API access by account eligibility. HTTP 401/403 is reported explicitly with the account/access requirement; no browser automation bypass or unrelated DNS deletion is attempted. This one-time authorization cannot be supplied by an unauthenticated coding environment.

Credentials are used through a temporary `0600` header file inside a private directory, deleted on exit, and never stored in either repository or Actions. GitHub account authorization is independently needed for Pages configuration. The script associates the domain with Pages and waits up to 30 minutes for GitHub's certificate, then enables HTTPS enforcement. DNS propagation/certificate issuance can outlast that window; rerunning the same bootstrap retries without moving a tag or changing signing identity. No TLS checks are disabled. `--configure-only` can prepare the repositories/keys before domain access is available, but does not publish the requested custom-domain site.

The certificate wait prints GitHub's state/description on state changes and at least once per minute, plus GitHub DNS health and local TLS errors. It reports certificate authority failures immediately. The API's certificate metadata is optional: when it is absent, a successful hostname/CA-verified TLS handshake plus accepted HTTPS enforcement still establishes readiness. No certificate verification is disabled. Reruns reuse an already-configured Pages domain and HTTPS setting, avoiding unnecessary configuration writes while issuance is pending. For a read-only live status check, run `gh api repos/jasonachkar/homebrew-lasa/pages --jq '{domain:.cname,status:.status,certificate:.https_certificate,https_enforced:.https_enforced}'` in another terminal; it prints no credentials. `/pages/health` may initially return an empty result while its asynchronous check is pending; that is not a successful DNS verdict.

To develop the site locally:

```bash
python3 -m venv .build/docs-venv
.build/docs-venv/bin/pip install -r requirements-docs.txt
python3 scripts/prepare-docs.py
.build/docs-venv/bin/mkdocs build --strict
# With the virtual environment activated:
bash test/docs.sh
```

`test/docs.sh` checks strict builds, customer-only content, local search and real multi-version deployments preserving the package repository. `test/domain.sh` tests GoDaddy/Pages creation, reuse, conflicting DNS and API denial through mocked external boundaries. `test/bootstrap-distribution.sh` uses real signing/deploy keys with mocked GitHub APIs; CI runs it and domain/version tests using macOS's system Bash. These tests do not prove that your accounts permit a live deployment; the bootstrap/live workflows provide that final evidence.


## Native package managers beyond APT

The release pipeline now builds DEB, RPM, Arch and APK packages for both architectures. The distribution publisher signs/indexes APT, RPM, Pacman and APK repositories and retains the Linux Homebrew tap. See [Linux distribution engineering](linux-distribution.md) for tool pins, key lifecycle, package/version mapping, compatibility and native-client tests.

Existing owners need only rerun the updated `bash scripts/bootstrap-azure.sh` from the clean pushed checkout to create/configure the additional Alpine key and update encrypted Azure variables. It preserves the existing OpenPGP and deploy keys. Stable package releases still run from `main`; feature-branch runs verify code and publish current documentation without creating a stable release. If using GitHub instead, rerun `bash scripts/bootstrap-distribution.sh --configure-only` to add the Alpine secret, then follow the existing trusted release flow.
