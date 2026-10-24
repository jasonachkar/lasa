# Full deployment from your Mac

[Maintainer index](README.md) · [Publishing design](publishing.md) · [Package formats](linux-distribution.md)

## Run the deployment

From the clean, pushed checkout of the source you intend to release:

```bash
git pull --ff-only
bash scripts/deploy-local.sh
```

This is a manual trigger for a complete release. Your Mac creates a disposable Ubuntu 24.04 VM through Multipass, verifies the source, builds and signs Linux AMD64/ARM64 packages, publishes the GitHub release and native repositories, updates Linux Homebrew, and publishes both numbered and current MkDocs documentation at **https://lasa.secureobs.com**. It then deletes its VM.

The build, verification, signing and documentation generation run locally. Published downloads and the website remain hosted by GitHub Releases/GitHub Pages; this is not an offline deployment or a server running on your Mac. GitHub's API, package downloads, Go vulnerability service, Pages serving and the existing custom-domain HTTPS setup must be reachable. No Azure organization, Azure PAT, GitHub Actions build runner or Mac Docker installation is required.

The command releases the **currently checked-out branch and commit**, including a reviewed feature branch. It does not merge branches or bypass their protection rules. This creates a real stable release, not a test deployment. Use `main` when that is your release policy. The checkout must match the selected branch on `jasonachkar/lasa`; a moving remote branch stops publication. Numbered tags/assets remain immutable.

## Prerequisites and first-run consent

The existing owner publishing setup must already have created:

- The public `jasonachkar/homebrew-lasa` distribution repository and branch-based Pages configuration.
- A writable distribution deploy key and the matching OpenPGP/Alpine keys in `~/Library/Application Support/lasa-distribution/jasonachkar_lasa`.
- The saved `signing-fingerprint`, `apk-public-key.sha256`, `deploy-key`, `apk-signing-key.pem` and `gnupg/` state. The state directory must be owner-controlled and mode `0700`.
- A working owner GitHub CLI login and the LASA custom-domain configuration.

Your previous bootstrap produced this state; the local deployment command reuses it and does not rotate or generate publishing keys. Missing keys, conflicting pins, an unregistered/read-only deploy key or incompatible Pages settings stop preflight. Restore the original private backup rather than replacing an already trusted key. A new installation without publishing state still needs initial [distribution configuration](publishing.md); `--configure-only` does not launch a release build.

Homebrew must already be available. The launcher installs missing GitHub CLI, GnuPG, jq, Python 3.12 and Multipass. Multipass installation/service authorization and an initial GitHub browser sign-in can require your macOS administrator/account consent. If the existing HTTPS repair needs GoDaddy credentials, it uses the same private local prompt as before. These provider/OS approvals cannot be supplied by a shell script.

The owner GitHub token needs source read/release/tag write access, distribution metadata/deploy-key/Pages read access (Pages write access if HTTPS repair is required), and source repository Variables read/write access to select the publishing provider. `LASA_GITHUB_TOKEN` can supply an existing dedicated local credential; otherwise the command captures the authenticated GitHub CLI token. Never paste tokens into chat or committed files. The SSH deploy key remains the credential used to push distribution content.

## Check without publishing

```bash
bash scripts/deploy-local.sh --check
```

This checks the clean/pushed source, saved state and pins, public distribution/Pages configuration, deploy-key registration, active GitHub publishers and Multipass service. It creates no VM, exports no OpenPGP private key, transfers no credentials, repairs no DNS and changes no publishing provider. Missing tools are reported rather than installed in this mode. Read access does not prove future provider-variable/release write access or Pages availability after a push.

The normal VM defaults are 2 CPUs, 4 GiB memory and a 40 GiB disk:

```bash
bash scripts/deploy-local.sh --cpus 4 --memory 6G --disk 50G
```

The first run downloads the Ubuntu image, guest packages, Go/tool dependencies and test container images. Expect substantially longer than a docs-only update. Each full deployment uses a fresh VM; private publisher VMs are not retained as build caches.

## Verification before owner credentials arrive

The Mac fetches tags/history and creates a Git bundle of the selected branch and tags. The bundle carries source/history, without transferring the working directory, private publishing state, Git credential helpers or owner tokens. The VM first installs Git through Ubuntu's signed package repositories, clones this local bundle and installs its build tools.

The Linux worker requires a detected Ubuntu 24.04 VM. Guest package installation runs through guest sudo; verification and publishing run as the ordinary `ubuntu` user. Docker runs entirely inside that VM. It does not mount the Mac Docker socket, home directory or host package databases.

Verification includes Go formatting/vet/unit/race/static/dependency/current vulnerability checks, bounded fuzzing, reproducibility for both release architectures, packaging, all Python tests, strict MkDocs/Mike preservation tests, bootstrap/version/domain/signature tests, real signed repository/package-manager installation/upgrade/tamper tests and ShellCheck. It records the exact verified Git revision and requires the source tree to remain clean. A failed vulnerability lookup or test is a failure; no skip-verification publishing option exists.

Go is pinned to 1.27.3 and its archive is checked against the official HTTPS release manifest. nFPM retains its pinned archive hashes. The guest GitHub CLI is pinned to 2.83.2 with literal SHA-256 pins for AMD64/ARM64, so existing GitHub-origin release attestations can be verified even though Ubuntu's base CLI is older. Python documentation dependencies retain their existing pinned requirements.

On Intel Macs, the native package-client matrix runs on AMD64. On Apple Silicon, unit/race checks run on native Linux ARM64 and both artifact architectures are built, while the existing AMD64 DNF/Zypper/Pacman/APK matrix runs under an explicitly enabled static QEMU handler. Those emulated AMD64 package checks **do not establish native ARM64 package-client compatibility**. Dedicated privileged eBPF/kernel/provider validation and the broader native compatibility matrix remain separate [VM validation](validation.md) gates; this publishing command does not claim to certify every target.

## Publication and credentials

Only after successful verification does the Mac repair/check the existing LASA domain, select `PUBLISHING_PROVIDER=local`, export the existing OpenPGP key through a short GnuPG alias, and stream the publication credentials through Multipass stdin. Tokens and private key values are not command arguments or an extra Mac credential payload file.

The guest receives one private credential file inside a mode-0700 directory. It is set to mode `0600`, read with a bounded size/schema and consumed before release commands start. Unrecognized input is preserved by the loader to protect against a mistaken private-key/configuration path; guest cleanup still removes the VM on failure. The worker verifies that the credentials' source revision matches both Git HEAD and its successful verification record. It passes only explicit known credential/configuration fields into the publisher environment; it does not evaluate shell fragments from JSON. The entire VM is removed in cleanup, including failures. No secure-erasure guarantee is implied for VM storage or host memory.

The shared `scripts/release.sh` engine calculates the version from immutable tags/conventional commits, checks the selected publishing provider and remote source head, builds signed DEB/RPM/Pacman/APK packages and archives/SBOMs, signs the checksum manifest, creates/repairs a draft release, and publishes it. Existing published bytes are reused, never rebuilt or overwritten. OpenPGP manifests use the established primary signing fingerprint. An existing GitHub-origin release retains GitHub attestation verification; a present detached signature must verify and cannot fall back to another trust policy.

The repository publisher authenticates release assets before updating the signed APT, RPM, Arch and Alpine indexes, universal installer and Linux Homebrew formula. Numbered/current MkDocs publication preserves package directories, older documentation versions and the domain configuration. The publisher verifies the served version/build identity and APT index over HTTPS, so a Git push alone is not reported as a successful deployment.

## One publishing provider

Successful verification selects source repository variable `PUBLISHING_PROVIDER=local`. Updated GitHub verification/version/release/docs jobs skip in this mode, including workflows triggered by the release tag. GitHub Pages still serves/deploys the public distribution repository. Updated Azure publication scripts check provider ownership and stop if local publishing has been selected; the local command does not call Azure APIs or cancel its jobs.

Run only one publisher at a time. Preflight rejects active/queued/waiting GitHub publishing workflows. Stop an already running Azure or older publishing job before switching; older checked-out code cannot be retroactively changed by this tool. Selecting a provider does not buy capacity, remove branch protections, cancel unrelated workflows or forge required status checks. If branch protection requires hosted checks, that policy remains in effect. A local filesystem lock serializes this publisher on one Mac; it is not a distributed lock across different machines using the same keys.

To return to another publishing provider, stop local publication first, then set the repository variable to `github` or `azure` using the owner's existing configuration. Local mode persists deliberately when a later publication fails, preventing a newly triggered GitHub job from competing during recovery.

## Interruptions and failures

The error identifies the current stage: preflight, version history, VM creation/Git bootstrap, tool installation, verification, domain/provider selection, key loading or publication. Captured credential-bearing responses stay withheld; safe HTTP statuses remain visible. Verification failures stop before owner credentials enter the VM. Published releases/tags and already pushed documentation can survive a later failure; rerun from the same reviewed commit to repair/reuse them.

The kernel-held Mac lock releases after interruption. An owner-private journal records only this publisher's VM name and source revision. The next deployment, after acquiring the lock, removes that specifically recorded interrupted VM before proceeding. It does not delete unrelated Multipass VMs. If the Multipass service is unavailable or deletion fails, the journal is retained and the command fails instead of claiming cleanup succeeded. Bring the service back and rerun; it retries the named cleanup. Forced process termination cannot run immediate cleanup, but normal retries recover the recorded guest.

For current docs only, use the existing faster command:

```bash
bash scripts/publish-docs-local.sh
```

The Mac/Multipass launcher and live owner publication must be exercised on the owner's Mac. Repository tests use actual Git bundles, fixture crypto material and credential-file handling with fixture GitHub/Multipass boundaries; those results are not a claim that a real VM or owner release was deployed from the cloud workspace.
