# Native Linux packages and repositories

[Maintainer index](README.md) · [Mac publishing](publishing.md) · [Azure](azure.md) · [Customer installation](../customer/installation.md)

## Availability and ownership

LASA-owned repositories make the product available through APT, DNF/YUM, Zypper, Pacman and APK after one repository-registration operation. They do not place LASA into a distribution's default package set. Debian/Ubuntu archive inclusion, Fedora/EPEL/COPR policies, SUSE OBS, AUR, Alpine aports and other community channels have their own accounts, review, licensing and maintenance requirements. Automation cannot claim maintainer acceptance or official endorsement.

The public distribution repository remains `jasonachkar/homebrew-lasa`; the site remains `https://lasa.secureobs.com`. Existing writeups/domains are not changed. Documentation, version archives, the Homebrew formula and package repositories coexist. `distribution.json` advertises the successfully generated distribution version, formats, architectures and public key pins; it is written only after repository generation succeeds. An unexecuted pipeline or pushed source branch is not evidence that a URL has been published.

## Package build

`package-release.sh` keeps the deterministic DEB/archive staging and adds `package-linux-formats.sh`. nFPM 2.48.0 is a separate build tool, downloaded from its official release with a checked-in SHA-256 pin for each Linux builder architecture. Its dependencies are not linked into LASA and do not change the scanner's module allowlist. It is extracted only into `.build/package-tools/`; no system binary is replaced.

All native formats contain the same CGO-disabled scanner binary, selected customer documentation, license notices and optional service examples. There are no install/uninstall scriptlets, automatic users, scanner executions or enabled services. Root ownership and executable/documentation modes are explicit. Native release time uses `SOURCE_DATE_EPOCH`; RPM build host is fixed. Signed bytes include signing timestamps where required, so source/binary reproducibility and immutable signed-release reuse are separate guarantees.

| Scanner version | Release artifact examples | Package-manager version |
| --- | --- | --- |
| `X.Y.Z` | `lasa_X.Y.Z_amd64.deb` / `arm64` | DEB `X.Y.Z` |
| `X.Y.Z` | `lasa-X.Y.Z-1.x86_64.rpm` / `aarch64` | RPM `X.Y.Z-1` |
| `X.Y.Z` | `lasa-X.Y.Z-1-x86_64.pkg.tar.zst` / `aarch64` | Pacman `X.Y.Z-1` |
| `X.Y.Z` | `lasa-X.Y.Z-r1-x86_64.apk` / `aarch64` | APK `X.Y.Z-r1` |

APK artifacts gain an architecture suffix in the release; repository copies use their canonical `lasa-X.Y.Z-r1.apk` filename within each architecture directory. The executable always reports the scanner version `X.Y.Z`, independently of packaging revisions. Semantic versioning remains automatic from commits and immutable tags. Existing published assets are reused on retries, never rebuilt or overwritten. Introducing a changed package for the same published version is rejected; allocate a new scanner version instead of silently changing bytes.

`write-release-manifest.sh` enumerates the exact version's binaries, archives, DEBs, RPMs, Pacman packages/signatures, APKs and SBOMs, including the license archive when present. Azure signs this manifest with the configured OpenPGP primary key. GitHub attests the manifest and all package formats. The authenticated publisher verifies provenance and hashes before indexing.

## Signing and key lifecycle

The existing owner OpenPGP key is reused for APT metadata, native RPM signatures, RPM metadata, Pacman package signatures and Pacman databases. `build-signed-packages.sh` verifies the imported primary fingerprint, supplies nFPM a temporary secret-key file for native RPM signing, and signs the Arch packages. Secret files live in a mode-0700 temporary directory with a cleanup trap and are never release assets.

Alpine uses a separate RSA-3072 PEM key. `prepare-apk-key.sh` runs on the owner's Mac during the updated bootstrap, stores it in the existing private state directory, registers the encrypted `APK_SIGNING_KEY` release secret and the public `APK_PUBLIC_KEY_SHA256` pin, and reuses it on retries. If a remote secret exists but local state is missing, it stops and asks for restoration; it does not rotate trust. A public/private mismatch or changed saved pin is fatal. Back up the complete state directory, including this additional key and pin, using the owner's existing secure backup process.

`sign-apk.py` supplies APK v2 RSA/SHA-256 signature framing around nFPM's unsigned control member and native `apk index` output. OpenSSL performs RSA signing; the script implements no cryptographic primitive. Input/control sizes, process duration and signature nesting are bounded. It atomically replaces only the build artifact. Package control data authenticates the data archive; the index authenticates repository selection. Native Alpine installation tests establish acceptance by the tested APK client. The image/client version remains part of that validation scope.

No package manager trust check is disabled for installation. Initial repository trust depends on the HTTPS installer and its embedded key pins. A same-channel key/hash is not independent out-of-band trust. Organizations can distribute the public key/fingerprint through their own configuration management.

## Repository generation

`publish-linux-repositories.sh` executes after the existing APT/formula/installer generation and release provenance verification. It requires native `createrepo_c`, RPM tools, `repo-add`, libarchive tools, Python/OpenSSL and Docker on the Linux publishing runner. Azure/GitHub provisioning installs these tools from the runner's signed system repositories. No Docker installation is required on the owner's Mac when using Azure.

- RPM: verify native package signatures against a temporary RPM database containing the configured public key; create SHA-256 repodata with `createrepo_c`; sign `repomd.xml`; publish its public key. Customers enable package and metadata verification.
- Pacman: verify detached package signatures, generate databases with native `repo-add --include-sigs --prevent-downgrade`, sign database/file indexes and publish regular-file aliases instead of Git-dependent symlinks. Database metadata includes package signatures. Old package files are retained; only the current package version is selected by the repository database.
- APK: verify signed packages with a pinned official multi-architecture Alpine image, generate the native index offline in that image, then sign the index with OpenSSL RSA/SHA-256 framing. The container receives only public package/key directories, runs as the invoking UID/GID, has no network or capabilities, and mounts no private signing state. Private key material is used only by the host-side signer.

Per-version package and detached-signature paths are immutable. Package managers handle upgrades from the mutable signed indexes. The existing version rollback guard applies before repository generation. A failure leaves a private staging checkout; no distribution commit is pushed until every repository succeeds. GitHub Pages/cache propagation remains asynchronous. The publisher waits for current APT metadata; the owner should also inspect `distribution.json` and native index endpoints when diagnosing partial CDN visibility.

## Installer behavior

The publisher generates a portable POSIX `install.sh` with the public base URL, OpenPGP fingerprint, Alpine key SHA-256 and the APT setup-script SHA-256. It recognizes APK, Zypper, DNF, YUM, Pacman and APT, including derivative distributions using those managers. Unsupported architectures/managers fail before registration. The `--detect` mode does not configure anything.

It installs only required trust/download prerequisites, registers LASA's key/repository and installs LASA. Conflicting LASA-named key/config files stop the relevant branch instead of being overwritten. APT retains its repository-specific keyring. RPM imports the verified key into the native shared RPM trust store. Pacman locally signs the verified public key in its native keyring. Alpine installs only the specifically pinned PEM public key. User/admin consent is supplied by the local root/sudo session, never through chat.

Arch setup performs the full upgrade required by the rolling-release package model. It does not refresh databases and perform an unsupported partial upgrade. Document this behavior for operators. Package removal does not remove scan data, service configurations or repository trust state; customer installation docs identify the LASA-owned paths.

## Native validation and limits

`test/distribution.sh` exercises repeated package builds, immutable publication, metadata signatures, both architectures and real isolated APT downloads, plus rollback/tamper/key rejection. It generates isolated fixture keys and never uses the owner's signing state. `test/linux-package-managers.sh` invokes real DNF, Zypper, Pacman and APK clients in pinned ephemeral AMD64 containers, with only the generated public repository and detection script mounted and networking disabled. Filesystem-only capabilities needed by native installers are scoped to these ephemeral containers; no privileged mode, host PID view or host package mounts are granted. Installation, an upgrade between two actual scanner versions, removal and tampered-index rejection assertions must pass with signature verification enabled. Host package databases and trust stores are not modified.

These are packaging/protocol tests. They do not certify the scanner's kernel/provider behavior, every distribution release or native ARM64 client behavior. Use the [privileged VM harness](validation.md) and target-specific compatibility matrix for those claims. Do not confuse a static package install with support for kernels that lack usable `openat2` or for native macOS/Windows. Cross-built ARM64 packages still need actual native ARM64 deployment validation.
