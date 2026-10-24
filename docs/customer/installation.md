# Installation and first use

[Documentation home](../../README.md)

## Requirements

Use Linux on AMD64 or ARM64. LASA uses `openat2` to constrain metadata paths; Linux 5.6 introduced this syscall, but kernel configuration, seccomp and container policy can still make it unavailable. Procfs must be mounted and the scanner's own metadata must be visible. No database, runtime control socket, API key, SecureObs account or outbound network access is required for scanning.

Build with the supported Go 1.27.2 patch release. CGO is disabled for release binaries. A C compiler is needed only for race tests and a pinned Clang/libbpf toolchain only for regenerating the optional eBPF object. The object is already embedded in normal builds.

## Configure your Linux package manager

LASA publishes its own signed repositories for Linux AMD64 and ARM64. Configure the repository once; subsequent installs and upgrades use your normal package manager. A stock machine does not know LASA's repository until this setup runs.

Download the complete setup script over HTTPS before executing it:

```sh
curl --proto '=https' --tlsv1.2 -fsSLo install-lasa.sh https://lasa.secureobs.com/install.sh
sh install-lasa.sh
lasa doctor
```

Run these commands from a directory you own. The script uses root or sudo for repository/package changes, detects the available manager, verifies the pinned signing key and installs LASA. `sh install-lasa.sh --detect` prints the selected manager/architecture without configuring a repository. Review the downloaded script according to your organization's policy. Initial trust comes from the HTTPS site and its published key pins; do not bypass signature, checksum or TLS failures.

| Linux family | Repository / native package | Install after setup | Update |
| --- | --- | --- | --- |
| Debian, Ubuntu and compatible derivatives | APT / DEB | `sudo apt install lasa` | `sudo apt update && sudo apt install --only-upgrade lasa` |
| Fedora, RHEL, Rocky, AlmaLinux, Oracle Linux, CentOS Stream | RPM / DNF | `sudo dnf install lasa` | `sudo dnf upgrade lasa` |
| Compatible systems using YUM | RPM / YUM | `sudo yum install lasa` | `sudo yum update lasa` |
| openSUSE / SUSE with compatible RPM support | RPM / Zypper | `sudo zypper install lasa` | `sudo zypper update lasa` |
| Arch Linux; compatible Arch Linux ARM targets | Pacman | `sudo pacman -S lasa` | `sudo pacman -Syu` |
| Alpine | APK | `sudo apk add lasa` | `sudo apk update && sudo apk upgrade lasa` |

These are LASA-owned repositories, separate from each distribution's default repositories. A package format being available does not establish kernel/provider compatibility for every derivative or historical release. Use a maintained operating system with the kernel requirements above; then check `lasa doctor` and [compatibility](compatibility.md). Gentoo, NixOS and other managers can use reviewed binary/source deployment; no official ebuild, Nixpkgs entry, AUR listing or distribution-maintainer endorsement is implied.

The setup script refuses conflicting existing LASA configuration/key files. It retains the distribution's other repositories. Arch setup performs a full system upgrade before installation, following the rolling-release requirement to avoid partial upgrades. The commands select architecture automatically. Optional systemd units are examples only; no package starts a service, grants scanner privileges or runs a scan.

For APT-only setup, the existing `https://lasa.secureobs.com/install-apt.sh` remains available. APT uses a repository-specific keyring and signed metadata. RPM repositories require both package and metadata signatures. Pacman verifies database and package signatures. APK packages and indexes use RSA/SHA-256 signatures with a separately pinned Alpine public key.

## Linux Homebrew

```sh
brew install jasonachkar/lasa/lasa
lasa doctor
```

The formula selects the architecture and verifies an exact archive checksum. Use `brew upgrade lasa` and `brew uninstall lasa`.

macOS can manage publishing but cannot run this Linux scanner. The Homebrew formula explicitly requires Linux. Native Windows/WinGet is not supported; WSL users can use their supported Linux distribution's package instructions. No native macOS or Windows security coverage is implied.

## Remove a package or repository

Use `sudo apt remove lasa`, `sudo dnf remove lasa`, `sudo yum remove lasa`, `sudo zypper remove lasa`, `sudo pacman -R lasa`, or `sudo apk del lasa`. Stop any separately configured daemon first. Package removal retains reports, state and repository configuration.

To stop receiving LASA packages, remove only the LASA-owned entries:

- APT: `/etc/apt/sources.list.d/lasa.list` and `/usr/share/keyrings/lasa-archive-keyring.gpg`.
- DNF/YUM: `/etc/yum.repos.d/lasa.repo`; Zypper: `/etc/zypp/repos.d/lasa.repo`. The public key file is `/etc/pki/rpm-gpg/RPM-GPG-KEY-lasa`; the imported RPM trust entry is shared RPM state, so review its fingerprint before removing it.
- Pacman: the `Include = /etc/pacman.d/lasa.conf` line and `/etc/pacman.d/lasa.conf`. Remove the specifically identified LASA key through `pacman-key` only after checking no other repository uses it.
- APK: the LASA URL line in `/etc/apk/repositories` and `/etc/apk/keys/lasa.rsa.pub`.

Do not remove distribution-wide keyrings or unrelated repository files. Local reports and separately installed service units need their own retention/removal policy.

## Build from source

```sh
go version                         # should report go1.27.2
make build
./bin/lasa version
./bin/lasa doctor
```

Module versions and checksums are pinned in `go.mod` and `go.sum`. Installation must preserve module checksum and TLS verification. Do not work around a failed checksum with `GOSUMDB=off`, an insecure proxy or modified expected digests.

## Native installation

An administrator may install a reviewed build:

```sh
sudo install -m 0755 bin/lasa /usr/local/bin/lasa
lasa doctor
lasa scan
```

This command installs the binary; the scanner itself never invokes sudo. Do not make the binary SUID or assign broad file capabilities to it. For direct downloads, verify checksums and release provenance before installation.

## Verify release provenance

GitHub Actions releases carry a GitHub build attestation. Verify the downloaded checksum manifest using `gh attestation verify SHA256SUMS --repo jasonachkar/lasa`, then run `sha256sum --strict -c SHA256SUMS` in the directory containing all listed assets.

Locally built and Azure releases instead provide `SHA256SUMS.asc` and `release-signing-key.asc`. They use an OpenPGP signature by the APT signing key; this is not a GitHub OIDC build attestation. Import the public key into a dedicated verification keyring, confirm its full primary fingerprint against your organization's trusted LASA signing fingerprint, verify `gpg --verify SHA256SUMS.asc SHA256SUMS`, and check the manifest hashes before installing. A key downloaded alongside a binary is not independently trusted. A valid signature proves control of the signing key, not that the builder was uncompromised.

Native package managers verify the configured repository/package trust chain automatically. Homebrew checks the archive hash pinned in its formula. Release provenance verification is an additional check for direct downloads.

## First private report

```sh
mkdir -m 0700 ./reports
lasa scan --format json --output ./reports/first.report.json
lasa report --input ./reports/first.report.json --format terminal
lasa report --input ./reports/first.report.json --format html --output ./reports/first.report.html
```

Report parents must already exist. LASA rejects symlinks in report paths and uses mode `0600` with atomic replacement. The HTML file is self-contained; it does not load fonts, scripts, images or other resources from a remote service. Protect HTML and JSON equally because both may expose infrastructure metadata.

## Narrowing collection

```sh
lasa scan --roots /usr/local/bin,/etc/systemd/system --max-files 2048 --timeout 20s
```

`--roots` replaces the default file roots. It does not change process or socket collection. Inspection is limited to metadata and two directory levels beneath each explicit root; it does not promise an exhaustive recursive crawl. Use separate, narrowly scoped roots for deeper relevant directories.

## Elevated and container views

First inspect `lasa doctor` and the unprivileged report. Run a deep scan only in a host context and with authorization appropriate to your organization:

```sh
sudo lasa scan --profile deep --format json --output ./reports/deep.report.json
```

Root-owned reports remain private to their owner. Procfs hidepid, ptrace policy, user namespaces and container restrictions can still limit root's view. An elevated scan does not certify that the entire host was observed.

Use `--profile container` when scanning inside a container. It reports that limited scope rather than silently presenting the result as a host audit. See [operations](operations.md) before exposing additional host namespaces or mounts.

## Updating and uninstalling

Keep the binary version and report schema version in your deployment inventory. Review rule and schema changes before comparing reports from a new release. Replace the installed binary through your normal package/deployment workflow and restart a daemon after replacement. A running daemon does not reload new binaries or suppression files automatically.

To uninstall a native binary, stop and disable any installed LASA service first, then remove the binary and installed unit using your system administration workflow. Local reports and state directories are not automatically deleted; choose retention and secure disposal deliberately.
