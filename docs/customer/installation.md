# Installation and first use

[Documentation home](../../README.md)

## Requirements

Use Linux on AMD64 or ARM64. LASA uses `openat2` to constrain metadata paths; Linux 5.6 introduced this syscall, but kernel configuration, seccomp and container policy can still make it unavailable. Procfs must be mounted and the scanner's own metadata must be visible. No database, runtime control socket, API key, SecureObs account or outbound network access is required for scanning.

Build with the supported Go 1.27.4 patch release. CGO is disabled for release binaries. A C compiler is needed only for race tests and a pinned Clang/libbpf toolchain only for regenerating the optional eBPF object. The object is already embedded in normal builds.

## APT and Homebrew packages

These commands require a successfully published release and distribution site; the presence of workflow source alone does not mean packages are live.

On Debian/Ubuntu Linux AMD64 or ARM64, the installer configures a repository-specific signing key, verifies its fingerprint and installs the package:

```bash
curl --proto '=https' --tlsv1.2 -fsSLo install-lasa.sh https://lasa.secureobs.com/install-apt.sh
bash install-lasa.sh
lasa doctor
```

Review the downloaded installer according to your organization's policy. Initial trust comes from the HTTPS distribution site and its published signing fingerprint. After installation, use `sudo apt-get update` and `sudo apt-get install --only-upgrade lasa` for updates. To remove it, use `sudo apt-get remove lasa`; the repository source and keyring remain until you remove `/etc/apt/sources.list.d/lasa.list` and `/usr/share/keyrings/lasa-archive-keyring.gpg`.

On Linux with Homebrew:

```bash
brew install jasonachkar/lasa/lasa
lasa doctor
```

The tap selects the architecture and verifies an exact archive checksum. Use `brew upgrade lasa` and `brew uninstall lasa`. Installing either package does not start a scanner or service. The DEB carries optional systemd examples under `/usr/share/doc/lasa/examples/`; follow the service-account guidance in [operations](operations.md) before installing a unit. Removing a CLI package does not clean up separately configured services or saved reports.

macOS can manage publishing but cannot run this Linux scanner. The Homebrew formula explicitly requires Linux. Native Windows/WinGet is not supported; WSL users can use the APT instructions inside a supported Linux distribution. No native macOS or Windows security coverage is implied.

## Build from source

```sh
go version                         # should report go1.27.4
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

This command installs the binary; the scanner itself never invokes sudo. Do not make the binary SUID or assign broad file capabilities to it. If release assets are published, verify their checksums and GitHub build attestation before installation. Release signing configuration in the repository is not evidence that an unpublished binary has been signed.

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
mkdir -m 0700 -p ~/reports
sudo lasa scan --profile deep --format json --output ~/reports/deep.report.json
lasa report --input ~/reports/deep.report.json
```

When a scan runs through sudo and the destination directory is a private directory of the invoking user, the report is written with mode `0600` and assigned to that user, so it can be read without sudo. Directories that other users can write to are refused. Without sudo, root-owned reports remain private to root. Procfs hidepid, ptrace policy, user namespaces and container restrictions can still limit root's view. An elevated scan does not certify that the entire host was observed.

Use `--profile container` when scanning inside a container. It reports that limited scope rather than silently presenting the result as a host audit. See [operations](operations.md) before exposing additional host namespaces or mounts.

## Updating and uninstalling

Keep the binary version and report schema version in your deployment inventory. Review rule and schema changes before comparing reports from a new release. Replace the installed binary through your normal package/deployment workflow and restart a daemon after replacement. A running daemon does not reload new binaries or suppression files automatically.

To uninstall a native binary, stop and disable any installed LASA service first, then remove the binary and installed unit using your system administration workflow. Local reports and state directories are not automatically deleted; choose retention and secure disposal deliberately.
