# Installation and first use

[Documentation home](../../README.md)

## Requirements

Use Linux on AMD64 or ARM64. LASA uses `openat2` to constrain metadata paths; Linux 5.6 introduced this syscall, but kernel configuration, seccomp and container policy can still make it unavailable. Procfs must be mounted and the scanner's own metadata must be visible. No database, runtime control socket, API key, SecureObs account or outbound network access is required for scanning.

Build with the latest supported patch of the Go version required by your checkout's `go.mod`. CGO is disabled for release binaries. A C compiler is needed only for race tests and a pinned Clang/libbpf toolchain only for regenerating the optional eBPF object. The object is already embedded in normal builds.

## Configure your Linux package manager

LASA's signed Linux packages and Homebrew tap are pending their first public release. The setup script and package repositories become available when that release is published. Until then, users with access to the LASA source repository can [build from source](#build-from-source) on Linux AMD64 or ARM64.

## Build from source

Run these commands from your LASA source checkout on Linux.

```sh
go version
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

This command installs the binary; the scanner itself never invokes sudo. Do not make the binary SUID or assign broad file capabilities to it. When release downloads become available, verify checksums and release provenance before installation.

## Verify release provenance

GitHub Actions releases carry a GitHub build attestation. Verify the downloaded checksum manifest using `gh attestation verify SHA256SUMS --repo jasonachkar/lasa`, then run `sha256sum --strict -c SHA256SUMS` in the directory containing all listed assets.

Azure releases instead provide `SHA256SUMS.asc` and `release-signing-key.asc`. They use an OpenPGP signature by the APT signing key; this is not a GitHub OIDC build attestation. Import the public key into a dedicated verification keyring, confirm its full primary fingerprint against your organization's trusted LASA signing fingerprint, verify `gpg --verify SHA256SUMS.asc SHA256SUMS`, and check the manifest hashes before installing. A key downloaded alongside a binary is not independently trusted. A valid signature proves control of the signing key, not that the builder was uncompromised.

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
