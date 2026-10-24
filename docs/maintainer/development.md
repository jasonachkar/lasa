# Development, testing, supply chain and release

[Maintainer index](README.md)

## Toolchain and workspace

Use supported Go **1.27.3**. Normal binaries use `CGO_ENABLED=0`, Linux AMD64/ARM64, trimmed paths and no build timestamp. Native Linux tests use the real kernel; a C compiler is required for Go's race detector. Keep Go checksum/TLS verification enabled. `go.mod` and `go.sum` pin modules; `tools/dependencies.allow` defines modules linked into the scanner binary.

Use the existing checkout in an isolated cloud task. Do not create an additional Git worktree unless requested. Retained binaries, dependencies and source files do not imply a daemon or BPF links will survive a task restart. Restart services explicitly using documented commands and verify their output.

Cloud setup used a checksum-verified Go toolchain outside the repository. If your machine lacks Go or compiler headers, install them through authoritative releases/signed packages, or the pinned BPF build container. No production secret or cloud credential is needed for static scans.

## Commands

```sh
make build                         # bin/lasa
make tools                         # pinned staticcheck, govulncheck, goimports, CycloneDX
export PATH="$(go env GOPATH)/bin:$PATH"
make check                         # build, gofmt, vet, tests, race, lint, dependency verification, vulnerability scan
make fuzz                          # seven bounded fuzz smoke runs
make reproducible                  # compare two binary builds per target architecture
make release-binaries              # dist binaries plus SHA256SUMS
make sbom                          # per-architecture CycloneDX binary SBOM, includes stdlib/version
make bpf                           # explicitly regenerate embedded BPF code/object
```

For a read-only home directory, put Go caches/GOPATH and `XDG_CACHE_HOME` under an approved writable workspace. Docker buildx can similarly need a writable `DOCKER_CONFIG`. This is tool initialization, not permission to dump or copy credential configuration. Reuse platform HTTPS Git authentication; a missing `GH_TOKEN` does not prove Git access is absent.

## Tests and boundaries

Unit tests cover configuration, domain identity framing, actionable errno, proc parsers, namespace mapping, mountinfo, container hints/redaction, file capability xattr parsing, path constraints, graph provenance/cycles, rules and priority, partial drift, report escaping/decoding, atomic storage and daemon behavior.

Every builtin rule has positive/negative/unknown/missing/conflict/not-applicable cases. Integration tests open real Linux TCP and UDP sockets, verify current-process ownership and local exposure, run a snapshot and check canonical report round-tripping. Command-level tests build the binary and exercise scan/report/explain/diff, threshold/strict/fatal exit behavior, private output and SIGTERM shutdown.

The explicit privileged sensor test is separate. A skip is not a pass and an object build is not an attachment test. Container deployment tests validate a deliberately limited view; they do not establish host-container namespace correctness or a container escape detector.

Fuzz targets exercise stat, status, endpoint/socket tables, mountinfo, YAML and JSON decoding. Three-second smoke runs are CI regression probes, not exhaustive fuzz validation. Keep discovered regression seeds and run longer dedicated fuzzing before security-sensitive releases.

Use Arrange–Act–Assert structure and explicit expectations. Avoid tests that merely reproduce the implementation. Important future matrix cases include hidepid, multiple network/user namespaces, overmounts, active process exec/exit churn, large inventories, filesystem races and supported BPF kernels.

## Vulnerability checks

`make vuln` uses the official Go vulnerability database and reports reachable code rather than treating every module advisory as applicable to Linux. Fresh advisory data requires access to `vuln.go.dev`. Network denial is a failed freshness check, not proof of vulnerability absence.

An authoritative local OSV snapshot can be used explicitly:

```sh
make vuln VULN_DB=file:///absolute/path/to/trusted/vulndb/data/osv
```

Record its upstream revision/date. The implementation validation used the official `golang/vulndb` repository through existing HTTPS Git authentication when direct database access was denied. This found and led to fixing a reachable cilium BTF parser advisory. Final recorded results must state the snapshot's freshness limit. Do not disable TLS/module verification or silently substitute an untrusted mirror.

## BPF supply chain

The object is generated with `bpf2go` from the pinned cilium module. Source-path remapping removes local checkout paths. The BPF CI job regenerates in the pinned builder and requires no generated diff. Package repositories and base image are part of this trust boundary; pinning the image does not make unversioned apt dependencies globally reproducible.

The compiler and libbpf versions are explicit. Build-container regeneration was configured; verify its actual job result before claiming it ran. Source/object hash comparisons and successful Go embedding do not prove a kernel verifier accepts the program.

## CI

See [publishing from a Mac](publishing.md) for the current automatic semantic-version, DEB/APT, RPM, Pacman, APK, Homebrew and MkDocs/Mike pipeline. Release versions are injected through `VERSION` into the Go binary; source builds default to `0.1.0-dev`. Use `VERSION=0.0.0 make packages` for local package verification, while the release workflows allocate production versions without editing source constants.

`ci.yml` configures native AMD64 and ARM64 Linux runners for formatting, vetting, tests, race, staticcheck, dependency allowlist/checksum verification, vulnerability scanning, fuzz smoke and repeated-build comparison. It builds architecture-appropriate container images and exercises doctor/scan/report in a read-only no-capability container view. Another job regenerates BPF with the pinned builder.

`privileged.yml` is manual, dedicated-runner-only and environment-gated. `release.yml` runs on version tags, checks that the tag agrees with the binary's version, builds/checks binaries, creates SBOMs/checksums, requests GitHub signed build provenance via OIDC and publishes release assets. Action references are pinned to commit IDs. Workflow configuration is not proof a remote CI/release was executed.

## Reproducibility and artifacts

Release binaries are built with fixed target settings, `-trimpath`, `-buildvcs=false`, stripped symbols and an empty build ID. The local reproducibility script compares two outputs per architecture. This establishes same-environment byte equality for those builds; independent-builder reproducibility remains a stronger separate claim. SBOM timestamps/serials are not claimed byte-reproducible.

`make sbom` generates CycloneDX 1.6 JSON for each binary with main-component version and Go standard-library metadata. The release workflow recomputes checksums over binaries and SBOMs before attesting. Review the SBOMs and third-party notices before distributing a release. `dist/` is ignored because these are generated artifacts; regenerate rather than commit private report data or binaries unnecessarily.

Release attestation/signing requires actual GitHub workflow execution and repository environment/permission configuration. No tag, release, signature or remote publication is created by this implementation task. Verify published assets with the GitHub CLI's attestation verification against the expected repository before installation; do not describe local checksums alone as signatures.

## Release gate

Require clean tests, no unexplained reachable vulnerability, current advisory review, output-schema validation, actual supported-platform evidence and documented limitations. Privileged sensor support must have VM event evidence. Review customer language so no unsupported detection becomes a product promise. Preserve existing license obligations and make publication scope a deliberate owner decision.
