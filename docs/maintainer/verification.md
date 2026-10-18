# Engineering verification and release readiness

[Maintainer index](README.md)

Verification date: **2026-10-18**. Scanner version: **0.1.0**. This records executed work, not a claim that every production environment is supported.

## Implemented deliverable

A functional local Go scanner with bounded Linux process, identity, namespace, socket, filesystem and kernel metadata collection; typed four-state observations; a provenance-aware graph; fifteen reviewed rule definitions; conditional local correlations; stable fingerprints; explicit scoring contributions; and actionable diagnostics/coverage.

The binary provides scan, doctor, explain, diff, terminal/JSON/HTML/SARIF saved-report rendering, local custom rules, justified/expiring suppressions, shell completion and a cancellable sequential daemon with private snapshots and bounded retention. The optional eBPF adapter and compiled CO-RE object collect metadata windows when kernel prerequisites are available. There is no mandatory backend or outbound telemetry.

Customer and maintainer documentation are separated. Native/container deployment, systemd examples, Linux CI, module allowlisting/checksum validation, release builds, SBOMs, checksums and signed build-provenance workflow configuration are supplied. No release or remote signing job was executed during implementation.

## Tested machine and toolchain

| Item | Observed evidence |
| --- | --- |
| Distribution | Debian GNU/Linux 13, base image version 13.6 |
| Reported kernel | Linux 6.18.55 |
| Native runtime architecture | AMD64 / x86-64 |
| Scanner user | Effective UID 1000, no effective or bounding Linux capabilities |
| Isolation | Restricted cloud/container-like Linux view, seccomp enabled, NoNewPrivs enabled |
| Go | Official supported Go 1.27.2 Linux AMD64 archive; SHA-256 verified before use |
| BPF compiler | Debian signed-package Clang/LLVM 19.1.7-3+b1, libbpf headers 1:1.5.0-3 |
| Docker | 28.4.0; minimal unprivileged scratch-image doctor/scan executed |
| Native ARM64 kernel runtime | **Not exercised here**; cross-build and same-environment byte comparison passed |

The Go archive checksum was `ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5`. Module checksum, package signature and TLS verification were not disabled.

## Exact test and build commands

The local toolchain and caches were placed in writable workspace locations. Tool paths were added to PATH; `GOTOOLCHAIN=local`, a writable GOPATH/GOMODCACHE/GOCACHE and `XDG_CACHE_HOME` were used. These path adaptations did not change application source semantics or bypass verification.

| Command | Observed outcome |
| --- | --- |
| `go test -count=1 -json ./...` | **80 passed test events**, **1 skipped**, **0 failed**; includes nested rule cases and fuzz seed cases |
| `make fmt` | Passed |
| `go vet ./...` / `make vet` | Passed |
| `staticcheck ./...` / `make lint` | Passed with pinned v0.8.2 |
| `make race` (`CGO_ENABLED=1 go test -race ./...`) | Passed, privileged sensor test remains explicitly skipped |
| `sh scripts/check-dependencies.sh` / `make deps` | Linked module allowlist matched; `go mod verify` passed |
| `make fuzz` | All seven bounded smoke targets passed: stat, status, endpoint, socket tables, mountinfo, YAML and report JSON |
| `make vuln VULN_DB=file:///workspace/toolchains/vulndb/data/osv` | No vulnerabilities found after dependency fixes, subject to advisory snapshot freshness below |
| `make build` | Functional statically linked Linux AMD64 binary |
| `make reproducible` | Two byte-identical binary builds for each of Linux AMD64 and ARM64 in this toolchain/environment |
| `make release-binaries` | Both architecture artifacts built; SHA256SUMS generated |
| `make sbom` | CycloneDX 1.6 JSON generated for both binaries; main version v0.1.0, six dependency/stdlib components per artifact |
| `make sbom` repeated | Passed after making notice packaging repeatable over read-only source license copies |
| `go generate ./internal/collector/ebpf` with pinned local Clang/libbpf | Object and generated Go compiled successfully |
| Same BPF generation from relocated temporary checkout + `cmp` | Generated Go and object bytes matched |
| JSON Schema validation of actual report | Passed against checked-in report-v1 schema |
| SARIF validation of empty, nonempty and suppressed finding reports | Passed against the SARIF 2.1.0 schema from SchemaStore |
| `systemd-analyze --root=ISOLATED_ROOT verify lasa.service lasa-deep.service` | Syntax/dependency validation passed using the actual binary and minimal base target definitions; services were not started |

Unit tests cover parser errors, cancellation, permission failure, process disappearance, mapping scope, malformed capability xattrs, uncertainty/conflict logic, graph provenance/cycles and inode replacement, stable fingerprints, highest-risk service aggregation, report escaping, unsafe outputs, retention and suppression expiry. Live Linux integration verifies actual TCP and UDP ownership and loopback classification. CLI subprocess tests exercise report formats, explanations, comparisons, severity/strict/fatal exits, private snapshot permissions and graceful SIGTERM shutdown.

The privileged event test is **skipped**, with the explicit message that an authorized disposable VM with BTF/tracefs and BPF/perf permissions is required. A skip does not establish attachment or event delivery.

## Real scanner output

Commands executed:

```sh
bin/lasa doctor --format json
bin/lasa scan --format json --output /tmp/lasa-release-validation.report.json
bin/lasa report --input /tmp/lasa-release-validation.report.json --format terminal
bin/lasa report --input /tmp/lasa-release-validation.report.json --format sarif --output /tmp/lasa-release-validation.sarif
bin/lasa report --input /tmp/lasa-final.report.json --format html --output /tmp/lasa-final.report.html
```

One captured scan of this restricted view reported:

```text
Processes: 17
Sockets: 18
Files: 1431
Observations: 17581
Findings: 0
Diagnostics: 720
Complete within declared scope: false
Engine elapsed time for this small instance: approximately 0.135 seconds
Stored JSON permission mode: 0600
```

Counts vary with process churn. This is one measured run, not a performance guarantee. The diagnostic totals were 546 symlink exclusions, 10 unavailable metadata paths, 158 permission failures and 6 vanished-process events. These remain visible; no issue-free or complete-host assurance was inferred.

An actual positive finding from a deliberately writable isolated fixture is preserved in [unsafe-permissions.json](../examples/unsafe-permissions.json). The file is an extracted example, not a full ingestible snapshot, and does not claim the host's active sudoers configuration was insecure. Its nonempty SARIF rendering and a justified-suppression SARIF rendering passed schema validation.

## Container validation

Executed with a writable Docker CLI configuration directory, without copying credentials:

```sh
docker build -t lasa:0.1.0 -f deploy/container/Dockerfile .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges lasa:0.1.0 doctor --format json
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges lasa:0.1.0 scan --profile container --format json
```

The scratch-image scan ran as UID 65532 and declared a container view. It observed one process, no endpoints/files in that minimal filesystem and nineteen diagnostics; overall collection was partial. The resulting JSON was rendered successfully to HTML. This validates minimal container execution and transparent limitations, not host scanning through a privileged container or every runtime's namespace layout.

The Dockerfile explicitly assigns executable mode when copying an artifact, so a restrictive developer umask does not leave the non-root container unable to execute the binary.

## Dependency security and freshness

Direct `govulncheck ./...` could not reach `vuln.go.dev` because this environment's network policy returned Forbidden. An authoritative offline source was obtained through the existing GitHub HTTPS proxy:

```text
https://github.com/golang/vulndb
revision d5e0cfac5d260523df858cd4c0f849e248468fb6
```

The installed pinned govulncheck supports a local flat OSV directory. The first check found reachable BTF parsing advisory **GO-2026-6238** in cilium/ebpf v0.20.0. The implementation upgraded to **v0.22.0**, regenerated the object and reran checks. A Windows-only x/sys advisory was also removed from the required module version by moving to **v0.44.0**. Final local-source checks report no vulnerabilities found.

This establishes the result against that exact upstream snapshot, not fresher advisories unavailable through the restricted endpoint. A production release gate must refresh the official database and recheck. An attempted full database-generator build encountered blocked dependency artifact egress; the tool's supported local OSV input avoided needing that generator without disabling any checksum verification.

## BPF validation and concrete blockers

The embedded object SHA-256 is:

```text
987900d4424026be62203b100b6cdc7d156c0cb747f447b085037a958dc55d74
```

An actual sensor-profile request emitted `BTF_UNAVAILABLE` and incomplete coverage with zero claimed runtime success. This instance exposes neither usable `/sys/kernel/btf/vmlinux` nor tracepoint metadata and grants no Linux capabilities. Kernel loading, verifier acceptance and event delivery are therefore **not verified**.

The pinned BPF builder image's base manifest was resolved/pulled, but its package step failed inside Docker because the bridge could not resolve `deb.debian.org`. A retry using the existing proxy route/host build networking identified that Docker could not resolve the environment's proxy hostname either. This is a build-container networking blocker, separate from kernel privileges. No TLS, package signature or artifact verification was disabled. The exact compiler/header packages were instead fetched through signed apt metadata in the actual cloud machine; local and relocated-checkout regeneration passed. The Docker builder configuration still needs execution in a normally networked CI environment.

## Binary artifact checksums

For the original scanner implementation state, before automatic version injection was added (historical hashes, not hashes of current release artifacts):

```text
48a2bdf8367754ca609e4eabcd27225a72a0ca8eb39e98d4f2d45ef0f6b679f8  lasa-0.1.0-linux-amd64
43a1b97dcac0ab10055886e792caf05158f8e819e2cf04d4d934b26f6d4e070b  lasa-0.1.0-linux-arm64
```

`dist/` contains generated binaries, SBOMs, checksums and packaged notices and is ignored by Git. Local checksum equality does not prove independent-builder reproducibility or release signing. No remote tag, release or signature was created by this implementation.

## Scope limits and release gates

### Package, automation and website validation (2026-10-18)

The subsequent publishing change passed local Go formatting, vet, unit/integration/end-to-end and race tests, staticcheck, module verification and repeated AMD64/ARM64 builds with version injection. The vulnerability check used the same authoritative OSV snapshot identified above, with the same freshness limitation.

Real DEB/archive builds for both architectures matched on repeated runs. Extracted binaries matched their inputs and the native binary reported the injected release version. An isolated real APT client accepted the generated signed repository and downloaded matching DEBs for both architectures; signature tampering was rejected. Same-version changed bytes, a lower publication version and an unexpected installer key were rejected. No package or trusted key was installed into the test machine.

Strict MkDocs builds passed for ten customer pages with local search. Real two-version Mike deployments retained both documentation versions, advanced `latest`, and preserved the APT files, Homebrew formula, CNAME and `.nojekyll`. The build explicitly excludes maintainer documents. Semantic version tests covered initial, patch/minor/major, breaking footers, existing tags and annotated tags.

Bootstrap tests used real RSA/SSH key generation with mocked GitHub boundaries, covering configuration, idempotency, tag/run orchestration, failed-run retries and missing-state/dirty-tree rejection. GoDaddy/Pages tests mocked external APIs and covered DNS creation/reuse, conflicts, HTTPS enforcement and API denial without leaking fixture credentials. ShellCheck and actionlint passed for the changed shell/workflow files. Native macOS execution is configured in CI but was not executed in this Linux cloud instance.

Git reads and pushes work in this cloud environment; GitHub API requests returned proxy `Forbidden`, and no GoDaddy credentials were available. Therefore no new live signing environment, public distribution repository, custom DNS record, HTTPS certificate, release attestation or documentation deployment is claimed here. The Mac bootstrap performs those operations under owner authorization. Their live results and hosted CI results still need to be observed before advertising the URLs as available.

1. Validate BPF load/attach and real exec/connect/bind/accept/unshare outcomes on representative authorized AMD64 and ARM64 Linux VMs. Include losses, backpressure, partial-hook failure and cleanup.
2. Run native ARM64, hidepid, nested user/network/PID/mount namespace, custom-runtime and large-host tests. This instance cannot establish those compatibility claims.
3. Exercise systemd service installation/lifecycle on a real service-manager host, including the static service account and state ownership. Syntax checking alone is not daemon deployment validation.
4. Execute the BPF builder, hosted CI matrix and release attestation workflow. Configuration alone is not a successful remote workflow run.
5. Refresh the official vulnerability database before a production release; preserve advisory freshness in the release record.
6. Validate organization-specific limits, report disclosure controls, disk capacity/retention and failure alerting on actual fleet workloads. Context deadlines are cooperative and there is no universal in-process hard memory guarantee.

Static scanning is useful and validated in the stated environment. It intentionally does not implement active external reachability tests, full ACL/effective-access proofs, complete systemd/PATH configuration parsing, continuous runtime streaming, every container runtime, distributed multihop attack discovery or automatic SecureObs upload. The confirmed-exposure rule definition cannot trigger from fabricated wildcard evidence. These boundaries are documented and are not disguised as completed detection.

Existing MIT licensing remains unchanged. Documentation separation is editorial; the owner controls repository/document publication. SecureObs should consume `lasa.report/v1` through an authenticated asset/tenant mapping layer and preserve evidence, coverage, unknowns, scoring versions and suppression state as documented in the ingestion contract.
