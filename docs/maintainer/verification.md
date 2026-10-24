# Engineering verification and release readiness

[Maintainer index](README.md)

Verification date: **2026-10-18**. Scanner version: **0.1.0**. This records executed work, not a claim that every production environment is supported.

Current builds require **Go 1.27.3** after the GO-2026-6809 security update. Earlier runs below retain their original toolchain versions as historical evidence.

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

## Security inspection extension (2026-10-23)

This extension adds eight opt-in inspection modules, 18 additional rule definitions (33 total), identity/ACL-aware discretionary permission candidates, exact-release offline package advisory matching, scope-aware finding/surface drift, report v2 and bounded daemon disk retention. The legacy v1 report remains readable. The earlier v1 integration recommendation above is historical; new consumers must implement the current v2 ingestion contract. The new inspection design supersedes earlier statements that configuration/ACL inspection is entirely absent, while retaining its documented limits.

Executed against this source in the restricted Linux workspace:

- Go formatting, vet, all unit/integration/end-to-end tests, race detector, staticcheck and module verification passed with Go 1.27.2. All 33 rule definitions have positive, negative, missing, unknown, not-applicable and conflict fixtures. Pipeline tests exercise native-provider fixtures through findings, graph and all four export formats, including secret omission.
- Eleven bounded fuzz targets passed, including new ACL, native package comparison, configuration and nftables parsers. Repeat builds matched for Linux AMD64 and ARM64; both release binaries cross-compiled.
- ShellCheck passed for all shell scripts and actionlint passed with the dedicated self-hosted runner label declared. VM helpers were reviewed for child namespace guards and fixture-only resource cleanup; this is not execution of those privileged helpers.
- Strict MkDocs builds and real isolated Mike deployments passed for 13 customer pages. Version archives, default aliases, APT files, Homebrew formula, CNAME and `.nojekyll` survived publication. Maintainer content was excluded.
- Chromium exercised all 13 pages, dark default, all three sidebar groups, keyboard/local search, theme persistence, clipboard and widths 320–1920px without script errors or external asset requests. Footer checks across six viewport sizes and the 404 page preserved sidebar height. Axe WCAG A/AA checks found no violations on six representative pages in both themes; this is an automated check, not an accessibility certification.

Not executed or blocked:

- The explicit privileged DAC/native-SSH tests correctly skipped without `LASA_PRIVILEGED_TESTS=1`. This sandbox does not establish native systemd, Docker provider, kernel eBPF, namespace/hidepid or disk-full VM compatibility. The new Mac Multipass wrapper and disposable Linux harness make the supported native checks reproducible; actual VM results still need to be recorded for each target architecture/distribution/kernel/provider.
- Native system-tool execution is refused where the sandbox presents executable ancestry as non-root-owned. That is the intended trust boundary, not a reason to weaken the production check. Native package-comparator cross-checks use the separate fixture test command.
- A current official `govulncheck ./...` was attempted and failed because the environment proxy returned `Forbidden` for `https://vuln.go.dev/index/modules.json.gz`. No current clean vulnerability result is claimed. Refresh/check through an authorized network before release; an older cached snapshot cannot establish current status.
- The environment cannot publish to the distribution repository or validate the live custom-domain/HTTPS deployment. Source builds and isolated publication passed; live deployment uses the owner's existing authenticated Mac publisher and preserved signing/deploy keys.


## Native Linux distribution extension (2026-10-23)

The package pipeline now produces DEB, RPM, Arch and APK artifacts for Linux AMD64/ARM64 and publishes APT, RPM/DNF/YUM/Zypper, Pacman and APK repositories alongside Homebrew and versioned docs. This is LASA-owned repository automation, not acceptance into default distribution repositories. Existing OpenPGP/deploy keys are preserved; the Mac bootstrap prepares a separate persistent Alpine RSA key and encrypted provider configuration.

Executed checks for this extension:

- Real repeated unsigned package/archive builds matched for both architectures. Signed builds verified the expected OpenPGP primary identity and Alpine public-key pin, produced native package signatures, and generated manifests covering all formats. Both architecture repositories were indexed and verified; unsigned/native-signature omissions are rejected before publication.
- A real isolated APT client accepted signed indexes and downloaded matching DEBs for both architectures, then selected/downloaded the newer version from updated authenticated metadata. Repeat publication, changed-byte rejection, lower-version rejection and invalid installer keys were exercised without changing the host APT database or trust store.
- Pinned native Fedora 43 DNF, openSUSE Leap 15.6 Zypper, Arch Pacman and Alpine 3.22 APK clients installed an actual `0.0.0` scanner, upgraded to an actual `0.0.1` scanner from updated signed repositories, verified the reported binary versions, removed LASA and rejected tampered repository metadata. Containers had no network and mounted only public fixture repositories; private fixture signing keys stayed outside. Filesystem-only capabilities allowed native installation inside the disposable containers. No host package database or trust store changed. The Leap image tests an older client; this does not endorse running an unsupported/EOL operating system.
- Python tests used real OpenSSL RSA/SHA-256 verification for APK framing and checked that malformed, truncated or already-signed inputs are not replaced. Azure orchestration tests and the Mac-compatible Bash bootstrap tests passed, including preservation of existing keys and rejection of missing local Alpine state when a remote secret exists.
- ShellCheck/actionlint passed. Strict MkDocs/Mike tests preserved the added RPM, Arch and APK directories as well as APT, Formula, CNAME and release archives. Browser navigation/search/theme/clipboard/responsive checks and automated accessibility checks passed with the expanded installation content.

An additional real runtime-provider check used the available Docker 28.4.0 UNIX API and a short-lived hardened Alpine fixture. `inspect.containers` completed and persisted the selected configuration asset without retaining its synthetic environment secret. This supersedes the earlier statement that no real Docker provider was queried; it validates that particular read-only provider case, not every runtime version or privileged-container consequence.

These results do not replace privileged VM/kernel/provider validation or native ARM64 runtime tests. The current official Go vulnerability lookup remains blocked by the proxy as recorded above. No live distribution/domain publication or new production release was possible with the cloud workspace's credentials. Source commits and isolated publication tests are separate from a successful owner-authorized deployment. The updated owner bootstrap configures the additional key/pipeline variables; stable package publication remains restricted to trusted `main` runs.


### Azure authorization recovery

The Azure bootstrap now supports `--reauth` and an explicit `LASA_AZURE_TENANT`. A read-only preflight checks project/organization access before key preparation/export or remote configuration writes. Microsoft tenant hints are restricted to GUIDs from known authentication authorities and one retry; forbidden projects are not treated as missing. Errors distinguish organization authentication from project authorization while suppressing response bodies and credentials. The 26 Python tests, shell syntax/ShellCheck and actionlint passed locally; the owner's live Azure 403 cannot be resolved or validated from this workspace's account.

Azure redirect recovery adds explicit JSON/federated-auth suppression headers, classified but unfollowed sign-in redirects, bounded response handling and a closed allowlist of safe Azure service codes. All 34 Python tests passed, including an actual local HTTP redirect test proving that the client never requests the redirect destination with the fixture bearer token. Tests cover redirect/session redaction, initial-browser-sign-in diagnostics, HTML and oversized responses, and refusal to treat authentication redirects as absent projects. Live organization authorization remains an owner-account check; no access or tenant membership is inferred merely from a changed HTTP status.

### Azure DevOps PAT recovery

Explicit `--devops-pat` mode uses a short-lived credential issued by the organization owner's browser account, avoiding CLI tenant/subscription selection. The wrapper accepts hidden terminal input or an existing secret-manager-provided `AZURE_DEVOPS_EXT_PAT`, withholds the latter from setup tool subprocesses, and removes it from Python's environment before child processes. The bootstrap PAT is never copied into provider credentials or private state. Organization/project checks remain read-only and precede key preparation/export; PATs cannot grant missing membership or bypass organization policy.

All 51 Python tests passed, including 17 additional PAT/input/authentication/isolation checks. An actual Bash wrapper run with fixture tools verified that only the Python bootstrap receives the injected PAT and no Azure CLI installation occurs in PAT mode. A real loopback HTTP test verified Basic authentication to the original fixture endpoint and no request or credential forwarding to its redirect destination. Tests also exercised rejected PATs without tenant retries or key mutations, insufficient project scopes, anonymous/missing-project handling, refusal of echoing/noninteractive input, cancellation, redaction and exclusion from pipeline/service-connection payloads. Shell syntax, ShellCheck, Python compilation and actionlint passed. No owner PAT or live Azure organization access was available here; successful local checks do not establish live setup, hosted capacity or deployment.

### Azure HTTP contract and direct-entrypoint corrections

Reviewed Microsoft's `azure-devops-python-api` SDK at `86c9a559fc4ab309df21e674b236a542f9e77f89` and Azure CLI extension at `429a129a69306ae7377684b00660dd3521a126ea`. The bootstrap omitted the SDK's `X-VSS-ForceMsaPassThrough` header and used one default API revision across independently versioned endpoints. The client now includes both SDK authentication headers and the specific connection, service-endpoint, queue and permission revisions. This establishes a source-contract correction; it does not establish which condition caused the owner's live 401/403.

The Python entrypoint now parses the same authentication/operation flags as the wrapper, obtains the existing GitHub CLI credential when needed and stops before key preparation if unavailable. Read-only `--check` requires neither GitHub credentials nor private publishing state. The wrapper identifies its revision/failure stage, avoids GitHub authentication and Git fetches in check mode, and keeps PAT isolation in both check and setup modes. Existing hosted queues and pipelines are validated before credential-bearing service-connection writes.

All 64 Python tests passed with resource warnings enabled, including 13 additional HTTP-contract, entrypoint, response-cleanup and credential-prerequisite regressions. Real loopback HTTP fixtures exercised both bearer and Basic setup requests, enforced the SDK header/API revisions, rejected the former connection revision, verified preflight before missing-project creation and reported a resource-specific 403 without printing its body. HTTP error/redirect streams now close; the warnings reproduced before that fix were absent in the final suite. Fixture requests are not a live Azure service test. Shell syntax, ShellCheck, actionlint, Python compilation and whitespace checks passed. A direct public Azure connectivity probe was blocked by this workspace's network proxy (CONNECT HTTP 403), so live organization access, owner credentials, hosted capacity and deployment remain unverified here.

### GitHub build-definition validation correction

The owner subsequently reached `POST .../_apis/build/definitions` and received HTTP 400. Reviewed the Azure CLI's `_create_repo_properties_object` / `_create_pipeline_build_object` at the revision above: the previous payload omitted `repository.properties.apiUrl` and the provider branch property and used the clone URL rather than the canonical repository URL. The payload now includes those provider fields, an explicit root folder for new definitions, and a YAML CI trigger for new definitions. Updates retain the revision/folder/custom triggers. This corrects a source-contract difference; the suppressed original Azure response does not prove which validation condition caused that live 400.

The exact GitHub credential copied to Azure now gets a source-YAML read check before key preparation/export. An explicitly unready Azure GitHub connection stops before writing a build definition. Bounded error parsing emits closed validation classifications, known field paths and numeric YAML locations without printing arbitrary exception names/messages, YAML values or credential material.

All 71 Python tests passed, including seven additional missing-provider-field, update-preservation, unready-endpoint, copied-credential, pre-mutation YAML-check and diagnostic-redaction regressions. The loopback HTTP fixture rejects the former missing-`apiUrl` payload with a field-specific 400, while the updated create payload passes for bearer and Basic clients. This is a regression fixture, not proof of live Azure acceptance. The actual `azure-pipelines.yml` also passed JSON Schema validation using Microsoft's `azure-pipelines-vscode/service-schema.json` (schema `v1.261.1`, repository revision `e8090fd525cd6ba47d7685c698f3f51983e298c6`). That validates YAML structure, not Azure task availability, provider permissions or hosted capacity. Shell syntax, ShellCheck, actionlint, Python compilation and whitespace checks passed. Live owner pipeline creation remains unverified from this workspace.

### Service-connection retry ownership correction

The owner next encountered the exact-description ownership guard. The previous implementation checked one field in a list projection and did not write the project-reference description. The bootstrap now fetches project-scoped details, writes markers in the supported endpoint data and both description locations, and verifies type, public GitHub URL, explicit non-shared status and project bindings before a managed credential update. Unknown provenance is not automatically adopted: an independent `LASA-GitHub-bootstrap` connection is created once and used for LASA while the original remains unchanged. Ambiguous, cross-project, shared or conflicting connection metadata is not used to authorize a credential overwrite.

All 79 Python tests passed with resource warnings enabled. Eight additional regressions exercise project-reference-only descriptions, omitted list metadata, automatic fallback/pipeline wiring, stable repeated recovery, unknown/shared/wrong-target/cross-project protection, reserved-name collisions and malformed metadata. Real loopback HTTP tests create/reuse the project-description-only connection and recover an unmarked legacy connection without updating its credentials or creating more fallback connections on retry. Existing orchestration fixtures now persist actual connection payloads and return list projections separately from detail responses. Shell syntax, ShellCheck, actionlint, Python compilation and whitespace checks passed. These checks cover the retry contracts; live Azure metadata persistence and pipeline creation remain owner-account checks.

## Manual local publishing from macOS

`scripts/deploy-local.sh` now prepares a disposable Ubuntu 24.04 Multipass publisher on the owner's Mac. The orchestrator verifies source/state/Pages/deploy-key prerequisites, carries Git history through a bundle, runs verification before sending owner credentials, selects local publishing, streams a bounded private guest payload through Multipass stdin and removes its specifically named VM. A filesystem lock plus an owner-private recovery journal handles concurrent/interrupted Mac runs. Existing publishing identities are preserved. The shared release engine retains the Azure entrypoint and adds current-branch local releases with provider/source checks and explicit tag-to-commit verification. Local mode guards source GitHub hosted verification/release/docs jobs, while published hosting remains GitHub Releases/Pages.

Executed checks:

- All 99 Python tests passed with resource warnings enabled, including 20 local-publishing cases. Actual Git repositories, branch/tag bundles, generated fixture OpenPGP/Alpine/SSH material, private file permissions, stdin credential transport and the real guest credential loader were exercised with fixture GitHub/Multipass services. Tests reject failed/mismatched verification before credential transfer, preserve original fixture keys, withhold secrets from argv/MultiPass environments/error output, delete the guest credential file and clean up only journaled VMs.
- Shared release orchestration fixtures exercised new tag/draft/all-format upload/publication, existing OpenPGP/GitHub release reuse without rebuild, source advancement, changed provider and a release tag belonging to another commit. New-release fixtures emit dummy package bytes and fixture signatures; native package/signature integrity is established by the separate real signing/package tests, not those lifecycle fixtures.
- Strict MkDocs/Mike tests passed with all 13 customer pages, maintained/current and numbered aliases, legacy redirects, package/domain preservation and rollback rejection. Maintainer-only deployment instructions stayed excluded from the site. Existing versioning, domain, bootstrap provisioning/retry/identity and real OpenPGP provenance/tamper tests passed.
- ShellCheck passed for every shell script, actionlint passed, Python compiled and whitespace checks passed. The pinned GitHub CLI 2.83.2 official checksum file was retrieved for both architectures; the AMD64 archive matched its literal SHA-256, executed successfully and exposed `gh attestation verify`. ARM64 archive execution was not performed.

Not executed here: actual macOS/Homebrew/Multipass installation, a real disposable Ubuntu publisher, Ubuntu guest provisioning, native ARM64 package clients or the ARM64 static-QEMU matrix, full owner release/signing/Pages deployment, or a new current vulnerability-service result. Those require the owner's Mac/network/credentials. QEMU is explicitly labeled emulated AMD64 coverage and does not replace native ARM64 validation. Earlier privileged kernel/provider and vulnerability-service limitations remain applicable. Fixtures and source changes are not reported as a successful owner deployment.

## Go standard-library security patch: GO-2026-6809

The owner's live local deployment found GO-2026-6809 (`crypto/x509` intermediate-certificate distrust) in Go 1.27.2 and stopped during verification, before transferring publishing credentials. The reported fixed toolchain is Go 1.27.3. The module minimum, Makefile pin, local publisher and validation VM downloads, GitHub/Azure toolchain selections, BPF toolchain guidance and current documentation now require 1.27.3. Historical execution records above retain the versions actually used. The vulnerability gate remains mandatory.

The official Go HTTPS manifest was retrieved and its Linux AMD64 1.27.3 archive was downloaded, verified against SHA-256 `65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40` and installed only in the writable workspace. Formatting, vet, unit/integration/end-to-end tests, race checks, staticcheck and module allowlist/checksum verification passed with this toolchain. An initial staticcheck cache write was blocked by the workspace's read-only home directory; rerunning that remaining check with a writable `XDG_CACHE_HOME` passed. Repeated builds matched for Linux AMD64 and ARM64, and both release-binary metadata records explicitly reported `go1.27.3`. Native ARM64 execution was not performed.

All 99 Python tests, ShellCheck/actionlint, whitespace checks and a strict 13-page MkDocs build passed. A live `govulncheck ./...` was attempted with Go 1.27.3 but the environment proxy denied `https://vuln.go.dev/index/modules.json.gz` (`Forbidden`). Consequently no current clean vulnerability result or complete `make check` success is claimed here. The owner must rerun normal local deployment, whose live vulnerability check remains in place; no advisory suppression, old database fallback or verification bypass was added. No owner release, key rotation or hosted deployment was performed from this workspace.

## Documentation interpreter and cross-user permissions correction

The owner's next run completed package generation and failed at the Python tests with `python: command not found`. The local worker had created its documentation virtual environment as root while inheriting `umask 077`; a reproduction confirmed that both the venv and its `bin/` directory were mode `0700`. The ordinary `ubuntu` account could not traverse the prepared environment. A system `python3` fallback alone would not repair inaccessible MkDocs/Mike dependencies.

The dedicated public-environment installer now creates a fresh documentation venv under its own `umask 022`, leaving the caller's private mask and existing state unchanged. Preparation tests imports and CLI execution as `ubuntu`; verification tests them again before Go compilation. Worker Python commands use the absolute prepared `python3` path, forwarded through `PYTHON` to shared docs scripts. Existing directories are not repermissioned, and private credential modes remain unchanged.

All 103 Python tests passed, including four offline real-venv/pip regressions covering a restrictive caller mask, a disabled bare-Python alias, readable modules/CLI scripts, missing interpreter/dependencies and preservation of an existing private directory/key. Strict MkDocs/Mike publishing tests passed with `PYTHON` explicitly selected and bare `python` replaced by a failing command. Actual MkDocs 1.6.1/Mike 2.2.0 readiness checks, ShellCheck, actionlint and whitespace checks passed.

A separate disposable, network-disabled Python 3.12 container (`python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704`) reproduced denial of root-created `0700` venv access to another UID. The corrected installer installed a local fixture wheel as root; the other UID imported its modules and executed both fixture console scripts successfully, while separate private fixture state/key modes remained `0700`/`0600`. Only SETUID/SETGID capabilities and a read-only public fixture mount were supplied; no owner keys, network, host package changes or live publication were involved. The fixture validates the cross-user permission boundary; actual Ubuntu/Multipass setup and owner deployment still require the owner's local run.

## Ubuntu Arch repository generator compatibility

The owner's next distribution test passed OpenPGP verification but failed because Ubuntu 24.04's `repo-add` 6.0.2 treats the unsupported `--include-sigs` option as the database filename. Pacman 6 includes package signatures automatically; 7 requires this option explicitly. The publisher now selects arguments by the identified tool generation, retaining downgrade prevention. It independently validates package identity, version, filename, SHA-256 and embedded detached signature in both generated indexes before they can be signed or published. Existing GPG verification remains mandatory.

All 107 Python tests passed, including option-contract regressions for both generations, unsupported-version and missing-input rejection, and missing, mismatched or malformed embedded signatures and package metadata. ShellCheck, actionlint and whitespace checks passed. Real repo-add scripts and matching libraries from Ubuntu 24.04 (6.0.2), the existing native tool set (7.0.0), and the cached official Arch container (7.1.0) ran on the Linux AMD64 host with newly generated fixture GPG signatures. Both x86_64 and aarch64 package indexes and repeat generation passed for every version; the original unsupported-option failure was reproduced with 6.0.2. This checks ARM64 package metadata, not native ARM64 execution. Fixture signing keys were isolated and deleted; no owner keys or live hosted deployment were involved.

The complete `test/distribution.sh` integration passed with Ubuntu's actual 6.0.2 generator and matching libraries selected on the Linux host. This covered reproducible packages, signed repository generation, repeat publishing and upgrades, real isolated APT downloads for both architectures, and AMD64 DNF/Zypper/Pacman/APK install, upgrade, removal and tampered-metadata rejection in disposable offline containers. The host's extracted RPM tools needed their matching `RPM_CONFIGDIR` before that complete run; the Ubuntu publisher installs these tools into their normal system paths. No package-manager signature requirement was disabled. This was a fixture distribution test, not an owner release, macOS/Multipass run or new vulnerability-service scan.

## Local deployment architecture and failure-boundary review

The owner's next ARM64 run reached an implicit image pull for the deliberately AMD64 package-client matrix. A real ARM64 pull of the pinned Arch image reproduced `no matching manifest`. Image acquisition and execution now both select a platform explicitly, validate cached image architectures, and execute each required tool before compilation. Tests and publication share the image selection helpers. The review also reproduced classic Docker's `cannot overwrite digest` failure when switching Alpine architectures under one index reference; distinct platform manifests from the existing reviewed index now allow both variants to coexist.

The AMD64 and ARM64 Alpine manifests were resolved from index `sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f`: respectively `sha256:dc92f017beea8e7f43263073d717f7bc011228c95d5312e440deb4d035bb4eec` and `sha256:3e07a4f627d12468155eb812785e10f2453a447c346872b47788a62437366764`. Both platform images were pulled successfully and remained usable without deleting caches. With the official Ubuntu 24.04 QEMU 8.2.2 static interpreter explicitly mounted, ARM64 Alpine reported `aarch64`, verified signed x86_64/aarch64 fixture packages and generated both architectures' APK indexes; their actual package/version/architecture records were inspected. No host-wide emulator registration was installed. This is emulated ARM64 tool execution on AMD64, not native ARM64 client certification.

Ubuntu's downloaded QEMU package supplied systemd `binfmt.d` rules and the expected `OPF` flags. ARM64 guest preparation now reloads `systemd-binfmt.service` and checks the enabled AMD64 handler's `F` flag, replacing the legacy registry command. Actual systemd registration inside an ARM64 Multipass VM was not executed here; the subsequent runtime probes remain mandatory in the owner's deployment.

All 113 Python tests passed, including six new shell-helper tests for explicit selection despite an ARM64 Docker default, native ARM64 versus emulated AMD64 clients, separate Alpine references, wrong cached architectures, pull-result mismatch, registry/runtime/daemon failures and missing emulation registration. The unchanged Linux worker also ran in a disposable, network-disabled Ubuntu 24.04 container with only its VM-detection and downstream command boundaries simulated. Injected documentation-readiness, container-preflight and Go-check failures produced their exact stage diagnostics, stopped further commands and removed stale verification approval. Approval is invalidated before even the Python readiness check. This regression runs automatically before compilation in normal local verification. It does not provision or simulate successful production publication.

Strict MkDocs/Mike build/version/archive/repository-preservation tests, distribution bootstrap/key-preservation fixtures, automatic versioning, domain/HTTPS error-path fixtures and real OpenPGP provenance/tamper tests passed. GitHub/DNS/Multipass boundaries in those fixtures remain explicitly simulated. ShellCheck, actionlint and whitespace checks passed. Owner keys, unrelated Pages sites and live releases were not changed. The current Go vulnerability-service gate remains mandatory; no new clean vulnerability-service result or complete owner macOS/Multipass deployment is claimed by this review.

The full real distribution test passed with `DOCKER_DEFAULT_PLATFORM=linux/arm64` on the AMD64 host, including reproducibility, signed first/repeat/newer-version publication, APT downloads for both architectures and native AMD64 DNF/Zypper/Pacman/APK install/upgrade/remove/tamper rejection. After resolving all remaining image pins to platform manifests from their existing indexes (including both Ubuntu fixture architectures), the real client matrix and Ubuntu worker failure tests passed again with that deliberately conflicting Docker default. The manifest references retain the prior reviewed image bytes; the catalog's seven digest/platform pairs were checked against the original index manifests. The strict customer website build passed after adding the maintainer review; all 13 customer pages were prepared and maintainer content remained excluded.

## QEMU crash: native clients and bounded execution

The owner's subsequent Apple Silicon run completed Fedora install/upgrade/removal, then reported `x86_64-binfmt-P: QEMU internal SIGSEGV {code=MAPERR, addr=0x20}` around its remaining rejection test. Registered emulation and version probes had not established full cryptographic-path compatibility. The local publisher now installs no QEMU and selects native Fedora/openSUSE/Alpine images for either host architecture. ARM64 Pacman/libalpm protocol checks use a native Ubuntu fixture built from a pinned platform base and Ubuntu-signed packages; AMD64 retains its official Arch client. The fixture does not claim Arch ARM OS compatibility. Both scanner artifact architectures continue to be built and indexed.

Every client scenario has a five-minute limit, readiness/indexing has 60 seconds, and the worker failure fixture has 30 seconds per case. Docker metadata/daemon checks have 30 seconds, pulls five minutes, and fixture builds ten minutes. The container runner captures the ID from `docker create` stdout into a caller-owned private file, starts the recorded container under a deadline, and removes that exact ID on exit/interruption. This also avoids root-owned CID-file permissions when the guest Docker CLI runs through sudo. Expected rejection now requires a nonzero result and a matching verification diagnostic, excluding signal exits and emulator/crash text. Positive Pacman hook/transaction diagnostics also fail even if Pacman returns zero. `SYS_CHROOT` is confined to the public-fixture Pacman container so native libalpm hooks can execute.

All 117 Python tests passed, including native-only ARM64 selection/build/cache cases and real shell regressions injecting a stalled process, exit 139, a QEMU SIGSEGV with misleading GPG text, unexpected success and unrelated failure. Deadline tests completed within their external five-second guard and removed only the recorded fixture ID. The nine platform pins were checked against their original reviewed index manifests. ShellCheck/actionlint and whitespace checks passed.

The complete distribution integration passed on the AMD64 host with an intentionally ARM64 Docker default: reproducible packages, signed first/repeat/upgrade repositories, both-architecture APT downloads and actual DNF/Zypper/Pacman/APK installation/upgrade/removal/rejection. The native Ubuntu Pacman fixture was built from the committed Dockerfile and exercised with real signed packages for install/upgrade/remove/tamper rejection. Initial fixture testing exposed missing `SYS_CHROOT` and Pacman's misleading zero exit on hook failure; the corrected capability and positive-error checks passed. DNF's negative case retains full diagnostic output because quiet mode suppressed the required signature evidence. After the final create/start lifecycle change, the real AMD64 matrix and both-architecture Alpine signature/index commands passed again with the bounded runner.

The cloud's Docker build sandbox could not resolve its ambient proxy hostname; the actual Ubuntu package-install build was validated using the workspace's public egress proxy by IP. No such workspace-specific proxy is committed or required by the guest. The production factory's base/Dockerfile-derived tag and cached build path were also exercised. Native ARM64 full-matrix execution and real macOS/Multipass orchestration were not available here; ARM64 command selection is fixture-tested and runtime gates remain in the owner's deployment. No owner key, hosted release, Pages configuration or current vulnerability gate was changed.
