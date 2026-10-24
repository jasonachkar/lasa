# LASA — Linux Attack Surface Analyzer

LASA is a local Linux security scanner that connects runtime exposure, privilege, isolation and sensitive resource metadata into evidence-backed, conditional risk scenarios. It explains what it observed, why a finding matters, what it could not establish and what to investigate next.

LASA analyzes local evidence without exploit tests or enforcement changes. The default scan does not read process environments or full arguments. Optional inspections expand configuration/provider access explicitly and discard raw responses and argument/environment fields; see the data-access contract. LASA sends no telemetry. Its JSON reports and executable work without a cloud service or SecureObs account.

**Coverage and validation:** baseline collection, configuration inspections, correlation and report workflows have automated tests. Native kernel/provider compatibility requires validation on deployment targets, including privileged eBPF and ARM64. See the [engineering verification record](docs/maintainer/verification.md) and [automated disposable-VM validation](docs/maintainer/validation.md).

## Quickstart

Maintainers with the existing publishing keys/configuration can deploy the full release from macOS with `bash scripts/deploy-local.sh`. It builds, verifies and signs in a disposable local Linux VM, then publishes packages and MkDocs without Azure or GitHub Actions build runners. See [local deployment](docs/maintainer/local-deployment.md) for prerequisites, automatic versions and recovery. Initial GitHub/GoDaddy setup remains documented in [publishing](docs/maintainer/publishing.md). The customer site targets **https://lasa.secureobs.com**; downloads become available after a successful publication. Scanning requires a Linux target.

After the signed repositories have been published, configure a Linux target once:

```sh
curl --proto '=https' --tlsv1.2 -fsSLo install-lasa.sh https://lasa.secureobs.com/install.sh
sh install-lasa.sh
```

Then use `sudo apt install lasa`, `sudo dnf install lasa`, `sudo zypper install lasa`, `sudo pacman -S lasa` or `sudo apk add lasa` as appropriate. [Installation](docs/customer/installation.md) describes trust, upgrades, supported systems and removal. These are LASA-owned repositories; default distribution repositories require separate maintainer acceptance.

Use Linux AMD64 or ARM64, kernel support for `openat2` (normally Linux 5.6+), and Go **1.27.3** to build:

```sh
git clone https://github.com/jasonachkar/lasa.git
cd lasa
make build
./bin/lasa doctor
./bin/lasa scan
./bin/lasa scan --format json --output scan.report.json
./bin/lasa report --input scan.report.json --format html --output scan.report.html
```

Start as an ordinary user. Restricted evidence is reported as unknown. A finding-free or incomplete scan is not an assurance that a host is secure. Report files are private mode `0600`; parent directories must exist and paths must not traverse symlinks.

## Customer documentation

These documents explain the product's behavior and operational contract without walking through its implementation algorithms.

| Document | What you will learn |
| --- | --- |
| [Product guide](docs/customer/product-guide.md) | Purpose, scanning workflow, evidence and suitable use cases |
| [Installation and quickstart](docs/customer/installation.md) | Prerequisites, installation, first scan and updates |
| [Security inspections](docs/customer/security-inspections.md) | Effective configuration, identities, runtime and local firewall checks |
| [Package advisories](docs/customer/package-advisories.md) | Offline vendor-derived matching, backports, provenance and freshness |
| [Detection coverage](docs/customer/detection-coverage.md) | Detection areas, qualifications and visibility-aware changes |
| [CLI reference](docs/customer/cli-reference.md) | Every command, flag, exit code and automation example |
| [Data access and privacy](docs/customer/data-and-privacy.md) | Exactly what is read, retained, omitted and disclosed |
| [Understanding results](docs/customer/results.md) | Confidence, exposure, conditional scenarios, scoring and comparison |
| [Operations and deployment](docs/customer/operations.md) | Daemon, storage, retention, systemd and containers |
| [Compatibility and limits](docs/customer/compatibility.md) | Supported targets, visibility boundaries and unverified environments |
| [Troubleshooting](docs/customer/troubleshooting.md) | Error codes, causes, impact and corrective actions |
| [SecureObs ingestion](docs/customer/secureobs.md) | Versioned local export and future ingestion responsibilities |

## Maintainer documentation

**Maintainer material contains implementation details.** The directory split below is not an access-control boundary. The repository owner must decide which files and source to distribute. See the [maintainer index](docs/maintainer/README.md).

- [Actual output example](docs/examples/README.md)
- [Implementation plan](docs/implementation-plan.md)
- [System architecture](docs/maintainer/architecture.md)
- [Code and collector design](docs/maintainer/code-design.md)
- [Data model and schemas](docs/maintainer/data-model.md)
- [Rules and detection catalog](docs/maintainer/rules.md)
- [Rule authoring](docs/maintainer/rule-authoring.md)
- [Threat model](docs/maintainer/threat-model.md)
- [eBPF sensor and kernel validation](docs/maintainer/ebpf.md)
- [Build, tests, CI and releases](docs/maintainer/development.md)
- [Verification and production readiness](docs/maintainer/verification.md)
- [Licensing and distribution](docs/maintainer/distribution.md)
- [Automated Linux repositories and Homebrew publishing from a Mac](docs/maintainer/publishing.md)
- [Azure pipeline, one-command Mac setup and direct website recovery](docs/maintainer/azure.md)

## Commands

```text
lasa scan                 Local snapshot; explicitly selected configuration inspections
lasa advisories           Explicit advisory update or validated local import
lasa doctor               Platform, visibility and optional sensor checks
lasa explain ID --report  Evidence and explanation for one fingerprint
lasa diff OLD NEW         Coverage-aware report comparison
lasa report --input FILE  Render saved JSON without rescanning
lasa rules list           Rule metadata and conditions
lasa daemon               Sequential scheduled scans and local retention
lasa completion SHELL     Shell completion (bash, zsh, fish, powershell)
lasa version              Scanner version
```

## Development and contribution

```sh
make tools                         # pinned lint/vulnerability/SBOM tools
export PATH="$(go env GOPATH)/bin:$PATH"
make check                         # format, vet, tests, race, lint, dependency policy, vulnerabilities
make fuzz reproducible release-binaries sbom
```

The scanner has no required external services. Dependency installation and explicit advisory/database updates need network access. Scans do not make direct outbound IP requests; selected native identity providers follow host policy. Do not run privileged tests on a workstation or a shared CI runner. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

The existing [MIT license](LICENSE) is retained. Selling software and support is compatible with that license; it does not restrict a recipient's rights to inspect, modify or redistribute the licensed source. A different commercial distribution model is an owner decision, described in the maintainer documentation.

## Configuration and advisory inspections

The default scan keeps its metadata-only collection scope. Explicitly enable deeper checks:

```bash
lasa scan --inspect systemd,ssh,permissions --format json --output inspection.report.json
lasa advisories update --release trixie --output advisories.json
sudo lasa scan --profile deep --inspect all --advisories advisories.json --timeout 2m --max-inspection-items 1024
```

Read [security inspections](docs/customer/security-inspections.md), [package advisories](docs/customer/package-advisories.md), [detection coverage](docs/customer/detection-coverage.md) and the expanded [data-access contract](docs/customer/data-and-privacy.md) before enabling modules. Reports use `lasa.report/v2`; the renderer still accepts legacy v1 reports. Diffs use `lasa.diff/v2` and include surface changes and visibility-aware remediation tracking.

Maintainers: [inspection design and trust boundaries](docs/maintainer/inspection-design.md) · [automated native Linux VM validation from macOS](docs/maintainer/validation.md). The validation harness creates an isolated VM, runs real kernel/provider tests, retrieves private results and removes only its own VM. A configured validation job is not evidence that it has run.
