# LASA — Linux Attack Surface Analyzer

LASA is a local Linux security scanner that connects runtime exposure, privilege, isolation and sensitive resource metadata into evidence-backed, conditional risk scenarios. It explains what it observed, why a finding matters, what it could not establish and what to investigate next.

A scan is read-only. LASA does not exploit vulnerabilities, change host security settings, collect process environments or command arguments, or send telemetry. Its JSON reports and executable work without a cloud service or SecureObs account.

**Release status:** initial implementation, version 0.1.0. Static collection, correlation, CLI workflows and Linux builds have automated and local integration coverage. Privileged eBPF attachment/event delivery, host/container namespace combinations and systemd deployment require the validation described in the [engineering verification record](docs/maintainer/verification.md). This is not a claim of universal detection or completed production certification.

## Quickstart

Package and documentation publishing can be bootstrapped from macOS with `bash scripts/bootstrap-distribution.sh`. See [automated publishing](docs/maintainer/publishing.md) for GitHub/GoDaddy authorization, signing, automatic versions and recovery. The MkDocs customer site targets **https://lasa.secureobs.com**; it and package installation become available after bootstrap and the release workflow complete. Scanning still requires a Linux target.

Use Linux AMD64 or ARM64, kernel support for `openat2` (normally Linux 5.6+), and Go **1.27.4** to build:

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
- [Automated APT and Homebrew publishing from a Mac](docs/maintainer/publishing.md)

## Commands

```text
lasa scan                 Local read-only snapshot and analysis
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

The scanner has no required external services. Dependency installation and vulnerability database refresh need network access; scans do not. Do not run privileged tests on a workstation or a shared CI runner. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

The existing [MIT license](LICENSE) is retained. Selling software and support is compatible with that license; it does not restrict a recipient's rights to inspect, modify or redistribute the licensed source. A different commercial distribution model is an owner decision, described in the maintainer documentation.
