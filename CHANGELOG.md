# Changelog

## 0.2.2 — automated publishing (2026-11-25)

- APT metadata is signed in CI by a dedicated signing subkey; packages carry the APT keyring.

## 0.2.1 — bounded memory for large scans (2026-11-24)

- Reducing an oversized report no longer builds the full JSON document to measure it, and picks the reduced file scope from each file's measured size, cutting peak memory for very broad scans from about 625–825 MB to about 410 MB. Under the example unit's `MemoryMax=512M`, such a scan now completes instead of being OOM-killed (#30).
- LASA sets the Go soft memory limit to 80% of a cgroup v2 `memory.max` when `GOMEMLIMIT` is unset (#30).
- `lasa doctor` states what each failed check affects and prints a `hint:` line, replacing the generic evidence impact text (#31).

## 0.2.0 — readable findings and reliable coverage (2026-11-24)

- Terminal output leads with a findings table (short ID, severity, priority, finding, affected resource), followed by short per-finding blocks with the observed facts, rule-specific risk and impact, fix, and a suggested command for permission findings. Diagnostics are grouped into collection gaps and items not inspected by design; caveats common to every finding appear once. Adds `--color auto|always|never`.
- HTML reports show the affected resource, observed facts and evidence on each finding card, a severity summary and findings table, grouped diagnostics and collapsed full evidence. SARIF results name the affected resource and give file findings a `file://` location.
- Builtin rules carry rule-specific prerequisites, scenarios and impacts; custom rules accept optional `scenario` and `impact`. Fingerprints are unchanged.
- Sensitive files are classified by canonical location instead of name alone.
- Policy-excluded symlinks, absent configured roots and kernel controls the kernel does not provide no longer make coverage partial.
- `lasa diff` resolves findings verified by complete evidence collectors, regardless of unrelated gaps, and reports `unknown_reasons`.
- Oversized scans omit unneeded file metadata instead of failing, and record the omission.
- JSON never encodes empty collections as `null`.
- The daemon logs new, changed and resolved findings and retention removals, and restores its baseline after a restart.
- Command errors are one line with a specific hint and name the offending flag and its valid range.
- `lasa explain` accepts unique ID prefixes and rule IDs; `report`, `explain` and `diff` read `-` from standard input; `lasa diff` adds `--format terminal` and `--fail-on-new`.
- `lasa doctor` checks `openat2` and identifies WSL2, gVisor and container environments.
- `lasa rules validate` and `lasa rules predicates`, plus a custom rules guide.
- Packages install a `lasa(1)` manual page and bash, zsh and fish completions; packaged documentation links work offline.
- Scans run through sudo can write to the invoking user's private directory and assign the report to that user. Relative `--roots` resolve against the working directory.
- A test keeps customer documentation from describing commands or flags the binary does not provide.

## Unreleased — publishing and customer website

Automated semantic versions and immutable Linux releases, reproducible DEBs/archives for AMD64 and ARM64, signed APT metadata and checksum-pinned Linux Homebrew formula updates. A macOS-compatible bootstrap configures scoped deployment/signing keys, protected-environment secrets, repositories, GoDaddy DNS and GitHub Pages HTTPS.

Added a customer-only MkDocs Material website targeting `lasa.secureobs.com`, with local search, collection/privacy/access documentation, installation/updates, CLI guidance and versioned Mike deployments. Live publishing still requires the owner's GitHub and GoDaddy authorization; native macOS/Windows scanning remains unsupported.

## 0.1.0 — initial implementation

Local bounded Linux process/socket/identity/filesystem/kernel metadata collection, provenance graph, strict typed local rules, conditional correlation and transparent prioritization. Fifteen builtin definitions include explicit unknown behavior; confirmed external exposure has no fabricated static source.

CLI scan, doctor, explain, diff, saved-report rendering, completion and daemon. Private atomic snapshots, conservative drift, justified suppressions, count retention, JSON/terminal/HTML/SARIF exports and versioned SecureObs ingestion contract.

Optional compiled CO-RE eBPF metadata sensor with feature/attachment diagnostics and bounded event windows. Privileged VM event validation remains a release gate. Linux AMD64/ARM64 build, repeated-build comparison, SBOM, deployment examples and CI/attestation configuration.

Customer and maintainer documentation are separated. Existing MIT license is retained. See the [verification record](docs/maintainer/verification.md) for actual tested platforms, skipped checks and remaining production risks.
