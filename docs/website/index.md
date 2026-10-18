# Understand your Linux attack surface

<div class="lasa-intro" markdown>

**LASA connects local runtime metadata to evidence-backed security findings.**

See what was observed, why it matters, where visibility was restricted and what to investigate next. Scans run locally, without a cloud account or telemetry.

[Install LASA](installation.md){ .md-button .md-button--primary }
[What does it access?](data-and-privacy.md){ .md-button }

</div>

## From installation to your first report

1. [Install](installation.md) with APT, the Linux Homebrew tap or a verified release binary.
2. Run `lasa doctor` as your ordinary user to inspect platform support and visibility.
3. Run `lasa scan` for a bounded, read-only snapshot.
4. [Interpret the evidence](results.md), including unknowns and collection errors.
5. Save a private JSON or self-contained HTML report when you need to share or compare results.

```bash
lasa doctor
lasa scan
lasa scan --format json --output first.report.json
lasa report --input first.report.json --format html --output first.report.html
```

## Know what runs on your machine

| Question | Read this |
| --- | --- |
| What does LASA read, and which paths does it inspect? | [Collection, access and privacy](data-and-privacy.md) |
| Does it read passwords, private keys or network payloads? | [What LASA does not collect](data-and-privacy.md#what-lasa-does-not-collect-or-do) |
| Where do reports go, and who can read them? | [Storage and permissions](data-and-privacy.md#what-is-stored) |
| When is elevated access needed? | [Installation and elevated views](installation.md#elevated-and-container-views) |
| What does a finding prove? | [Results and uncertainty](results.md) |
| How do I automate scans and retention? | [Operations](operations.md) |
| Why did a collection or command fail? | [Troubleshooting](troubleshooting.md) |

!!! note "Linux is required for scanning"
    LASA targets Linux AMD64 and ARM64 with `openat2` support, normally kernel 5.6 or later. Publishing can be managed from a Mac, but native macOS and Windows scans are not supported. Windows users can run the Linux package inside a compatible WSL distribution. The Homebrew formula requires Linux.

## Read-only collection, explicit limits

LASA reads process, socket, namespace, mount, permission and selected kernel metadata. It does not exploit the host, remediate findings, collect full command arguments or process environments, capture traffic payloads, or upload reports. Metadata can still reveal sensitive infrastructure details; reports need appropriate access controls.

A finding is a conditional risk assessment with supporting evidence. It is not proof of successful exploitation. Missing evidence remains unknown. A finding-free or incomplete scan is not a security certification. Read [compatibility and limits](compatibility.md) before deploying it across a fleet.

## Packages and documentation versions

Releases supply Linux AMD64/ARM64 binaries, `.deb` packages, archives, checksums, SBOMs and build attestations. APT verifies signed repository metadata and package hashes; the Homebrew tap pins archive checksums. See [installation](installation.md) for download verification and updates.

The version selector keeps documentation for published releases. `latest` follows the newest release; report schema versions are separate from executable versions. Choose the documentation matching `lasa version` when operating an older installation.

[Website third-party notices](assets/licenses/NOTICE.txt) cover the documentation tools and theme. Scanner dependency notices accompany release packages.
