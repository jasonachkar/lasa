---
title: LASA documentation
---

<p class="lasa-eyebrow">Linux Attack Surface Analyzer</p>

# LASA documentation

<div class="lasa-lead" markdown>

Understand what is exposed on your Linux systems. Install LASA, run your first scan, and turn local runtime evidence into actionable security findings.

</div>

<div class="lasa-actions" markdown>

[Install LASA :material-arrow-right:](installation.md){ .md-button .md-button--primary }
[Explore the product guide](product-guide.md){ .md-button }

</div>

<div class="lasa-facts" markdown>

<span>:material-linux: Linux AMD64 & ARM64</span>
<span>:material-shield-check-outline: Read-only collection</span>
<span>:material-lock-outline: Local reports. No telemetry.</span>

</div>

## Find your way

Everything you need to install, use and operate LASA, with clear explanations of the evidence it collects.

<div class="lasa-cards" markdown>

-   :material-download-outline: **Install and get started**

    Set up LASA with APT, Linux Homebrew or a release binary, and check your system's visibility.

    [Installation and first use :material-arrow-right:](installation.md)

-   :material-console: **Run a scan**

    Explore commands, scanning options, report formats and exit codes.

    [CLI reference :material-arrow-right:](cli-reference.md)

-   :material-file-search-outline: **Understand your findings**

    Follow the evidence behind each result, assess severity and identify your next steps.

    [Read and interpret results :material-arrow-right:](results.md)

-   :material-shield-lock-outline: **Know what LASA accesses**

    See what the scanner reads, what it stores and how your data stays on your systems.

    [Collection, access and privacy :material-arrow-right:](data-and-privacy.md)

-   :material-server-outline: **Deploy and operate**

    Schedule scans, manage report retention and configure the optional systemd service.

    [Operations guide :material-arrow-right:](operations.md)

-   :material-lifebuoy: **Resolve a problem**

    Understand permission errors, missing evidence and collection diagnostics.

    [Troubleshooting :material-arrow-right:](troubleshooting.md)

</div>

## Your first scan

<div class="lasa-steps" markdown>

### 1. Check your system

After [installing LASA](installation.md), check platform support and the visibility available to your current user.

```bash
lasa doctor
```

### 2. Collect a snapshot

Run a bounded, read-only scan. The terminal report explains findings and highlights any collection gaps.

```bash
lasa scan
```

### 3. Save and explore the evidence

Save a JSON report and turn it into a self-contained HTML report for review. Report files stay on your system.

```bash
lasa scan --format json --output first.report.json
lasa report --input first.report.json --format html --output first.report.html
```

</div>

## Understand the scope

LASA connects process, socket, namespace, mount, permission and selected kernel metadata to security findings. Each result explains what was observed and where visibility was limited. It does not exploit the host, modify its security configuration, capture network payloads or upload reports.

- [Product guide](product-guide.md) — capabilities and common workflows.
- [Compatibility and limits](compatibility.md) — supported systems and collection boundaries.
- [Collection, access and privacy](data-and-privacy.md) — inspected paths, stored data and permissions.
- [SecureObs and local exports](secureobs.md) — working with reports outside the scanner.

## Documentation versions

Use **Current documentation** for the maintained product guide, or select a numbered release to match the output of `lasa version`. Executable versions and report schema versions are separate; see [understand results](results.md) when comparing reports across releases.
