---
title: LASA documentation
description: Your field guide to Linux attack surface, local evidence, read-only scanning and security findings with LASA.
---

# Know your Linux attack surface.

<div class="lasa-lead" markdown>

Your field guide to exposed services, permissions and runtime evidence. Start with one Linux system. Follow a finding back to its source. Understand what was checked and where visibility was limited.

</div>

<div class="lasa-actions" markdown>

[Run your first scan :material-arrow-right:](installation.md){ .md-button .md-button--primary }
[Explore LASA](product-guide.md){ .md-button }

</div>

## From a local snapshot to a clear next step

<div class="lasa-workflow" markdown>

-   **1. Check your system**

    Install LASA on Linux AMD64 or ARM64. Use `lasa doctor` to check platform support and the visibility available to your current user.

-   **2. Understand the evidence**

    Run a read-only scan. Connect process, socket, namespace, mount and permission metadata to findings, and review any collection gaps.

-   **3. Review and follow through**

    Trace each finding to its evidence. Review recommended remediation, make changes through your own operations process, and scan again.

</div>

## Choose your next step

<div class="lasa-cards" markdown>

-   [I am new to LASA :material-arrow-right:](installation.md)

    Install with APT, Linux Homebrew or a release binary, and complete your first scan.

-   [I want to automate scans :material-arrow-right:](cli-reference.md)

    Choose scan options, export formats and exit codes for your workflow.

-   [I am investigating a finding :material-arrow-right:](results.md)

    Read severity and supporting evidence, assess uncertainty and review your next steps.

-   [I need to understand data access :material-arrow-right:](data-and-privacy.md)

    See exactly what LASA reads, what it stores and which permissions it needs.

-   [I operate Linux systems :material-arrow-right:](operations.md)

    Schedule scans, manage report retention and configure the optional systemd service.

-   [I need to resolve a problem :material-arrow-right:](troubleshooting.md)

    Understand permission errors, incomplete collection and diagnostic messages.

</div>

## Your first scan

After [installing LASA](installation.md), check your system and collect a snapshot:

```bash
lasa doctor
lasa scan
```

Save the evidence as JSON and create a self-contained HTML report for review:

```bash
lasa scan --format json --output first.report.json
lasa report --input first.report.json --format html --output first.report.html
```

## Know what your results prove

LASA reads local Linux metadata and evaluates it with local security rules. It does not exploit the host, modify security configuration, capture network payloads or upload reports. Your reports stay on your system, with no telemetry or cloud account required.

An empty findings list does not establish that a system is secure. Check the scan scope and collection diagnostics before drawing conclusions. See [compatibility and limits](compatibility.md) and [collection, access and privacy](data-and-privacy.md) for the boundaries of a scan.

## Versions and compatibility

Run `lasa version` to check the installed scanner version. Executable versions and report schema versions are separate; see [understand results](results.md) when comparing reports across releases.
