# Product guide

[Documentation home](../../README.md)

## The problem LASA helps investigate

Linux security depends on combinations of conditions. A listener, a root process and an enabled kernel feature have very different implications depending on how they relate. LASA organizes local evidence so an operator can prioritize combinations that deserve attention: for example, a potentially reachable process that also carries powerful initial-user-namespace capabilities.

LASA is useful for host posture reviews, workload privilege reviews, pre-deployment checks, incident triage and tracking the effect of hardening changes. It is a point-in-time evidence tool, not an incident response verdict, vulnerability exploit framework, malware detector or replacement for a firewall policy review.

## What happens during a scan

1. LASA determines its visible Linux scope and records the time and host identity context.
2. It collects bounded process, socket, namespace, kernel-control and explicitly scoped file metadata.
3. It connects evidence that refers to the same visible subjects.
4. It evaluates reviewed local rules, preserving unknown and conflicting evidence.
5. It emits findings, supporting observations, conditional risk scenarios, coverage and diagnostics.

There is no active network reconnaissance or direct outbound discovery request during a scan. Optional native providers and advisory management have the separate access contract below. Local socket information is read from the kernel; LASA does not try connecting to each service. The optional sensor observes a finite event window and is requested explicitly through the sensor profile.

## Facts, deductions and scenarios

A fact might establish that a process owns a TCP listener or that a file has a particular permission mode. A deduction may associate a conventional management port with that process. A scenario explains a possible consequence **if** an attacker first obtains the necessary access or control.

Those are different kinds of statements. A wildcard listener is potentially reachable outside loopback, but its internet reachability is unknown. An SSH authorized-key file with permissive metadata might still be rejected by SSH. A container-looking cgroup name is a hint rather than proof of a container runtime boundary. LASA includes these qualifications in the relevant finding.

## Profiles

| Profile | Intended use | Privilege behavior |
| --- | --- | --- |
| `standard` | Safe baseline in the current visible Linux namespaces | Ordinary user; no elevation |
| `deep` | Explicitly authorized higher-visibility host metadata inspection | Requires effective UID 0; still subject to capabilities and policy |
| `container` | An explicitly acknowledged container view | Does not add host access |
| `sensor` | Static snapshot plus a finite eBPF metadata event window | Requires separately authorized kernel prerequisites; failures remain visible |

Deep does not turn off security controls, connect to runtime sockets, read credentials or recursively crawl the whole filesystem. Root in a restricted container does not become host root merely by selecting a profile.

## Reading the outcome

Review the declared scope and collection diagnostics before interpreting findings. A scan may successfully write a useful report while some checks remain incomplete. Enable `--strict` when automation must distinguish this state through the process exit code.

For each finding, examine its observed evidence, prerequisites, confidence, uncertainty and recommended remediation. Verify impact and maintenance constraints before changing a production service. LASA does not execute remediation actions.

## Where the product fits

Reports are usable on their own, in a local operations process, or by a future SecureObs ingestion service. LASA does not require a backend, a graph database or an always-running agent to perform a one-shot scan. It does not monitor activity continuously unless an operator arranges repeated sensor windows; scheduled windows can have observation gaps.

See [data and privacy](data-and-privacy.md), [result interpretation](results.md) and [compatibility](compatibility.md) before deploying it fleet-wide.

## Effective configuration and advisory inspection

Use `--inspect` to add supported systemd, SSH, sudo, discretionary permissions, nftables, Docker-compatible runtime, package-advisory and scheduler checks. Modules emit evidence and coverage into the same report and finding workflow. These modules can read selected configuration/native-provider output beyond the default metadata sources; they do not run exploit tests or apply remediation.

Start with [security inspections](security-inspections.md), prepare [package advisories](package-advisories.md) if needed, and review [detection coverage](detection-coverage.md). Configuration changes and advisory data remain subject to their provider and freshness requirements. A larger enabled scope is not a guarantee that every security condition can be decided.

## Inspection-specific diagnostics

| Code or symptom | Why it happens | Action |
| --- | --- | --- |
| `NATIVE_TOOL_UNTRUSTED` | A native executable or ancestor is writable or is not root-controlled in this namespace | Review the named owner/mode and deployment namespace; use trusted system tools without weakening validation |
| `INSPECTION_TIMEOUT` | A native provider exceeded its deadline | Check manager availability/load and deliberately adjust command/scan deadlines if appropriate |
| `INSPECTION_UNSUPPORTED` | Syntax, provider version, namespace, packet context or advisory coverage cannot be interpreted safely | Read the named module's boundary; preserve the unknown result and inspect independently |
| `RESOURCE_LIMIT` | Work, native output, response or evidence budget was exhausted | Narrow the selected scope or deliberately adjust documented work limits; retain incomplete coverage |
| `COLLECTOR_INTERNAL_ERROR` | A collector encountered an internal panic | Other collectors can finish; report the component, scanner version and stack fingerprint privately to the maintainer |
| Native query failure | Missing tool, denied policy query, inaccessible manager/runtime, or rejected configuration | Review the target and safe cause/location. Raw native output is withheld when it may disclose secrets |
| No package vulnerability result | Advisory file is missing, stale, expired, malformed or for a different release | Refresh through the approved updater/vendor process; do not relabel stale timestamps |
| Byte-retention failure | The newest snapshot alone exceeds the managed byte quota | Increase the quota or reduce report scope; the snapshot is retained and failure remains visible |
| Disk-space preflight/write failure | Available space or filesystem permissions do not meet persistence requirements | Restore capacity/permissions, preserve existing reports and restart through the supervisor |

The scanner does not automatically upgrade native tools, change firewall policy, reset runtime permissions or elevate to make a diagnostic disappear. See [security inspections](security-inspections.md) for the exact provider requirements.


## Package-manager installation

If APT reports `Unable to locate package lasa`, or another manager reports no matching package, enable LASA's signed repository using [installation](installation.md). `apt install` cannot find a package in an unconfigured repository. Run the setup script only after the repository has been published; a website being available does not establish that a package release completed.

If a repository/index URL returns 404, check the source URL, architecture, release/publishing status and HTTPS certificate. The generated `https://lasa.secureobs.com/distribution.json` identifies the published native formats/version. During a new deployment, stale CDN caches can briefly disagree; retry after propagation rather than disabling verification.

Key fingerprint/hash mismatches, invalid metadata signatures, missing package signatures and package-hash errors are fatal trust failures. Retain the diagnostic and expected fingerprint, check proxy/cache behavior and contact your repository administrator. Do not use `--nogpgcheck`, `--allow-untrusted`, insecure TLS or a replacement key from an unverified message. The setup script stops at conflicting LASA-owned configuration files so an administrator can review ownership.

The Arch setup performs a full upgrade to avoid partial upgrades. Package installation does not start a scanner. If an installed binary fails `lasa doctor`, inspect kernel/syscall/seccomp/procfs support separately from package availability. See [compatibility](compatibility.md).
