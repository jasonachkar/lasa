# Compatibility, supported behavior and limits

[Documentation home](../../README.md)

## Platform targets

LASA targets Linux AMD64 and ARM64 little-endian systems. Native macOS and Windows scans are unsupported. Build the Linux binaries from a suitable Linux toolchain and use real Linux hosts/VMs for kernel-sensitive testing. ARM64 cross-compilation alone does not validate an ARM64 kernel at runtime.

`openat2`, procfs, visible namespaces and permission-compatible metadata access are required for the intended static workflow. Kernels predating `openat2`, hardened syscall filters and procfs restrictions can prevent collection. No insecure path-following fallback is used. The scanner reports failures rather than pretending that a version string establishes compatibility.

Static collection and report workflows were exercised on a Debian 13.6 AMD64 cloud host. Both target architectures have reproducible build checks. Privileged eBPF attachment/event delivery, the full host/container namespace matrix and live systemd deployment still require target-host validation. CI configuration is a plan for repeatable checks; an unexecuted CI job is not a verified compatibility claim.

## Capability matrix

| Capability | Current behavior |
| --- | --- |
| Real process/identity/namespace metadata | Implemented, bounded and permission-aware |
| TCP/UDP IPv4/IPv6 and UNIX endpoints | Implemented for enumerated process network namespaces |
| Interface addresses and routing | Scanner network namespace; no upstream topology guarantee |
| Scoped file metadata, ACL presence, file capability xattrs | Implemented; effective access evaluation is conservative |
| Cgroup runtime and service association | Heuristic association, not a runtime API inventory |
| Kernel hardening metadata | Selected allowlist; not a complete kernel or LSM policy audit |
| Evidence-linked local correlations | Implemented; conditional compromise remains explicit |
| 15 builtin rule definitions | Tested; confirmed-exposure rule requires evidence static scans intentionally never fabricate |
| Active external exposure validation | Not implemented; no active port scanning |
| Continuous runtime monitoring | Not implemented; optional bounded observation windows are supported |
| Optional eBPF | Compiled CO-RE object and feature-detecting loader; runtime support requires target-host validation |
| Effective write access for arbitrary identities | Not asserted; permission candidates retain ACL/mount/identity uncertainty |
| Remote/cloud host inventory | Not implemented or required |
| SecureObs upload | No built-in upload; local versioned ingestion contract provided |

## Namespace and container boundaries

Process IDs are scoped. Process identity includes boot identity, PID namespace and start time, so reuse of a numeric PID does not imply the same process. The scanner never treats a capability mask in an arbitrary user namespace as proof of host-level privilege.

A process can be visible while its descriptors, executable or namespace links are restricted. Network namespaces are inspected through visible process representatives; hidden processes and namespace objects with no visible representative may remain unobserved. Only the scanner namespace's interface API is queried; other namespaces' full interface topology is not inferred from their socket tables.

Container detection uses cgroup naming hints. Custom runtimes, altered cgroup layouts and ambiguous host-style mount names can defeat or confuse those hints. Reports qualify them. A container profile acknowledges limited visibility; it does not grant access or escape the container.

## Filesystem and service boundaries

The default scope omits arbitrary homes, deep directory trees, hidden service paths and symlink targets. Sensitive files are recognized by the location their consumer reads, not by name alone: sudoers configuration is `…/etc/sudoers` or a direct child of `…/etc/sudoers.d`, unit configuration lives under a systemd unit directory (`…/etc/systemd/system`, `…/lib/systemd/system`, `…/run/systemd/system`), and authorized keys are inside a `.ssh` directory. The `…` prefix also matches an explicitly scoped image or container root such as `/mnt/image/etc/sudoers.d`. Scoped metadata is not proof a service will load a file. Sudo/SSH acceptance policies, systemd activation, ACL interpretation, supplementary-group membership and mount/execution options can affect impact.

LASA does not read service unit contents, PATH environments, private keys or application configuration contents. Conventional search-directory and service filename checks therefore remain conditional. Kernel LSM presence is contextual evidence, not proof of a policy's effectiveness.

## Completeness, scoring and exploitability

No scan provides complete host security coverage or guaranteed detection. Scores are prioritization values, not exploit probabilities. A high-confidence observation of a risky combination does not prove a successful compromise. The supported static workflow can be useful while collection is partial; strict mode and downstream acceptance policy determine whether that coverage meets your operational needs.
