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
| 33 builtin rule definitions | Baseline and opt-in inspection rules; external-confirmation rules still require an independent source |
| Active external exposure validation | Not implemented; no active port scanning |
| Continuous runtime monitoring | Not implemented; optional bounded observation windows are supported |
| Optional eBPF | Compiled CO-RE object and feature-detecting loader; runtime support requires target-host validation |
| Identity-aware discretionary access | Optional local-account/ACL/traversal analysis; LSM, immutable flags and external identity policy remain qualified |
| Remote/cloud host inventory | Not implemented or required |
| SecureObs upload | No built-in upload; local versioned ingestion contract provided |

## Namespace and container boundaries

Process IDs are scoped. Process identity includes boot identity, PID namespace and start time, so reuse of a numeric PID does not imply the same process. The scanner never treats a capability mask in an arbitrary user namespace as proof of host-level privilege.

A process can be visible while its descriptors, executable or namespace links are restricted. Network namespaces are inspected through visible process representatives; hidden processes and namespace objects with no visible representative may remain unobserved. Only the scanner namespace's interface API is queried; other namespaces' full interface topology is not inferred from their socket tables.

Container detection uses cgroup naming hints. Custom runtimes, altered cgroup layouts and ambiguous host-style mount names can defeat or confuse those hints. Reports qualify them. A container profile acknowledges limited visibility; it does not grant access or escape the container.

## Filesystem and service boundaries

The default scope omits arbitrary homes, deep directory trees, hidden service paths and symlink targets. Scoped metadata is not proof a service will load a file. Sudo/SSH acceptance policies, systemd activation, ACL interpretation, supplementary-group membership and mount/execution options can affect impact.

The default scan does not read service configuration contents or process environments. Optional inspections add effective native service/SSH/sudo policy, selected cron configuration, local identities, runtime settings and package data. See [security inspections](security-inspections.md) and [data access](data-and-privacy.md) for exact sources and retained fields. Kernel LSM presence remains contextual evidence, not proof of a policy's effectiveness.

## Completeness, scoring and exploitability

No scan provides complete host security coverage or guaranteed detection. Scores are prioritization values, not exploit probabilities. A high-confidence observation of a risky combination does not prove a successful compromise. The supported static workflow can be useful while collection is partial; strict mode and downstream acceptance policy determine whether that coverage meets your operational needs.

## Inspection provider requirements

| Module | Provider/requirements | Explicit boundaries |
| --- | --- | --- |
| systemd/timers | Trusted root-owned `systemctl`, system manager access, JSON inventory output and selected effective properties | Alternate roots, unsupported execution flags, unresolved command syntax and inaccessible managers remain unknown |
| SSH | Trusted root-owned OpenSSH `sshd` 9.3+ with configuration-only `-G`, readable configuration | Older provider versions remain unsupported; no fallback to host-key validation |
| sudo | Trusted native `sudo` with supported long-list policy output; authorization for noninteractive queries | External identities, unusual RunAs/output syntax and query denials remain explicit gaps |
| permissions | Local passwd/group records, metadata/ACL access, supported `openat2` behavior and mount metadata | No arbitrary NSS membership reconstruction, mandatory-policy proof, write attempt or universal remote-filesystem authorization model |
| firewall | Trusted `nft`, authorized ruleset access in the scanner network namespace | Supported nftables subset only; named sets, transformations, other hooks and external filtering can make verdicts unknown |
| containers | Explicit Docker-compatible local UNIX API 1.24–1.50 | No native containerd gRPC, Kubernetes inventory or remote TCP API |
| packages | Trusted `dpkg-query` or `rpm`, exact-release advisory data and native version semantics | Automatic feed retrieval targets Debian; other supported schemes require authenticated database import |
| scheduler | Readable supported cron/root spool sources; systemd manager for timer checks | Complex shell programs, wrappers, anacron semantics and arbitrary startup mechanisms are not fully interpreted |

The scratch container image intentionally contains no host administration tools. Installing or mounting a native tool alone does not establish host visibility; manager sockets, namespaces, identity mapping and filesystem scope must also be correct. The scanner refuses tools with writable or non-root-controlled executable ancestry. Do not weaken these checks to remove diagnostics.

Fixture and contract tests establish parser/rule behavior. Native provider, kernel and architecture compatibility must also be validated on the deployment targets. The maintainer VM harness automates that work from macOS or an authorized disposable Linux VM; an unexecuted matrix is not a verified support claim.
