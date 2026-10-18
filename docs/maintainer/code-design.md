# Code and collector design

[Maintainer index](README.md)

## Package responsibilities

| Package | Responsibility |
| --- | --- |
| `cmd/lasa` | OS signal context, command execution, stderr rendering, exit status |
| `internal/cli` | Cobra commands, validation, local policy/rule input, output orchestration |
| `internal/application` | Dependency-ordered collection, snapshot assembly, diff, suppressions and daemon |
| `internal/domain` | Versioned entity, evidence, diagnostic, graph and report types |
| `internal/platform/linux` | Bounded reads, constrained paths, explicit proc links and pinned executable metadata |
| `internal/collector/process` | Proc stat/status parsing, bounded PID workers, identities, namespace links, cgroups and socket descriptors |
| `internal/collector/identity` | Namespace mappings and mountinfo parsing/collection |
| `internal/collector/network` | Per-visible-network-namespace tables, endpoint parser, inode ownership and scanner topology |
| `internal/collector/container` | Clearly qualified cgroup runtime/service interpretation helpers |
| `internal/collector/filesystem` | Scoped metadata traversal, xattrs, statfs and candidate permission facts |
| `internal/collector/kernel` | Fixed allowlist of kernel-control metadata |
| `internal/collector/ebpf` | Generated embedded object, kernel probes, tracepoint links, ring buffer and bounded event decoding |
| `internal/graph` | Provenance validation, indices, derived facts and bounded traversal |
| `internal/rules` | Strict YAML loader, typed predicate validation and four-state composition |
| `internal/correlation` | Rule outcomes, deduplication, supporting subgraphs and conditional findings |
| `internal/scoring` | Versioned transparent additive priority |
| `internal/storage` | Safe regular-file reads, private atomic writes, directory creation, flock and retention |
| `internal/report` | Deterministic JSON, safe terminal, escaped static HTML and SARIF |
| `rules/builtin` | Embedded reviewed rule pack |

Interfaces stay narrow: `collector.Collector` describes and collects; `linux.Reader` provides only bounded metadata reads, link reads and bounded names. Pinned executable metadata is a Linux-specific optional adapter capability. `Engine` stage factories allow in-memory test collectors. No collector directly generates a finding or writes a user report.

## Process parsing and identity

`stat` parsing locates the last closing parenthesis around `comm`, rather than splitting command names on spaces. It validates PID, parent, field count and start time. `status` parsing validates required UID/GID vectors, unsigned groups/capabilities, unique fields and isolation values. Seccomp/NoNewPrivs missing values remain sentinel `-1`, not a disabled/secure assertion.

A process is read with start-time checks before and after collection. Identity combines boot ID, PID namespace, PID and start ticks. Vanishing PIDs are recoverable diagnostics. Executable metadata is pinned through the specific procfs executable reference; it is not a general permission to follow filesystem symlinks or read an executable.

The collector does not read `cmdline` or `environ`. Descriptor traversal retains socket inode metadata, not descriptor contents. A failed descriptor read makes negative socket-ownership conclusions incomplete. Supplementary groups, mapping ranges and namespace identities are retained for context.

## User namespace interpretation

A root UID and a capability bitmask alone are insufficient. Initial-user-namespace privilege facts require a complete identity UID mapping **and** the observed reserved Linux initial user namespace inode (`user:[4026531837]`). Initial PID namespace checks use the reserved initial PID namespace identity (`pid:[4026531836]`). These are Linux proc namespace constants, not guesses based on the scanner's own PID 1. Missing links/mappings remain unknown; a different user namespace does not become host privilege through root UID alone.

This interpretation is deliberately narrow and needs VM regression tests across supported kernels and unusual namespace setups. It is not a general proof that every operation permitted by a capability can succeed under an LSM or seccomp policy.

## Networking

Socket tables are read through a visible PID in each enumerated network namespace; another PID is tried when a representative disappears or is inaccessible. IPv4 and IPv6 proc encodings are decoded with Linux's per-32-bit-word layout for the targeted little-endian architectures. TCP LISTEN and UDP bound endpoints are distinct. Loopback and IPv4-mapped loopback addresses are local; other binds are potential, never confirmed external reachability.

Ownership uses a namespace/inode index built from process descriptors. Interface APIs and route tables only describe the scanner's network namespace. Unknown namespaces, inaccessible owners, namespace budget limits and table parse errors remain explicit. No setns, remote connection, firewall mutation or active port probing is performed.

## Filesystem safety and permission candidates

`openat2` uses `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS` and `RESOLVE_NO_MAGICLINKS` for ordinary metadata paths. Files are opened with `O_PATH`, statted and kept pinned while ACL/capability xattrs are addressed through scanner-owned `/proc/self/fd/N`. This avoids opening a hostile device substituted between a metadata check and an ordinary read-only open. No scanned file contents are read.

Read-only state comes from `fstatfs` on that descriptor, not a longest-path guess in mountinfo. This matters for overmounts with duplicate targets, bind mounts and altered scanner mount namespaces. File capability xattrs validate revision, exact size and flags before a nonempty set is established. ACL presence is recorded; ACL semantics are not modeled as confirmed effective access.

Permission candidates include other-writable bits or group-writable bits for a non-root group, unless the pinned object's mount is observed read-only. Ownership, actual group membership, ACLs, sticky directories and execution policy remain prerequisites. Names associated with sudoers, SSH keys, systemd units and runtime sockets identify scoped candidates; explicit nonstandard roots may contain similarly named inactive files, so file activation/use must be verified. Runtime socket classification requires an actual socket type.

Traversal is breadth-first, deduplicated by path, limited to two levels and a bounded queue/entry budget. Symlink exclusions are counted and diagnosed. There is no fallback that recursively follows links to improve apparent coverage.

## Kernel, service and container context

The kernel collector reads only an allowlist. Unavailable controls are unknown, not a secure default. AppArmor being enabled is not proof a particular process is confined; no generic risk discount is applied. Cgroup strings can suggest a runtime or a `.service`, but no control API is contacted and no systemd unit contents are parsed. Host-style mount paths remain hints about sensitive resources rather than proof of source host ownership.

## Resource budgets

Defaults: 30-second cooperative deadline, 4 PID workers, 4,096 PIDs, 512 descriptors per PID, 4,096 file entries, 1MiB per metadata read and two directory levels. Configuration bounds prevent accidental unlimited settings. Fixed ceilings include 128 network/mount namespaces, 65,536 total sockets, 32,768 mounts, 200,000 graph edges, 1MiB rule/policy inputs, 256 rules and 64MiB saved report input. Sensor limits are documented separately.

These are explicit work budgets, not a hard universal RSS or wall-clock guarantee. The daemon unit adds an OS memory limit. A hostile or stalled kernel/filesystem can hold a syscall beyond context cancellation. Monitor resources and narrow scope on dense hosts.

## Errors and persistence

Diagnostics preserve component/operation/target/cause/errno/impact/remediation and recoverability. Disappearing processes, denied metadata and feature failures remain observable; the CLI alone decides fatal status and strict-mode acceptance. Generic errors are wrapped with the relevant operation, and machine output stays on stdout.

Storage uses directory-relative exclusive creation, mode 0600, file sync, atomic rename and parent sync. It rejects symlink traversal, non-regular report targets and unsafe shared output directories. Sticky temporary directories are supported. Existing regular reports may be atomically replaced. JSON input is bounded, strict about unknown fields and validated for version and evidence integrity.

The daemon's private directory, `flock`, sequential scan loop, fatal persistence errors and managed-file-only retention prevent overlapping writes and silent data loss. Leftover temp files are ignored rather than guessed to be complete. The unit does not automatically upload reports or modify host security settings.
