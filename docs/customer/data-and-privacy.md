# Data access, privacy and storage

[Documentation home](../../README.md)

## Data collection contract

LASA reads local Linux metadata through a fixed set of collectors. It does not recursively search the entire disk by default. Explicit roots expand only filesystem metadata scope, not permission to read their file contents.

| Source | Data read | Purpose and what appears in a report |
| --- | --- | --- |
| `/proc/PID/stat` | PID, parent PID, start time; bounded parsing of kernel fields | Process identity and PID-reuse protection; no full command arguments |
| `/proc/PID/status` | Command name, UIDs/GIDs, groups, capability masks, seccomp, NoNewPrivs | Privilege and isolation context |
| `/proc/PID/exe` | Kernel link plus pinned executable device/inode metadata | Executable identity and file correlation; no executable bytes |
| `/proc/PID/ns/*` | Namespace link identities | Scope and namespace relationships |
| `/proc/PID/uid_map`, `gid_map` | Namespace mapping ranges | Interpret credentials and capability context |
| `/proc/PID/cgroup` | Cgroup membership paths with long hexadecimal identifiers pseudonymized | Runtime hints, service association and stable context |
| `/proc/PID/fd/*` | Link metadata, bounded descriptor count | Socket inode ownership; descriptor contents are never opened |
| `/proc/PID/net/tcp*`, `udp*`, `unix` | Bounded socket table rows in visible network namespaces | Endpoints, listener/bound state, UNIX paths and owners |
| Scanner namespace interface API and route tables | Interface addresses, flags, names, IPv4/IPv6 route metadata | Local topology evidence; not upstream firewall or NAT knowledge |
| `/proc/PID/mountinfo` | Mount roots/targets, filesystem, options and propagation fields | Namespace-scoped mounts and read-only context |
| Scoped file paths | Device/inode, ownership, mode, capability/ACL xattr metadata | Unsafe permission candidates and privileged-executable association |
| Selected `/proc/sys` and `/sys` paths | Ptrace, disclosure, namespace and BPF restrictions; LSM/lockdown and cgroup indicators | Kernel posture context and explicit collection gaps |
| `/etc/machine-id` or fallback | Machine identity, hashed before reporting | Cross-scan host mapping; raw machine ID is not retained |
| Boot ID, kernel release, OS release metadata | Boot context, architecture, distribution | Process identity, compatibility and scan context |
| Optional eBPF | Bounded process name/identity, endpoint metadata, selected syscall event outcomes and namespace flags | Finite runtime observation; no traffic payloads |

The scanner's own procfs file-descriptor links can be used to address a pinned file for metadata/xattr inspection. This does not grant permission to read the scanned application's contents.

## Default filesystem roots

```text
/usr/bin
/usr/sbin
/usr/local/bin
/etc/systemd/system
/usr/lib/systemd/system
/etc/sudoers
/etc/sudoers.d
/etc/ssh
/root/.ssh
/run/docker.sock
/run/containerd/containerd.sock
```

Traversal is bounded to two directory levels under each root, a global entry budget and a deadline. Symlinks are excluded, including ordinary distribution alternatives links. A parent symlink can also make an explicit root inaccessible; choose its canonical target deliberately instead of expecting automatic traversal. User home directories are not recursively enumerated. Add a specific authorized-key directory only when it is part of the intended scope.

## What LASA does not collect or do

- No `/proc/PID/environ`, full argv/cmdline, credential-store or private-key contents, application log files or arbitrary file contents.
- No network payloads, packet capture, authentication attempts, active vulnerability probes or exploitation.
- No Docker/containerd API requests or control socket connection for baseline analysis.
- No automatic remediation, host policy modification, privilege escalation or installation-time kernel enforcement.
- No remote telemetry, report upload, SecureObs authentication or background outbound connectivity.

Metadata can still be sensitive. Executable paths, process names, UNIX socket paths, interfaces, mount paths, identity numbers and service names reveal system structure. A command name can itself contain a sensitive string chosen by its owner. Omitting arguments and hashing selected identifiers is not a guarantee of anonymity. Review report handling under your own data classification policy.

## What is stored

A one-shot terminal scan does not create a hidden report database. `--output` stores the selected report. JSON retains the complete snapshot: metadata entities, observations, provenance graph, findings, evaluation outcomes, coverage, diagnostics and optional runtime events/drop counts. HTML retains a readable representation of evidence, findings and errors. SARIF retains finding-level information and stable fingerprints.

The daemon creates a private state directory, an exclusive lock file and timestamped JSON snapshots. Retention is by **snapshot count**, not days or byte quota. Only scanner-named regular snapshot files owned by the daemon user are retention candidates. Unrelated files and symlinks are not deleted. Temporary files from interrupted writes are not treated as reports or automatically interpreted.

## Permissions and exposure

New output files use mode `0600`; newly created state directories use `0700`. Report writes use an exclusive temporary file, sync and atomic rename. Symlink paths and non-regular output targets are rejected. These protections do not defend against a compromised root user, a hostile kernel or a user who subsequently copies a report into a public location.

Terminal rendering escapes control characters. HTML uses escaped output and no remote resources. JSON must be treated as untrusted input by every downstream renderer. A stable fingerprint is a correlation identifier, not an authentication signature or an encryption mechanism.

## Retention, deletion and export

Operators own all stored reports and decide backups, encryption at rest, access control, deletion and export. LASA does not encrypt report files itself. Deleting a report does not delete backups or guarantee physical media erasure. If an external integration is added, obtain authorization, establish transport and storage controls and preserve the report's coverage and uncertainty semantics.
