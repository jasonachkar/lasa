# Data access, privacy and storage

[Documentation home](../../README.md)

## Data collection contract

The default scan reads local Linux metadata through a fixed set of collectors. Optional `--inspect` modules expand the collection contract explicitly, as described below. It does not recursively search the entire disk by default. Explicit roots expand only filesystem metadata scope, not permission to read their file contents.

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

## Optional inspection access

Enable these sources only through the corresponding `--inspect` module. Their scope is independent of `--roots`. The default scan does not query them.

| Module/source | Data accessed | Retained data |
| --- | --- | --- |
| Local `/etc/passwd` and `/etc/group` | Account/group records, including fields that must be discarded | Selected names, numeric IDs and group relationships needed for findings; password/GECOS fields are discarded |
| Systemd system manager | Loaded/enabled service inventory and selected effective service/timer properties | Unit identity/state, selected settings, executable/script/environment-file paths and supporting permission metadata |
| Configuration-only `sshd -G -C` | Native SSH configuration resolution, including configured includes and the chosen connection context | Selected effective authentication/permission settings and the recorded context; LASA does not request host-key validation |
| Native `sudo -n -ll -U` | Effective policy provider output for local identities | Selected root grants and command paths; general policy text is discarded |
| Explicit execution/configuration paths | Metadata and ACLs along supported path resolutions, including normal symlink targets | Named discretionary writer candidates and selected component metadata; target file contents are not opened by LASA |
| Native nftables query | JSON ruleset in the scanner network namespace | A supported-model verdict and packet context; no packet payloads or active probe |
| Selected Docker-compatible UNIX socket | Version, container inventory and container inspect responses through GET requests | Selected privilege, namespace, mount, capability and confinement settings; container IDs are pseudonymized |
| Native package database and ownership queries | Installed package/source versions and selected executable ownership | Inventory count, advisory-relevant versions and selected process relationships |
| Explicit local advisory file | Vendor-derived advisory ranges and source/freshness metadata | Relevant advisory identifiers, fixed versions, severity and provenance; not the entire cache |
| Cron/root spool files and systemd timers | Supported schedules and command configuration | Source/line identity, selected execution/search paths, user and permissions; command arguments and unrelated environment values are discarded |

Native systemd properties and runtime inspect responses can include command arguments, environment values, labels or other sensitive fields in transient memory. LASA selects the fields above and does not persist raw responses, full command arguments, environment dumps or raw configuration files. This is a broader access choice than metadata-only scanning; it is not a promise that sensitive fields never enter memory.

Native tools and local management daemons are trusted parts of the inspected system. Their configured includes, identity providers and ordinary audit logging follow host policy. A native sudo/NSS lookup can contact an organization identity service; a read-only management query can cause ordinary daemon/audit logging. LASA does not change enforcement settings or execute remediation. It does not request Docker mutations, remote runtime endpoints or host-key validation.

## What LASA does not collect or do

- The default scan does not read `/proc/PID/environ`, full argv/cmdline, credential-store/private-key contents, application logs or arbitrary application contents. Optional inspection access and transient native/API data are described above. LASA does not directly request `/etc/shadow`, private-key bodies or `/proc/PID/environ`.
- No network payloads, packet capture, authentication attempts, active vulnerability probes or exploitation.
- No runtime API requests or control-socket connection for baseline analysis. Only the explicit containers module uses its selected Docker-compatible endpoint.
- No automatic remediation, host policy modification, privilege escalation or installation-time kernel enforcement.
- No remote telemetry, report upload or SecureObs authentication. Scans make no direct outbound IP advisory/API requests. `lasa advisories update` is a separate explicit HTTPS download; native identity-provider behavior follows host policy.

Metadata can still be sensitive. Executable paths, process names, UNIX socket paths, interfaces, mount paths, identity numbers and service names reveal system structure. A command name can itself contain a sensitive string chosen by its owner. Omitting arguments and hashing selected identifiers is not a guarantee of anonymity. Review report handling under your own data classification policy.

## What is stored

A one-shot terminal scan does not create a hidden report database. `--output` stores the selected report. JSON schema v2 retains the complete snapshot, enabled inspection modules, requested metadata roots, scope fingerprint and inspection assets: metadata entities, observations, provenance graph, findings, evaluation outcomes, coverage, diagnostics and optional runtime events/drop counts. HTML retains a readable representation of evidence, findings and errors. SARIF retains finding-level information and stable fingerprints.

The daemon creates a private state directory, an exclusive lock file and timestamped JSON snapshots. Retention is bounded by **snapshot count** and an optional `--retention-bytes` quota for managed snapshots. It is not time-based retention or a quota on unrelated files. The daemon also checks a configured free-space reserve before persisting a report. Only scanner-named regular snapshot files owned by the daemon user are retention candidates. Unrelated files and symlinks are not deleted. Temporary files from interrupted writes are not treated as reports or automatically interpreted.

## Permissions and exposure

New output files use mode `0600`; newly created state directories use `0700`. Report writes use an exclusive temporary file, sync and atomic rename. Symlink paths and non-regular output targets are rejected. These protections do not defend against a compromised root user, a hostile kernel or a user who subsequently copies a report into a public location.

Terminal rendering escapes control characters. HTML uses escaped output and no remote resources. JSON must be treated as untrusted input by every downstream renderer. A stable fingerprint is a correlation identifier, not an authentication signature or an encryption mechanism.

## Retention, deletion and export

Operators own all stored reports and decide backups, encryption at rest, access control, deletion and export. LASA does not encrypt report files itself. Deleting a report does not delete backups or guarantee physical media erasure. If an external integration is added, obtain authorization, establish transport and storage controls and preserve the report's coverage and uncertainty semantics.
