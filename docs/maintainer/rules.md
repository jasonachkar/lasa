# Builtin detection catalog

[Maintainer index](README.md)

This catalog describes the actual builtin definitions. All are version 1. Unknown required evidence prevents a match. Titles describe conditional risk, never established compromise. Every rule has explicit positive, negative, unknown, missing, conflicting and not-applicable test cases.

## Predicate semantics

`network.potential` requires an owned non-loopback endpoint. Negative conclusions require complete descriptor/table visibility. `network.management` uses conventional management/database port numbers and does not prove the application protocol. `network.confirmed` is intentionally unknown in static scans; LASA-002 is evaluated/tested but cannot trigger without an independently established fact source that this release does not provide.

`privilege.host_root` requires UID 0, a full identity mapping and the reserved initial user namespace identity. `capability.dangerous` checks effective CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH or CAP_SYS_MODULE in that same established initial namespace. It is not a universal permission model for every Linux capability. `isolation.weak` requires seccomp 0 and NoNewPrivs 0; missing values are unknown.

Container predicates combine cgroup hints, namespace identities and mount metadata. Host-style mount paths do not prove ownership of a host filesystem. `file.write_candidate` is permission metadata, not effective CAN_WRITE. `file.unsafe_parent` requires an inspected writable ancestor; the absence of inspected unsafe parents stays unknown rather than claiming the entire ancestry is secure. `file.privileged_execution` requires a device/inode match to an observed privileged executable. `file.search_path` identifies conventional system command search directories, not the actual environment of a privileged process.

## Rules

### LASA-001 — Privileged listener with dangerous initial-user-namespace capabilities

Subject: `process`. Category: `exposure`. Severity: **high**. Confidence: **high**.

A non-loopback listener is owned by a process with a dangerous effective capability in the initial user namespace. Reachability beyond this namespace is unverified.

Trigger:

```json
{
  "all": [
    {
      "predicate": "network.potential",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "capability.dangerous",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `network.potential`, `capability.dangerous`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Remove unnecessary capabilities, run under a dedicated account and restrict listener reachability.

### LASA-002 — Confirmed exposure with initial-namespace root privilege

Subject: `process`. Category: `exposure`. Severity: **critical**. Confidence: **high**.

A separately confirmed exposure fact combines with initial-user-namespace root privilege. Static collection never asserts confirmed exposure.

Trigger:

```json
{
  "all": [
    {
      "predicate": "network.confirmed",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "privilege.host_root",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `network.confirmed`, `privilege.host_root`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Restrict the independently verified entry point and remove root execution.

### LASA-003 — Potentially exposed conventional management port

Subject: `process`. Category: `exposure`. Severity: **medium**. Confidence: **medium**.

A process owns a non-loopback endpoint on a conventional management or database port. Port number does not establish protocol identity or internet reachability.

Trigger:

```json
{
  "all": [
    {
      "predicate": "network.potential",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "network.management",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `network.potential`, `network.management`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Verify the service and its intended clients; bind to a restricted interface and enforce authentication and network policy.

### LASA-004 — Initial-namespace root process without seccomp or NoNewPrivs

Subject: `process`. Category: `isolation`. Severity: **medium**. Confidence: **high**.

A root process in the initial user namespace reports seccomp disabled and NoNewPrivs disabled. This is a conditional hardening risk, not evidence of compromise.

Trigger:

```json
{
  "all": [
    {
      "predicate": "privilege.host_root",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "isolation.weak",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `privilege.host_root`, `isolation.weak`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Validate workload compatibility, reduce privilege, and configure service-level NoNewPrivileges and appropriate syscall filtering.

### LASA-005 — Container hint with initial PID namespace access

Subject: `process`. Category: `container`. Severity: **high**. Confidence: **medium**.

Cgroup naming suggests a container while the process belongs to the initial PID namespace. Container identification remains heuristic.

Trigger:

```json
{
  "all": [
    {
      "predicate": "container.hint",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "container.host_pid",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `container.hint`, `container.host_pid`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Verify the runtime boundary and avoid sharing the host PID namespace where unnecessary.

### LASA-006 — Runtime control socket has permissive write metadata

Subject: `file`. Category: `container`. Severity: **high**. Confidence: **medium**.

A scoped container runtime socket path has write permission bits for others or a non-root group. Effective access and runtime authorization remain conditional.

Trigger:

```json
{
  "all": [
    {
      "predicate": "file.kind",
      "op": "eq",
      "value": "runtime_socket"
    },
    {
      "predicate": "file.write_candidate",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `file.kind`, `file.write_candidate`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Restrict socket ownership and group membership; verify ACLs, mount state and runtime authorization. Do not expose the socket to workloads.

### LASA-007 — Privileged executable inode has unsafe write metadata

Subject: `file`. Category: `execution`. Severity: **high**. Confidence: **medium**.

A scoped file inode matches an executable inode reported by an initial-user-namespace root process and has permissive write metadata. Effective access and future execution remain conditional.

Trigger:

```json
{
  "all": [
    {
      "predicate": "file.privileged_execution",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "file.write_candidate",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `file.privileged_execution`, `file.write_candidate`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Restrict executable write permissions and confirm the running executable inode before replacing or restarting the service.

### LASA-008 — Service launch configuration has unsafe write metadata

Subject: `file`. Category: `execution`. Severity: **high**. Confidence: **medium**.

A scoped systemd service or drop-in configuration path has permissive write metadata. Unit activation and daemon reload behavior are prerequisites.

Trigger:

```json
{
  "all": [
    {
      "predicate": "file.kind",
      "op": "eq",
      "value": "service_config"
    },
    {
      "predicate": "file.write_candidate",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `file.kind`, `file.write_candidate`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Restrict unit and drop-in ownership and permissions. Review enabled units and reload configuration only through change control.

### LASA-009 — Sudoers configuration has unsafe write metadata

Subject: `file`. Category: `identity`. Severity: **high**. Confidence: **medium**.

A sudoers configuration path has permissive write metadata. Sudo may reject insecure modes; LASA does not claim the file will be accepted.

Trigger:

```json
{
  "all": [
    {
      "predicate": "file.kind",
      "op": "eq",
      "value": "sudoers"
    },
    {
      "predicate": "file.write_candidate",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `file.kind`, `file.write_candidate`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Use root ownership and restrictive sudoers modes; validate configuration through the system sudoers administration workflow.

### LASA-010 — SUID executable has an unsafe write path candidate

Subject: `file`. Category: `execution`. Severity: **high**. Confidence: **medium**.

A SUID file has unsafe write permission bits or an inspected writable ancestor. Actual replacement and SUID execution depend on ownership, sticky bits, ACLs, mounts and execution policy.

Trigger:

```json
{
  "all": [
    {
      "predicate": "file.executable",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "file.suid",
      "op": "eq",
      "value": true
    },
    {
      "any": [
        {
          "predicate": "file.write_candidate",
          "op": "eq",
          "value": true
        },
        {
          "predicate": "file.unsafe_parent",
          "op": "eq",
          "value": true
        }
      ]
    }
  ]
}
```

Required evidence: `file.suid`, `file.executable`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Remove unnecessary SUID and restrict file and ancestor permissions; verify sticky directories, nosuid/noexec, ACLs and inode identity.

### LASA-011 — File-capability executable has an unsafe write path candidate

Subject: `file`. Category: `execution`. Severity: **high**. Confidence: **medium**.

An executable with a security.capability xattr has permissive file or ancestor write metadata. Capability persistence and execution effect require separate verification.

Trigger:

```json
{
  "all": [
    {
      "predicate": "file.executable",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "file.capability",
      "op": "eq",
      "value": true
    },
    {
      "any": [
        {
          "predicate": "file.write_candidate",
          "op": "eq",
          "value": true
        },
        {
          "predicate": "file.unsafe_parent",
          "op": "eq",
          "value": true
        }
      ]
    }
  ]
}
```

Required evidence: `file.capability`, `file.executable`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Restrict executable and directory permissions; remove unnecessary file capabilities and verify that the xattr has intended semantics.

### LASA-012 — Conventional privileged command search directory is writable

Subject: `file`. Category: `execution`. Severity: **high**. Confidence: **medium**.

A conventional system executable search directory has permissive write metadata. Actual use in a privileged PATH is unknown because environments are not collected.

Trigger:

```json
{
  "all": [
    {
      "predicate": "file.kind",
      "op": "eq",
      "value": "directory"
    },
    {
      "predicate": "file.search_path",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "file.write_candidate",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `file.kind`, `file.search_path`, `file.write_candidate`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Restrict directory ownership and write permissions; verify privileged service command resolution and use absolute executable paths.

### LASA-013 — Authorized-key path has unsafe write metadata

Subject: `file`. Category: `identity`. Severity: **high**. Confidence: **medium**.

An explicitly scoped authorized_keys path has permissive write metadata. SSH may reject it under StrictModes; effective access and SSH configuration are unverified.

Trigger:

```json
{
  "all": [
    {
      "predicate": "file.kind",
      "op": "eq",
      "value": "authorized_keys"
    },
    {
      "predicate": "file.write_candidate",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `file.kind`, `file.write_candidate`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Restrict the key file and parent directory ownership and permissions; verify SSH StrictModes and the effective authorized-key path.

### LASA-014 — Container hint with sensitive host-style mount path

Subject: `process`. Category: `container`. Severity: **high**. Confidence: **medium**.

A process with a container cgroup hint sees a mount at a sensitive /host/etc, /host/proc or /host/sys style path. Source ownership and effective access are not established.

Trigger:

```json
{
  "all": [
    {
      "predicate": "container.hint",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "container.sensitive_mount",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `container.hint`, `container.sensitive_mount`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Verify the mount source and namespace, remove unnecessary host-style mounts and prefer read-only narrowly scoped mounts.

### LASA-015 — Dangerous root capabilities combined with weak isolation

Subject: `process`. Category: `isolation`. Severity: **high**. Confidence: **high**.

An initial-user-namespace root process has dangerous effective capabilities, disabled seccomp and disabled NoNewPrivs. Compromise is conditional.

Trigger:

```json
{
  "all": [
    {
      "predicate": "privilege.host_root",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "capability.dangerous",
      "op": "eq",
      "value": true
    },
    {
      "predicate": "isolation.weak",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `privilege.host_root`, `capability.dangerous`, `isolation.weak`.

Prerequisite: Successful exploitation or malicious control of the affected subject is a prerequisite; LASA does not test exploitation.

Remediation: Remove unnecessary capabilities and root execution, then apply tested NoNewPrivileges and syscall restrictions.

## Scope and intentional omissions

There are fifteen tested definitions, not fifteen promises of universal runtime detection. Confirmed external exposure has no fabricated static source. Unit configuration contents, actual PATH environments, arbitrary user/group ACL access, runtime control-socket authorization and complete mount-source provenance are not read or inferred. Their related findings remain candidates with precise qualifications.

Sensitive paths with familiar names inside custom roots may be inactive examples or backups; verify deployment use. Sudo and SSH can reject insecure configuration modes. File capabilities can be cleared by modification, mounts can be nosuid/noexec, sticky directories can prevent replacement, and LSM policy can constrain effects. These facts remain prerequisites rather than invented intermediate attack steps.

Kernel hardening values are contextual and do not generate a flood of low-signal posture findings. No CVE exploitation attempt or version-only exploitability rule is implemented. A future rule requires evidence support and tests, not merely a larger advertised rule count.
