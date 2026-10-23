# Builtin detection catalog

[Maintainer index](README.md)

This catalog describes the actual builtin definitions: fifteen metadata definitions and eighteen opt-in inspection definitions (33 total). All are version 1. Unknown required evidence prevents a match. Titles describe conditional risk, never established compromise. Every rule has explicit positive, negative, unknown, missing, conflicting and not-applicable test cases.

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

The original fifteen definitions describe the default metadata scope. The inspection extension below adds eighteen definitions, bringing the catalog to 33; these are not promises of universal runtime detection. Confirmed external exposure has no fabricated static source. Default metadata rules do not establish effective unit/SSH/sudo policy, actual PATH environments, arbitrary user/group ACL access, runtime control-socket authorization or complete mount-source provenance. Explicit inspections add the bounded provider/DAC/runtime/advisory evidence described below; unsupported conditions remain unknown. Their related findings remain candidates with precise qualifications.

Sensitive paths with familiar names inside custom roots may be inactive examples or backups; verify deployment use. Sudo and SSH can reject insecure configuration modes. File capabilities can be cleared by modification, mounts can be nosuid/noexec, sticky directories can prevent replacement, and LSM policy can constrain effects. These facts remain prerequisites rather than invented intermediate attack steps.

Kernel hardening values are contextual and do not generate a flood of low-signal posture findings. No CVE exploitation attempt or version-only exploitability rule is implemented. A future rule requires evidence support and tests, not merely a larger advertised rule count.

## Opt-in inspection definitions

All use `subject: asset` and an explicit `asset.kind` prerequisite. See [inspection design](inspection-design.md) for collection and trust semantics.

### LASA-101 — Root service execution path permits writes by a local identity

Version 1 · category `systemd` · severity **high** · confidence **high**.

Effective systemd execution metadata references a path or replaceable ancestor permitted by local Unix discretionary access. LSM policy, immutable flags, execution timing and concurrent changes remain prerequisites.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "systemd_service"
    },
    {
      "predicate": "systemd.writable_execution",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `systemd.writable_execution`, `asset.kind`.

Remediation: Restrict the named script, executable and parent-directory write access; review the service user and apply changes through service change control.

### LASA-102 — Root listener service lacks selected systemd restrictions

Version 1 · category `systemd` · severity **medium** · confidence **high**.

An observed listener is associated with a root systemd service with NoNewPrivileges and ProtectSystem disabled. Service requirements and other confinement controls need review.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "systemd_service"
    },
    {
      "predicate": "systemd.exposed_unconfined",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `systemd.exposed_unconfined`, `asset.kind`.

Remediation: Review the listener reachability, reduce service privilege and test appropriate systemd restrictions.

### LASA-110 — SSH context permits root password authentication

Version 1 · category `ssh` · severity **medium** · confidence **high**.

Effective sshd policy permits root password authentication for the recorded connection context without a required additional authentication method. Account lock state and network reachability are not established.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "ssh_policy"
    },
    {
      "predicate": "ssh.root_password",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `ssh.root_password`, `asset.kind`.

Remediation: Review the recorded context; prefer individual accounts and controlled privilege delegation, and validate effective SSH policy before reload.

### LASA-111 — SSH ownership and mode enforcement is disabled

Version 1 · category `ssh` · severity **low** · confidence **high**.

Effective sshd StrictModes is disabled for the recorded context. This is policy evidence, not proof that an unauthorized key is accepted.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "ssh_policy"
    },
    {
      "predicate": "ssh.strict_modes_disabled",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `ssh.strict_modes_disabled`, `asset.kind`.

Remediation: Enable StrictModes where compatible and review actual authorized-key path ownership and permissions.

### LASA-120 — Local identity has unrestricted sudo root delegation

Version 1 · category `sudo` · severity **medium** · confidence **high**.

The native sudo policy provider reports unrestricted root commands for this local identity. Intentional administrator delegation can be documented with an expiring suppression.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "sudo_identity"
    },
    {
      "all": [
        {
          "predicate": "sudo.unrestricted_root",
          "op": "eq",
          "value": true
        },
        {
          "predicate": "sudo.passwordless_root",
          "op": "eq",
          "value": false
        }
      ]
    }
  ]
}
```

Required evidence: `sudo.unrestricted_root`, `sudo.passwordless_root`, `asset.kind`.

Remediation: Review whether unrestricted delegation is necessary and prefer narrowly scoped, administrator-controlled commands.

### LASA-121 — Local identity has passwordless unrestricted sudo root delegation

Version 1 · category `sudo` · severity **high** · confidence **high**.

The native policy provider reports an unrestricted root grant without password authentication. This grants substantial impact if the identity is compromised.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "sudo_identity"
    },
    {
      "predicate": "sudo.passwordless_root",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `sudo.passwordless_root`, `asset.kind`.

Remediation: Restrict the grant and account access, or document an intentional administrator exception with ownership and expiry.

### LASA-122 — Sudo root command permits writes by its delegated identity

Version 1 · category `sudo` · severity **high** · confidence **high**.

A root command in the effective sudo policy has a discretionary write or replacement path available to the delegated local identity. Command arguments, digest constraints and mandatory controls may limit execution.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "sudo_identity"
    },
    {
      "predicate": "sudo.writable_command",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `sudo.writable_command`, `asset.kind`.

Remediation: Remove writable execution paths and review sudo command/digest/argument restrictions with the native policy tools.

### LASA-130 — Sensitive execution or access path permits local discretionary writes

Version 1 · category `permissions` · severity **high** · confidence **high**.

A selected privileged executable or sensitive configuration path has a direct write or replacement candidate for a named local identity, accounting for ACL masks, traversal, sticky directories and observed mount state. Policy acceptance and mandatory controls remain unverified.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "permission_path"
    },
    {
      "predicate": "permissions.privileged_write",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `permissions.privileged_write`, `asset.kind`.

Remediation: Restrict the named writer and affected components; verify policy activation, immutable flags and LSM controls before prioritizing remediation.

### LASA-140 — Local nftables model permits traffic to a management endpoint

Version 1 · category `firewall` · severity **medium** · confidence **high**.

The supported nftables input model accepts the recorded new-connection packet for a non-loopback management endpoint. Legacy filtering, XDP/tc, NAT, upstream networks and actual application authentication are outside this verdict.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "nftables_endpoint"
    },
    {
      "predicate": "firewall.management_permitted",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `firewall.management_permitted`, `asset.kind`.

Remediation: Review the recorded packet context and restrict management access to intended clients; verify external reachability independently.

### LASA-150 — Running container has privileged runtime configuration

Version 1 · category `containers` · severity **high** · confidence **high**.

The explicitly selected Docker-compatible runtime reports a running privileged container. Runtime scope and actual host namespace boundaries must be verified.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "runtime_container"
    },
    {
      "predicate": "containers.privileged",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `containers.privileged`, `asset.kind`.

Remediation: Remove privileged mode where possible and grant only the individual capabilities and devices required.

### LASA-151 — Running container shares the runtime host PID namespace

Version 1 · category `containers` · severity **high** · confidence **high**.

The selected runtime reports host PID mode for a running container. This increases visibility and may increase impact depending on identity, capabilities and host policy.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "runtime_container"
    },
    {
      "predicate": "containers.host_pid",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `containers.host_pid`, `asset.kind`.

Remediation: Use a private PID namespace unless host PID access is required and explicitly controlled.

### LASA-152 — Running container mounts a conventional runtime-control socket path

Version 1 · category `containers` · severity **high** · confidence **medium**.

The selected runtime reports a mount whose source has a conventional runtime-control socket filename. Verify the endpoint type and authorization. A read-only bind mount does not prevent UNIX socket API connections; actual runtime scope and access remain conditional.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "runtime_container"
    },
    {
      "predicate": "containers.runtime_socket",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `containers.runtime_socket`, `asset.kind`.

Remediation: Remove runtime control sockets from workloads or use a deliberately restricted API intermediary.

### LASA-153 — Running container has a sensitive writable bind mount

Version 1 · category `containers` · severity **high** · confidence **high**.

The selected runtime reports a writable bind mount of a sensitive system directory. The endpoint defines the runtime host scope; no successful container escape is asserted.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "runtime_container"
    },
    {
      "predicate": "containers.sensitive_mount",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `containers.sensitive_mount`, `asset.kind`.

Remediation: Remove the mount or narrowly scope it and use read-only data access where appropriate.

### LASA-154 — Running container combines dangerous added capabilities with disabled confinement

Version 1 · category `containers` · severity **high** · confidence **high**.

The selected runtime reports dangerous added capabilities and an explicitly unconfined seccomp or AppArmor setting. User namespaces and actual policy effectiveness still matter.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "runtime_container"
    },
    {
      "predicate": "containers.unconfined_capabilities",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `containers.unconfined_capabilities`, `asset.kind`.

Remediation: Reduce added capabilities and restore tested seccomp/AppArmor confinement.

### LASA-160 — Installed package matches a vendor-derived advisory range

Version 1 · category `packages` · severity **medium** · confidence **high**.

The native package database version matches an affected range for the exact distribution release. Matching uses Debian or RPM version semantics and does not prove exploitability or binary integrity.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "installed_package"
    },
    {
      "all": [
        {
          "predicate": "packages.vulnerable",
          "op": "eq",
          "value": true
        },
        {
          "predicate": "packages.high_severity",
          "op": "eq",
          "value": false
        },
        {
          "predicate": "packages.exposed_vulnerability",
          "op": "eq",
          "value": false
        }
      ]
    }
  ]
}
```

Required evidence: `packages.vulnerable`, `packages.high_severity`, `packages.exposed_vulnerability`, `asset.kind`.

Remediation: Apply the vendor fixed package where available, review advisory prerequisites and restart affected workloads after updating.

### LASA-161 — Advisory-affected package is associated with a listening process

Version 1 · category `packages` · severity **high** · confidence **high**.

An affected native package owns a matching observed executable inode used by a process with a non-loopback listener. This increases review priority without proving internet reachability or exploitability.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "installed_package"
    },
    {
      "predicate": "packages.exposed_vulnerability",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `packages.exposed_vulnerability`, `asset.kind`.

Remediation: Review the recorded advisories, update the package, restart the service and restrict listener access.

### LASA-162 — Installed package matches a high-severity vendor advisory

Version 1 · category `packages` · severity **high** · confidence **high**.

An installed package falls within a high or critical vendor-derived affected range for the exact distribution release. Applicable mitigations and vendor backports must be considered.

```json
{
  "all": [
    {
      "predicate": "asset.kind",
      "op": "eq",
      "value": "installed_package"
    },
    {
      "all": [
        {
          "predicate": "packages.high_severity",
          "op": "eq",
          "value": true
        },
        {
          "predicate": "packages.exposed_vulnerability",
          "op": "eq",
          "value": false
        }
      ]
    }
  ]
}
```

Required evidence: `packages.high_severity`, `packages.exposed_vulnerability`, `asset.kind`.

Remediation: Apply vendor remediation and review whether the affected component is loaded or used.

### LASA-170 — Privileged scheduled execution references a discretionary write path

Version 1 · category `scheduler` · severity **high** · confidence **high**.

A root cron job or active systemd timer references a script, executable, configuration or search directory writable or replaceable by a local identity. Scheduler acceptance, activation and mandatory controls remain prerequisites.

```json
{
  "all": [
    {
      "any": [
        {
          "predicate": "asset.kind",
          "op": "eq",
          "value": "scheduled_job"
        },
        {
          "predicate": "asset.kind",
          "op": "eq",
          "value": "systemd_timer"
        }
      ]
    },
    {
      "predicate": "scheduler.writable_root_job",
      "op": "eq",
      "value": true
    }
  ]
}
```

Required evidence: `scheduler.writable_root_job`, `asset.kind`.

Remediation: Restrict execution and search paths, prefer absolute administrator-controlled paths and validate the schedule under change control.
