# Security inspections

[Documentation home](../../README.md)

LASA combines its default Linux metadata scan with optional configuration inspections. Use these inspections to connect service settings, local identities, execution paths, container configuration and package advisories to evidence-backed findings.

## Choose the collection scope

A default `lasa scan` retains its metadata-only behavior. Configuration inspection is an explicit choice:

```bash
lasa scan --inspect systemd,ssh,permissions --format json --output inspection.report.json
```

Enable all inspection modules when you have authorization for their documented access:

```bash
sudo lasa scan --profile deep --inspect all --advisories advisories.json \
  --timeout 2m --max-inspection-items 1024 \
  --format json --output inspection.report.json
```

LASA never elevates itself. `sudo` is an operator choice; `--profile deep` requires effective UID 0. Inspection flags also work with `lasa daemon`. Modules are independent of the base profile: `--inspect all` enables every module, while a container profile continues to describe the container-visible system.

`--roots` controls the baseline filesystem metadata collector. It does **not** restrict the configuration providers enabled by `--inspect`. Those providers use the sources described below. Review [data access and privacy](data-and-privacy.md) before enabling them.

If `lasa scan --help` does not list `--inspect`, update to a scanner build containing inspection modules. New scans use report schema v2; see [results and compatibility](results.md).

## What each module checks

| Module | Inspected sources | Findings and qualifications |
| --- | --- | --- |
| `systemd` | Loaded and enabled service inventory; selected effective system-manager properties | Writable root-service executables, interpreter scripts and environment-file paths; selected missing restrictions on an associated root listener. Effective overrides come from the manager. Alternate root images/directories and unsupported execution syntax remain unknown. |
| `ssh` | Configuration-only `sshd -G` output for selected connection contexts | Root password authentication without a required additional method; disabled `StrictModes`. These describe policy for the recorded context, not a successful login, unlocked account or reachable SSH service. |
| `sudo` | Local passwd/group metadata and noninteractive native long-list policy queries | Unrestricted root delegation, passwordless unrestricted grants and writable delegated command paths. Native policy evaluation handles configuration includes and aliases; unsupported output/RunAs expressions remain unknown. Intended administrator grants can be suppressed with a justification and expiry. |
| `permissions` | Selected privileged/sensitive paths, their ancestry, ownership, ACLs and mount metadata | Named local identities with discretionary write or replacement candidates. This supplements baseline permission-bit findings; it does not attempt a write. |
| `firewall` | JSON nftables rules in the scanner network namespace; observed listeners and interface addresses | Management endpoints permitted by the supported nftables packet model. Verdicts cover a recorded packet context and do not prove upstream reachability. |
| `containers` | An explicitly selected local Docker-compatible UNIX socket, through read-only HTTP queries | Running privileged containers, host PID mode, runtime socket mounts, sensitive writable bind mounts and selected dangerous-capability/unconfined combinations. The selected daemon defines the runtime scope. |
| `packages` | Native installed-package database, selected executable ownership queries and a local advisory database | Distribution-specific affected versions, high-severity advisories and affected packages associated with non-loopback listeners. Vendor backport versions are compared with Debian/RPM semantics. |
| `scheduler` | System crontab, `/etc/cron.d`, root crontab spool locations and active systemd timers | Writable execution/configuration/search paths in supported root jobs and timer services. Shell expansion, pipelines, wrappers and other unsupported syntax produce coverage diagnostics. |

## Systemd execution and permissions

Systemd inspection queries effective properties instead of treating every unit-looking file as an active service. It considers loaded active/activating services and enabled/linked service configurations. A disabled, inactive unit is not automatically treated as an active root entry point.

For supported interpreters, LASA identifies the script path as well as the interpreter. Supported relative scripts use the effective working directory. Environment-file **paths and permissions** are inspected; their contents are not opened by LASA. Inline programs and unsupported execution options remain explicit gaps. A privileged command prefix in a non-root unit requires independent review.

A discretionary access candidate can involve writing a file directly or replacing an affected path component. LASA considers local UID/group membership, ACL masks, directory search permission, sticky-directory ownership, read-only mount state and mount boundaries. It detects selected metadata changes during inspection and asks for a rerun when the path changes.

The result remains conditional: immutable/append-only flags, SELinux/AppArmor policy, remote filesystem authorization, service activation and later changes can affect actual impact. External directory-service membership and arbitrary identity-provider policy are not reconstructed from `/etc/passwd` and `/etc/group`.

## SSH connection contexts

`sshd -G` requires OpenSSH 9.3 or later. LASA uses configuration-only mode rather than host-key validation mode. An unavailable provider produces a diagnostic; it does not fall back to reading private keys.

Supply representative contexts so `Match` conditions are evaluated for intended clients:

```bash
sudo lasa scan --inspect ssh \
  --ssh-context 'user=root,host=admin.example,addr=192.0.2.20,laddr=192.0.2.10,lport=22' \
  --ssh-context 'user=deploy,host=admin.example,addr=192.0.2.20,laddr=192.0.2.10,lport=22' \
  --format json --output ssh.report.json
```

Required context fields are `user`, `host`, `addr`, `laddr` and `lport`; `rdomain` is optional. Addresses must be IP literals. The default context is root from localhost to localhost on port 22. A result for that default is **not** a statement about every remote client. Context values are stored in the report.

## Firewall packet contexts

For a wildcard listener, supply a destination address actually observed on a local interface. Supply source and interface information when policy depends on them:

```bash
sudo lasa scan --inspect firewall \
  --network-source 192.0.2.20 \
  --network-destination 192.0.2.10 \
  --network-interface eth0 \
  --format json --output firewall.report.json
```

The model considers new TCP/UDP traffic, supported literal address/prefix/port/interface conditions, inline sets/ranges, base-chain policy and supported chain jumps/returns. Later base chains can still block an earlier accept. An empty nftables input policy does not establish filtering.

Unsupported expressions, named sets, packet transformations, other hooks or insufficient packet context produce an unknown verdict. Legacy iptables, XDP/tc, upstream firewalls, NAT, cloud security groups and application authentication are outside this verdict. Other network namespaces require independent inspection. LASA does not send a packet or make an authentication attempt to establish these findings.

## Container runtime access

```bash
sudo lasa scan --inspect containers --container-socket /run/docker.sock \
  --format json --output containers.report.json
```

This module uses a Docker-compatible API, versions 1.24 through 1.50, over the selected UNIX socket. It does not implement containerd's native gRPC API or the Kubernetes API. Compatible Podman endpoints must implement the queried Docker API behavior. Remote TCP endpoints and redirects are not used.

Runtime socket access is privileged even when LASA sends only read-only requests. A read-only bind mount of a UNIX socket does not restrict its API operations. Inspect responses can contain environment values and other sensitive fields in transit through scanner memory; LASA discards those fields and stores only its selected configuration evidence. This access is excluded from the default scan.

## Budgets, failures and unknowns

`--max-inspection-items` defaults to 256 and accepts 1–4096. It bounds enumerated work within each module, including permission targets. Command output, API responses, file reads, evidence arrays and report exports have additional bounds. A limit produces incomplete coverage rather than a claim that remaining assets are safe.

`--inspection-command-timeout` defaults to 5 seconds per native command. `--timeout` bounds the whole scan cooperatively. Native command cancellation terminates its process group. A kernel-blocked filesystem operation can still require external process supervision; no in-process timeout can guarantee interruption of every kernel operation.

Inspect `inspect.MODULE` coverage and diagnostics before accepting a report. Missing tools, missing permissions, inaccessible managers/sockets, unsupported syntax, stale advisories and timeouts identify the affected operation and scope. Raw native error output is withheld when it could contain configuration secrets; recognized errors retain safe cause and configuration-location information.

Use `--strict` when automation must reject incomplete collection. Use `--fail-on high` to apply a separate finding-severity gate. Neither flag turns unknown checks into a secure result.

See [detection coverage](detection-coverage.md), [package advisories](package-advisories.md) and [troubleshooting](troubleshooting.md).
