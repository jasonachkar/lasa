# Troubleshooting and diagnostic reference

[Documentation home](../../README.md)

## Read the whole diagnostic

Every structured collector diagnostic carries a code, component, operation, target, underlying cause, errno when available, evidence impact, remediation and recoverability. Some also identify a required feature or privilege. Use JSON for the complete diagnostic list; terminal summary output displays at most twelve diagnostics to avoid burying findings.

```sh
lasa doctor --format json
lasa scan --format json --output investigation.report.json
```

A successful report write can contain incomplete collection. `--strict` exposes this as exit 3. Fix the specific cause and rerun; the existence of a previous report does not establish that new settings took effect.

## Common codes

| Code | Why it happens | What to do |
| --- | --- | --- |
| `HOST_UNSUPPORTED` | Incompatible platform or initialization requirement | Use supported Linux and inspect the underlying cause; deep requires explicitly authorized UID 0 |
| `PROC_UNAVAILABLE` / `PROC_RESTRICTED` | Required own-process or boot metadata is absent or denied | Mount supported procfs and authorize its required metadata visibility; reliable process identity needs boot ID |
| `CONFIG_INVALID` | Invalid profile, budget, local rule pack or policy | Correct the named field/path; use generated command help |
| `PERMISSION_DENIED` | Procfs, namespace, ACL or directory policy denied the operation | Check the specific target and namespace; do not grant broad capabilities as a generic fix |
| `PROCESS_VANISHED` | A short-lived process disappeared during its snapshot | Expected under churn; rerun if the process matters; old findings remain uncertain |
| `NETWORK_NAMESPACE_UNREADABLE` | No visible representative could expose a namespace table | Verify process visibility and namespace policy; the scanner cannot infer hidden sockets |
| `NOT_FOUND` | A configured metadata path is absent or not visible | Confirm whether the feature/resource exists in this view; absence is not a blanket secure result |
| `UNSAFE_PATH` | A configured path traverses a symlink or escapes its constrained root | Select the canonical path (for example the output of `realpath`); symlinks are never followed |
| `SYMLINK_NOT_FOLLOWED` | An entry inside a root is a symbolic link; its target is recorded but not inspected | No action unless the target matters; then add its canonical path to `--roots`. Does not make coverage partial |
| `NOT_PRESENT` | A configured root does not exist (for example `/run/docker.sock` without Docker) | No action unless the path should exist. Does not make coverage partial |
| `NOT_SUPPORTED_BY_KERNEL` | The running kernel does not provide this control (for example SELinux on an AppArmor host) | No action. Does not make coverage partial |
| `METADATA_ENCODING` | A path has non-UTF-8 bytes and its JSON label is lossy | Use the diagnostic's quoted byte target for exact filesystem identification |
| `RESOURCE_LIMIT` | A configured or fixed enumeration budget was reached, or file metadata was omitted to keep the report under 64 MiB | Narrow scope or deliberately raise the configurable budget; inspect remaining incomplete coverage |
| `COLLECTION_FAILED` | Metadata could not be safely read or parsed | Inspect operation, target and detailed cause, including truncation/format errors |
| `SCAN_CANCELLED` | Deadline or signal interrupted a collection phase | Increase a too-short deadline or rerun after intentional cancellation |
| `BTF_UNAVAILABLE` | Optional sensor cannot access usable kernel BTF | Use a BTF-enabled supported host; static scans remain available |
| `EBPF_PERMISSION_DENIED` | Kernel policy denied feature probing, loading or attachment | Validate authorized BPF/perf privileges in the relevant user namespace and host policy |
| `EBPF_VERIFIER_REJECTED` | The kernel verifier rejected the program | Preserve verifier output; report exact kernel/configuration to maintainers; never bypass it |
| `TRACEPOINT_UNAVAILABLE` | A required tracepoint or its visibility is missing | Inspect tracefs exposure and supported event sources; unavailable sources are not fabricated |
| `EBPF_LOAD_FAILED` | Object, CO-RE, memory or kernel loading failure | Read the precise cause; verify BTF, helpers, map support and memory limits |
| `EBPF_EVENTS_LOST` | Kernel buffer pressure or retained-event budget discarded events | Treat runtime coverage as incomplete; shorten windows or reduce workload/observation pressure |
| `REPORT_READ_FAILED` / `REPORT_INVALID` | Missing, unsafe, oversized or unsupported report input | Supply the original supported JSON report through a regular non-symlink path |
| `FINDING_NOT_FOUND` | Fingerprint is absent from the selected report | Use the ID shown by `lasa report` for that scan, not its rule ID |
| `REPORT_INCOMPATIBLE` | Reports cannot be meaningfully compared | Verify host identity and schema/profile context |
| `OUTPUT_WRITE_FAILED` | Destination is unsafe, missing, unwritable or full | Create a private real parent directory; check filesystem capacity and ownership |
| `DAEMON_FAILED` | State lock, persistence, retention or scan failure | Inspect the nested cause and supervisor log; avoid competing daemons in one state directory |

## Permission diagnosis

Root is not a universal solution. Reading other users' procfs links is subject to ptrace policy, namespace ownership, procfs options and LSM policy. Container capability sets can exclude otherwise useful operations even for UID 0. Deep scans require an authorized host context; LASA does not recommend CAP_SYS_ADMIN as a universal workaround.

For eBPF, feature support, BTF and tracepoints are independent prerequisites. CAP_BPF and CAP_PERFMON are commonly relevant on suitable kernels, but host policy and older-kernel behavior still matter. Doctor's visibility checks alone do not establish load permission or event delivery.

## Why no findings appeared

A clean finding list can mean no supported rule matched the observed evidence, that the relevant condition was outside scope, or that needed facts were unknown. Check diagnostics and rule evaluations. The confirmed-exposure predicate is intentionally unknown in static scans; wildcard binding is not enough to satisfy it.

## Why an issue stayed unknown after a change

A missing or inaccessible subject is not a verified fix. Complete a compatible scan that can evaluate the prior subject and establish the relevant negative condition. Resource replacement, cgroup changes, machine-ID changes and rule-version changes can affect identity and continuity.

## Collecting a support bundle

Provide the scanner version, Linux distribution/kernel/architecture, profile, relevant budgets, exact diagnostic codes and a minimized redacted report excerpt. Do not send credentials, process environments, private keys or full infrastructure reports to a public issue. Reports can reveal paths, identities and service topology even without file contents. Use your organization's approved private support channel for sensitive evidence.
