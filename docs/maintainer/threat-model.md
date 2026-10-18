# Threat model and security boundaries

[Maintainer index](README.md)

## Assets and trusted components

Protect host availability, privilege boundaries, credentials, report confidentiality/integrity and the integrity of released scanner artifacts. Trusted inputs include the installed scanner binary, reviewed builtin/custom rules, the OS kernel's metadata interfaces and the operator's explicit scan scope. The source checkout, compiler, module checksum system and generated BPF object belong to the build trust boundary.

Scanned process metadata, filesystem names, procfs strings, socket tables, saved reports and custom rule files are untrusted data. A privileged attacker or compromised kernel can falsify/omit evidence; LASA cannot establish host integrity against that adversary. Ordinary processes may race collection, choose misleading names and make resources disappear.

## Threats and controls

| Threat | Controls | Residual limitation |
| --- | --- | --- |
| Process name or path injects terminal escape sequences | Terminal control/Cf escaping; JSON escaping; HTML template autoescaping and safe text rendering | Human-readable names can still be misleading; no authenticated service identity is implied |
| Malicious procfs data causes parser crash or excessive work | Bounded reads, strict numeric/length validation, duplicate-field checks, parser/fuzz tests | A hostile kernel can stall a syscall or lie about data |
| PID reuse joins unrelated processes | Boot/PID namespace/start-time identity and before/after checks | Whole-host collection is not atomic; exec/FD changes can happen between reads |
| Container root is described as host root | Initial user namespace identity and mapping checks before host privilege inference | Unusual namespace configurations need target-VM validation; capabilities still interact with LSM/seccomp |
| Wildcard listener is marketed as internet-exposed | Potential/local/unknown states; no static confirmed-exposure shortcut | No knowledge of upstream firewalls, NAT or proxies |
| Path traversal or symlink escapes scope | Normalized roots and directory-relative `openat2` resolution constraints | Canonical symlink targets are deliberately uninspected unless explicitly scoped |
| File replaced with a device between stat and xattr open | Pinned O_PATH descriptor and scanner-owned proc-fd metadata reference | An attacker able to alter the kernel or scanner process defeats this boundary |
| Overmount lookup misclassifies writeability | `fstatfs` on the pinned object rather than path-length mount guessing | This is the scanner mount namespace, not proof of another subject's effective access |
| ACL/mapping/sticky-bit omission creates false CAN_WRITE | Permission candidates and uncertainty; no unconditional effective-access edge | The scanner can miss access not expressed by its conservative candidate model |
| Runtime socket inspection changes daemon state | No control-socket connection; metadata inspection only | Permission candidates do not prove runtime authorization semantics |
| Report write follows a hostile symlink | Open directory descriptors, no-follow paths, exclusive temporary file, private mode, sync and atomic rename | Chosen directory owner/root can disrupt files; backups/copies need external controls |
| Report parser exhausts memory or injects a renderer | 64MiB input cap, strict fields/schema/provenance checks, escaped output, no remote resources | Large allowed reports still consume significant memory; no universal hard RSS guarantee |
| Rule YAML executes code or expands aliases | Closed typed predicate registry, strict fields, alias/tag rejection, bounded trees and packs | A malicious operator can still write logically misleading local rules; review required |
| Partial scan creates false resolution | Explicit coverage/errors, strict mode, conservative diff requiring negative evaluation | Unknown issues may remain after an asset disappears; downstream policy must preserve uncertainty |
| Sensor captures secrets or traffic contents | Fixed event ABI, no argv/environ/filename capture, no payload buffer, bounded maps/ring/window | Command names and IP endpoints are still sensitive metadata |
| BPF resource leak or backpressure | Owned links/maps/reader closed, context window, drop counts and bounded retained events | Unsupported hooks and dropped events reduce coverage and remain diagnostic |
| Compromised generated BPF object enters release | Pinned compiler/base image/dependencies, regeneration comparison, module checksums and review | No local privileged verification here; trusted VM release gates are still required |
| Dependency supply-chain failure | Pinned module versions/checksums, dependency allowlist, govulncheck, SBOM, attestation workflow | Advisory data can be stale; no static scan proves absence of unknown vulnerabilities |

## Privileged operation

Standard scanning does not elevate. Deep requires an explicit effective UID 0 context and remains read-only. Do not distribute the binary SUID or give it broad file capabilities. Access requirements depend on the operation and owning namespace; root inside a container or a CAP_SYS_ADMIN suggestion is not a universal solution.

The sample deep unit lists read/search and ptrace capabilities because they relate to scoped metadata and procfs link visibility. This is still privileged inspection and requires organization-specific review. BPF/perf permissions are separate; the deep unit does not enable a sensor. Hosted pull requests must never execute privileged kernel tests on a shared self-hosted runner.

## Data minimization and disclosure

The scanner never reads full argv/environ, private keys, arbitrary configuration contents or network payloads. It hashes machine identity and pseudonymizes long hexadecimal cgroup identifiers. It does retain process names, file/mount paths, user/group numbers, service names, socket endpoints and kernel context. These can reveal infrastructure and occasionally sensitive names. Reports are private files, not encrypted vaults.

Do not log complete snapshots or upload them to public CI artifacts by default. Support bundles should minimize and redact evidence. If a central ingestion layer is added, it must authenticate tenant/asset mapping, encrypt transport, apply size/schema limits and retain uncertainty. A report's own host ID is not a credential.

## No enforcement boundary

LASA does not block syscalls, change permissions, install firewall rules or execute remediation. It does not prove exploitability, continuous runtime coverage or the absence of vulnerabilities. Defensible local evidence is the product contract; remediation decisions remain with the operator.

## Security review and response

Run the tests and supply-chain checks in the development guide. Preserve a failing verifier log and platform context without collecting credentials. Report vulnerabilities through the process in [SECURITY.md](../../SECURITY.md), with a private channel selected by the repository owner before accepting sensitive reports. Do not add a fictional security email or claim a response SLA that has not been established.
