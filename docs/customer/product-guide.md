# Product guide

[Documentation home](../../README.md)

## The problem LASA helps investigate

Linux security depends on combinations of conditions. A listener, a root process and an enabled kernel feature have very different implications depending on how they relate. LASA organizes local evidence so an operator can prioritize combinations that deserve attention: for example, a potentially reachable process that also carries powerful initial-user-namespace capabilities.

LASA is useful for host posture reviews, workload privilege reviews, pre-deployment checks, incident triage and tracking the effect of hardening changes. It is a point-in-time evidence tool, not an incident response verdict, vulnerability exploit framework, malware detector or replacement for a firewall policy review.

## What happens during a scan

1. LASA determines its visible Linux scope and records the time and host identity context.
2. It collects bounded process, socket, namespace, kernel-control and explicitly scoped file metadata.
3. It connects evidence that refers to the same visible subjects.
4. It evaluates reviewed local rules, preserving unknown and conflicting evidence.
5. It emits findings, supporting observations, conditional risk scenarios, coverage and diagnostics.

There is no network reconnaissance or outbound discovery request. Local socket information is read from the kernel; LASA does not try connecting to each service. The optional sensor observes a finite event window and is requested explicitly through the sensor profile.

## Facts, deductions and scenarios

A fact might establish that a process owns a TCP listener or that a file has a particular permission mode. A deduction may associate a conventional management port with that process. A scenario explains a possible consequence **if** an attacker first obtains the necessary access or control.

Those are different kinds of statements. A wildcard listener is potentially reachable outside loopback, but its internet reachability is unknown. An SSH authorized-key file with permissive metadata might still be rejected by SSH. A container-looking cgroup name is a hint rather than proof of a container runtime boundary. LASA includes these qualifications in the relevant finding.

## Profiles

| Profile | Intended use | Privilege behavior |
| --- | --- | --- |
| `standard` | Safe baseline in the current visible Linux namespaces | Ordinary user; no elevation |
| `deep` | Explicitly authorized higher-visibility host metadata inspection | Requires effective UID 0; still subject to capabilities and policy |
| `container` | An explicitly acknowledged container view | Does not add host access |
| `sensor` | Static snapshot plus a finite eBPF metadata event window | Requires separately authorized kernel prerequisites; failures remain visible |

Deep does not turn off security controls, connect to runtime sockets, read credentials or recursively crawl the whole filesystem. Root in a restricted container does not become host root merely by selecting a profile.

## Reading the outcome

Review the declared scope and collection diagnostics before interpreting findings. A scan may successfully write a useful report while some checks remain incomplete. Enable `--strict` when automation must distinguish this state through the process exit code.

For each finding, examine its observed evidence, prerequisites, confidence, uncertainty and recommended remediation. Verify impact and maintenance constraints before changing a production service. LASA does not execute remediation actions.

## Where the product fits

Reports are usable on their own, in a local operations process, or by a future SecureObs ingestion service. LASA does not require a backend, a graph database or an always-running agent to perform a one-shot scan. It does not monitor activity continuously unless an operator arranges repeated sensor windows; scheduled windows can have observation gaps.

See [data and privacy](data-and-privacy.md), [result interpretation](results.md) and [compatibility](compatibility.md) before deploying it fleet-wide.
