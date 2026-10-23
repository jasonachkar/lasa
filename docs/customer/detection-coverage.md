# Detection coverage

[Documentation home](../../README.md)

LASA prioritizes combinations supported by local evidence. It separates an observed condition, a conditional consequence and information it could not establish. Findings are not proof of exploitation, and a scan with no findings is not a security certification.

## Detection areas

The builtin catalog contains 33 versioned rule definitions. Available findings depend on enabled modules, permissions, supported providers and evidence coverage.

| Area | What LASA helps investigate |
| --- | --- |
| Exposed services | Non-loopback listeners combined with privilege, capabilities or conventional management ports. |
| Isolation and containers | Selected namespace/capability combinations; runtime-confirmed privileged settings, sensitive mounts and control-socket exposure when runtime inspection is enabled. |
| Privileged execution | Unsafe metadata on privileged executables, system search paths and service launch files; named discretionary writer candidates from optional identity/ACL analysis. |
| Access and authentication | Sensitive sudo/SSH path permissions; effective SSH policy for recorded contexts; selected effective sudo root grants. |
| Service and scheduled execution | Supported root-service, cron and timer execution paths that local identities can influence. |
| Package advisories | Release-specific affected package ranges, high-severity vendor assessments and selected running-listener associations. |
| Local firewall context | Supported nftables decisions for a recorded new-connection packet. |

The separately confirmed external-exposure rule remains unavailable to purely local static scans. LASA does not invent an external confirmation source to make that rule trigger.

## Reading a finding

A finding includes its rule/version, affected subject, severity, confidence, supporting observations, prerequisites, uncertainty and remediation. New inspection findings identify the inspected service, identity, endpoint, package or configuration path. JSON and the HTML evidence table retain the selected settings and permission/advisory details.

An observation can be reliable while its possible consequence remains conditional. For example, native policy can establish a root delegation grant without establishing that the account is compromised. A discretionary writer candidate does not prove that mandatory policy permits an actual modification. An affected package version does not prove that a particular vulnerable function is reachable.

Scores prioritize review. They are not probabilities of compromise. Review network scope, identity, activation and compensating controls before making operational changes.

## Collection outcomes

Review collector coverage and individual diagnostics. `unknown` is distinct from a negative observation, and `not_applicable` is distinct from secure. Collector completeness applies to its declared bounded scope, not every asset or security control on the host.

Optional inspections appear as `inspect.systemd`, `inspect.ssh`, and similarly named coverage entries. Counts describe enumerated work; diagnostics can also describe unavailable prerequisites. They are not a percentage of total host security coverage.

## Changes and remediation tracking

```bash
lasa diff before.report.json after.report.json
```

The diff distinguishes new, continuing, changed, resolved and unknown findings. Changes in supporting evidence can move a continuing finding into `changed`, even if severity is unchanged.

A finding can be resolved only when the corresponding evaluation establishes absence or non-applicability, its relevant evidence collectors have complete coverage, and the declared scan scope is compatible. Losing access, narrowing roots, disabling a module or changing an SSH context must not silently resolve an issue. An unrelated collector failure can remain visible without blocking an independently verified resolution.

Diff schema v2 also reports observed changes in listeners, process privilege context, file permissions and selected inspected settings. A listener no longer observed is a statement about compared snapshots, not proof it is unreachable everywhere. Process comparisons across boot changes retain uncertainty. Surface changes are bounded and indicate truncation explicitly.

## Handling intentional exceptions

Use justified, expiring suppressions for intended administrator delegation or accepted configuration risks. Keep evidence and coverage in the retained report. A suppression changes handling; it does not change the observation or prove the risk has disappeared.

See [results](results.md), [security inspections](security-inspections.md), [compatibility and limits](compatibility.md), and [troubleshooting](troubleshooting.md).
