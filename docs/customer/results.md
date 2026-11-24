# Understanding results and changes

[Documentation home](../../README.md)

## Start with scope and coverage

A report is a record of what LASA could inspect within a declared scope and resource budget. Read `host.scope`, `profile`, `coverage`, `complete` and `diagnostics` before interpreting its findings.

Coverage counters describe enumerated work: attempted items, successful metadata collection, skipped entries, unsupported (not applicable) entries and inconclusive checks. Skipped and inconclusive work makes a collector partial. Unsupported work is an established absence that does not: a symbolic link excluded by policy, a configured root that does not exist, or a kernel control the running kernel does not provide. They are not a percentage of all possible host vulnerabilities or all assets on a network. A process can have a successfully collected status while its descriptors remain inaccessible; therefore successful and inconclusive counts can refer to different subchecks on the same process. The counters are not interchangeable denominators.

Ordinary user scans frequently encounter permission restrictions. Inaccessible kernel paths, process exits or resource limits also result in partial coverage. A control is only treated as not provided by the kernel when its parent interface is visible and populated; when securityfs is not mounted, for example, LSM controls remain unknown. LASA does not silently convert those gaps into secure conditions.

## Observation states

| State | Interpretation |
| --- | --- |
| `observed` | The value was obtained or a supported deduction was established |
| `not_observed` | A condition was evaluated and not established as present |
| `unknown` | Missing, inaccessible, conflicting, truncated or otherwise inadequate evidence |
| `not_applicable` | This check does not apply to the subject or value type |

An unknown observation does not mean false. A rule requiring unknown evidence does not produce a confirmed match. Reports preserve rule evaluation outcomes so the absence of a finding can be distinguished from an evaluated negative result.

## Three independent risk dimensions

**Severity** describes the rule's potential consequence: informational, low, medium, high or critical. **Confidence** describes the evidence and inference: confirmed, high, medium, low or unknown. Builtin findings currently use high or medium confidence; LASA does not label an inferred compromise scenario confirmed. **Exposure** describes reachability evidence:

- `confirmed`: independently verified exposure evidence; static collection does not produce this state.
- `potential`: a non-loopback endpoint, including wildcard bindings, was observed.
- `local`: the endpoint is loopback or UNIX-local; this is not a blanket statement about other relay/proxy paths.
- `unknown`: reachability could not be established for the subject.

IPv6 wildcard bindings do not establish that IPv4 traffic will be accepted. LASA does not infer dual-stack policy, firewall rules, upstream NAT, cloud security groups or public load balancers from a bind address.

## What a finding contains

A finding includes a fingerprint, versioned rule identity, affected subject, severity/confidence/exposure, supporting observation references, prerequisites, a conditional scenario, uncertainties, remediation and a transparent priority score. Related process instances can share a stable finding identity; their evidence is retained rather than treated as separate scan executions.

Use `lasa explain` to inspect the recorded evidence. No explanation proves that compromise occurred. A remediation is advice to review, not an action LASA executes. For example, enabling a seccomp mode may require workload-specific testing and does not by itself establish that a useful attack surface was removed.

## Priority scores

The current score is a bounded 0–100 prioritization index. Each finding exports the scoring version and named contributions. It combines rule consequence, exposure evidence and observed initial-user-namespace privilege. It is not a probability, compliance score or estimate of successful exploitation.

LSM presence and enabled seccomp do not automatically earn risk reductions: configuration presence alone does not prove an effective mitigation. Compare priorities within the documented scoring version; changing a rule or score version can change a finding's meaning.

## Conditional scenarios and attack paths

The report connects observed relationships such as process ownership of a listener and possession of a capability. Any step requiring compromise, write access not fully proven, a later service restart or a particular upstream policy remains conditional. LASA does not invent a missing vulnerability to turn adjacent facts into an exploit chain.

Current correlations are local evidence combinations centered on a subject. They are not an enterprise-wide lateral movement simulation or a proof that every listed graph neighbor forms one executable sequence.

## Comparing snapshots

`lasa diff old.report.json new.report.json` requires matching host identities. It classifies findings as new, continuing, materially changed, resolved or unknown. Material changes include priority, severity, confidence, exposure and suppression status.

A missing finding is only marked resolved when the newer report uses the same profile, contains an explicit negative or not-applicable evaluation of the same rule for the same stable subject, and every collector that supplied that evaluation's evidence completed its scope. Derived facts are traced back to the collectors that produced their inputs. Gaps in unrelated collectors do not block a verified resolution. Disappearing or unenumerated assets remain unknown, and `unknown_reasons` states why for each unknown finding. This conservative policy can require a follow-up scan before a dashboard can claim resolution. Broader file roots or a different profile also affect comparability; record scan scope alongside reports.

Fingerprint stability favors service identity, executable and stable cgroup context rather than PID alone. A resource rename, host identity change, container replacement or rule version change can legitimately yield a new fingerprint. A missing machine ID forces a boot-scoped fallback and is diagnosed; it weakens continuity across reboots.

## Suppressions

Suppression acknowledges a reviewed finding without removing its evidence. Create a local JSON file:

```json
{
  "schema": "lasa.suppressions/v1",
  "entries": [
    {
      "fingerprint": "REPLACE_WITH_FULL_FINDING_FINGERPRINT",
      "justification": "Temporary exception approved under change SEC-123; compensating controls verified by owner.",
      "expires": "2026-12-01T00:00:00Z"
    }
  ]
}
```

Apply with `--suppressions exceptions.json`. A unique fingerprint and nonempty justification are mandatory; expiration is optional. Expired entries no longer suppress. Suppressed data stays in reports and SARIF exports, but does not trigger `--fail-on`. Protect and review this file as security policy; the daemon loads it at startup, so restart after a change.

## Report formats

JSON is the complete versioned interchange form; empty collections are encoded as `[]` or `{}`, never `null`. Terminal output lists findings first in a table (short ID, severity, priority, finding and affected resource), then a short block per finding with the observed facts (for example mode and owner), the rule-specific risk, the fix and, for permission findings, a suggested command to review. Diagnostics are grouped by code into collection gaps and items not inspected by design; JSON retains every diagnostic. Color is used on terminals only; control it with `--color auto|always|never` or `NO_COLOR`. HTML is a static self-contained report with the same structure, per-finding evidence and collapsed full evidence. SARIF 2.1.0 names the affected resource in each result and logical location, and gives file findings a `file://` artifact location; it never fabricates source-code positions. Some GitHub code scanning views require repository physical locations and may omit or poorly display host findings; retain the JSON/HTML report as the operational record.
