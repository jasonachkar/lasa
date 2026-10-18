# Data model, identity and versioned schemas

[Maintainer index](README.md)

## Contracts

| Artifact | Version |
| --- | --- |
| Snapshot | `lasa.report/v1` |
| Rule pack | `lasa.rules/v1` |
| Priority calculation | `lasa.priority/v1` |
| Finding fingerprint inputs | `lasa.finding/v1` |
| Suppression policy | `lasa.suppressions/v1` |
| Diff | `lasa.diff/v1` |
| Explanation | `lasa.explanation/v1` |
| Doctor output | `lasa.doctor/v1` |
| Runtime event | `lasa.runtime/v1` |
| SARIF | `2.1.0` |

The authoritative Go structs are in `internal/domain/model.go`. A complete machine-readable snapshot shape is checked into [`schemas/report-v1.schema.json`](../../schemas/report-v1.schema.json). Regenerate it from the domain with `go run tools/schema/main.go > schemas/report-v1.schema.json`. The suppression schema is also in `schemas/`. Exported field additions require a deliberate compatibility decision because the CLI decoder rejects unknown fields for the current version.

## Snapshot envelope

A snapshot records schema/scanner version, execution ID, start/completion timestamps, profile, host identity/scope, entity arrays, observations, graph, findings, per-subject rule evaluations, diagnostics, coverage, overall completeness and optional runtime events/drop totals. JSON timestamps are RFC3339-compatible Go time values in UTC. A scan execution ID uses 128 bits from the OS cryptographic entropy source; entropy failure is fatal.

Sorted serialization makes a saved snapshot round-trip deterministically. Different live scans naturally differ in execution ID, times and changing host data. Non-UTF-8 path bytes retain distinct internal IDs, are escaped in direct terminal/HTML rendering, and cause an explicit encoding diagnostic; JSON string display labels are lossy for those bytes. Nil lists may serialize as `null`; consumers must not assume every list is non-null. Maps are serialized with Go's stable JSON string-key ordering. Observation and finding order is normalized before export.

## Host and process identity

The host ID is a length-prefixed raw-byte SHA-256-derived pseudonymous ID based on machine ID, truncated to 128 bits for report identifiers. Boot identity is a required procfs prerequisite; failure is fatal rather than inventing a boot ID. If machine identity is unavailable, a diagnosed boot-scoped fallback is used. Raw machine ID is not retained. This is pseudonymization, not authentication or anonymous aggregation; cloned machine IDs require external asset-mapping policy.

A process execution ID combines boot ID, PID namespace identity, numeric PID and kernel start ticks. The collector reads start time before and after the metadata group to avoid PID-reuse association. `start_time_ticks` is the Linux userspace clock-tick field from `/proc/PID/stat`, not Unix time.

`stable_id` favors service/cgroup context, executable identity and effective UID instead of numeric PID. If the executable/service cannot be established, a process-execution fallback avoids collapsing unrelated unknown processes. Container replacement or cgroup identity changes can legitimately change stable identity.

Executable device/inode fields identify the pinned procfs executable object. A file's current path is only correlated as `EXECUTES` if device and inode match; an old/deleted/replaced path does not silently inherit that relationship.

## Entities

- **Host:** OS, distribution, kernel, architecture, scope, boot identity and scanner namespaces.
- **Process:** PID/parent/start, command name, executable metadata, real/effective/saved/filesystem credentials, groups, capability masks, seccomp/NoNewPrivs, namespaces, cgroups and socket inodes. No argv or environment.
- **Socket:** protocol/family, local endpoint, state, inode, namespace, visible owners and exposure classification. TCP listening and UDP bound semantics remain distinct.
- **Interface:** scanner-namespace interface identity, address list and flags. Route tables are separate observations; the schema does not imply global network topology.
- **Service:** cgroup-derived systemd association, with source and process. It is not a parsed systemd execution specification.
- **File:** scoped path, pinned ownership/device/inode/mode, capability xattr, ACL-presence and read-only state. These are metadata, not effective access proofs.
- **Mount:** namespace, mount root/target, source/filesystem, options and propagation fields. Sources are kernel metadata and can be sensitive.
- **Container:** process association and runtime hint with low confidence; no runtime control API identity is asserted.
- **KernelControl:** named allowlisted control value, state and source. Unavailable paths stay unknown.

## Observations and provenance

An observation has ID, subject, key, normalized string value, explicit state, source, collector and collection time. `derived` marks deductions; `evidence` links their inputs. `redacted` identifies values whose raw identifiers were replaced or omitted; this flag is not a guarantee that all metadata is anonymous. `error_code` is available when an observation-level error is attached; collectors also retain detailed diagnostics separately.

Observation IDs are deterministic over length-prefixed raw-byte subject/key/value/source/state data. They are local evidence identifiers rather than independent event IDs. Collectors preserve unknown states and do not replace unreadable values with false. Conflicting values for a predicate produce unknown evaluation. Every graph edge used in a finding references existing observations; findings recursively retain the supporting IDs for derived facts.

## Findings and risk

A finding includes a stable fingerprint, rule/version, title/description, affected subject(s), stable subject, severity, confidence, exposure, evidence, prerequisites, warnings, remediation, score version/contributions, scenario and coverage context. Suppression leaves data intact and adds policy state/justification.

Fingerprint inputs are contract marker, host ID, rule ID/version and stable subject identity. Scan ID, collection time and ephemeral PID are deliberately excluded when a stable subject exists. Deduplication retains every affected subject and supporting evidence and preserves the highest observed priority across matching service instances. Scoring evidence is retained even when it is additional context rather than a rule trigger. This makes findings comparable across executions without treating every restarted process as a new issue. It is not a promise of identical fingerprints across resource renames or rule-version changes.

Severity, confidence and exposure are separate. Priority `lasa.priority/v1` is:

```text
base = 10 + 15 × severity_rank     # informational=0 ... critical=4
potential exposure = +10
confirmed exposure = +20          # replaces potential contribution
observed initial-namespace root = +10
cap total at 100, retaining an explicit cap contribution if needed
```

Scores are not probabilities. The implementation does not discount a score for merely observing seccomp or an LSM. Each contribution and reason is stored. Multiple rule findings on a subject are not summed into a host exploitation probability.

## Attack scenarios

`attack_path` contains supporting entities/edges, observation references, prerequisites, a separately conditional compromise step, potential impact, uncertainties and scoring factors. The graph edges remain observed relationships. An implication such as attacker control or effective write capability is not encoded as a verified edge when its evidence is absent.

Supporting subgraphs follow proven incoming/outgoing relationships to depth three with at most 64 relationships per subject, keeping original edge directions and never converting adjacency into exploitability. Current path objects describe local correlation scenarios rather than arbitrary multihop paths. Consumers must not render all neighboring entities as a verified linear exploit sequence. Extension to longer paths must preserve ordered, provenance-backed steps and explicit unknown compromise prerequisites.

## Runtime identities

Runtime events carry boot-relative nanoseconds, initial-namespace PID/TID/parent, start time, helper-reported UID, bounded command name and optional endpoint/namespace flags. Attempts are labeled attempts; only successful accept/unshare exit hooks carry those outcome meanings. No event proves network payload contents or external exposure.

Static linkage requires matching boot ID, a static process in the initial PID namespace, numeric PID and matching start ticks converted from boot-relative nanoseconds on the targeted Linux ABIs. Events from ambiguous container PID views remain unlinked rather than matched by numeric PID alone. Sensor gaps and losses must survive ingestion.

## Drift and suppressions

Diff requires matching host IDs. New fingerprints are new; equal fingerprints with changed priority/severity/confidence/exposure/suppression are materially changed. An absent old finding resolves only with a compatible profile, complete collection and explicit negative/not-applicable evaluation for that stable subject/rule. Otherwise it is unknown. This may conservatively retain issues after an asset vanishes.

Suppression entries require a unique fingerprint and nonblank justification; optional expiration is an RFC3339 timestamp. Policies are bounded, strict JSON. Suppressions are local policy, not a change to the observation or evidence truth.

## SecureObs adapter responsibilities

Validate schema/limits/references; authorize asset and tenant mapping independently; ingest execution IDs idempotently; preserve all uncertainty, provenance, suppression and scoring version fields. A snapshot is not signed or encrypted by LASA. The ingestion layer must establish transport integrity and storage access policy. Do not fetch URLs or execute queries derived from report fields.
