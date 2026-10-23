# Rule authoring and validation

[Maintainer index](README.md)

## Local declarative packs

A pack is a single YAML document with schema `lasa.rules/v1` and a rule list. JSON is an accepted YAML subset; the builtin pack uses this representation for deterministic review. Supply custom packs only through an explicit `--rules /local/path` flag. They add to builtins and cannot override builtin IDs. LASA never downloads packs or executes expressions, shell commands, templates or plugins from them.

```yaml
schema: lasa.rules/v1
rules:
  - id: ACME-001
    version: "1"
    category: exposure
    subject: process
    title: Review a privileged non-loopback endpoint
    description: A process has a potentially reachable endpoint and observed initial-user-namespace root credentials.
    severity: high
    confidence: high
    unknown: skip
    required_evidence:
      - network.potential
      - privilege.host_root
    prerequisites:
      - An attacker would first need a compromise path; reachability and exploitation are not established by this rule.
    remediation: Reduce unnecessary privilege and verify intended network reachability.
    when:
      all:
        - predicate: network.potential
          op: eq
          value: true
        - predicate: privilege.host_root
          op: eq
          value: true
```

## Required metadata

Rules require a unique nonempty ID (at most 128 bytes), rule version `"1"`, category, `process` or `file` subject, nonempty title/description/remediation, severity, confidence, `unknown: skip`, a required-evidence list and a prerequisite list. Supported builtin confidence declarations are high, medium and low. Broader report confidence values are reserved for evidence contexts; an author cannot label a hypothetical exploit confirmed.

Applicability constraints are expressed in the typed `when` tree, for example `file.kind == service_config` or `container.hint == true`. There is no separate arbitrary applicability expression field. Unknown YAML fields are rejected, so misspelling a key does not silently weaken a rule.

## Condition grammar

Each condition contains exactly one of:

- `all: [conditions...]`
- `any: [conditions...]`
- `not: condition`
- `predicate: registered.name`, `op: typed_operator`, `value: typed_value`

Boolean/string predicates permit `eq` and `neq`. Numeric predicates permit `eq`, `neq`, `gt` and `lt`. YAML booleans must be booleans, not quoted strings. Unknown predicates, unsupported versions, invalid types/operators, ambiguous condition nodes and metadata omissions fail loading before a scan.

`all` needs all operands established. A known negative can make an `all` negative despite another unknown. `any` can succeed with a known positive alternative even if a different alternative is unknown. `not` inverts observed/not-observed and preserves unknown/not-applicable. Conflicting observations are unknown. Do not design a rule where a missing fact becomes a positive match through negation.

`required_evidence` is checked separately from the condition result. Only name evidence that must be observed for every successful branch; putting every `any` alternative in this list can unintentionally suppress useful matches.

## Registered predicates

Boolean process predicates:

```text
network.potential
network.confirmed
network.management
privilege.host_root
capability.dangerous
isolation.weak
container.hint
container.host_pid
container.sensitive_mount
```

Boolean file predicates:

```text
file.executable
file.sgid
file.owner_root
file.suid
file.capability
file.write_candidate
file.unsafe_parent
file.privileged_execution
file.acl_present
file.readonly
file.search_path
```

`file.kind` is a string: relevant values include `sudoers`, `authorized_keys`, `service_config`, `runtime_socket`, `directory`, `executable`, `other`. `identity.euid` is numeric. Read the detection catalog for the evidence and limitations of each key; a predicate name is not a stronger guarantee than its collector can establish.

`network.confirmed` remains unknown in static scans. It exists as a guarded contract for independently established exposure, not as a wildcard-address shortcut. Custom YAML cannot invent a value or elevate exposure confidence.

## Resource and parser controls

Packs are capped at 1MiB and 256 combined rules. The loader rejects anchors/aliases, unsupported tags, multiple documents, unknown fields and duplicate IDs. YAML structure is bounded to 16,384 nodes and depth 32; condition trees are separately bounded to depth 16 and 256 nodes per rule. These ceilings protect both parsing and evaluation, and must not be disabled just to accept a generated pack.

## Tests and review

For every detection, add a positive case, a negative case, unknown/missing data, not-applicable behavior, conflicting values and fingerprint/provenance assertions where relevant. Include misleading near-matches: container-root capability scope, IPv4-mapped loopback, replaced executable inode, read-only overmount, empty capability xattr and inactive filename candidates.

Use explicit fixture observations and expected outcomes, not tests that generate their expected values by evaluating the same condition tree. Review title and consequence wording independently of matching logic. A correct boolean condition can still produce an indefensible exploitability claim.

The builtin tests enumerate cases for every reviewed rule. Fuzzing exercises the YAML loader; malformed or oversized packs must return an error without executing code, following aliases or making network requests. Increasing a rule's semantic power requires a registered Go predicate, tests and privacy/scope review; YAML alone cannot add Linux access.

## Inspection assets

Rules can target `subject: asset`. Use `asset.kind` to scope a rule to its configuration/identity/runtime/package subject type before evaluating its registered inspection predicates. Missing or conflicting evidence stays unknown. Inspection definitions share the builtin engine and tests; they do not bypass evidence, scoring, suppression or report validation.
