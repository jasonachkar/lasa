# Write custom rules

[Documentation home](../../README.md) · [CLI reference](cli-reference.md) · [Understand results](results.md)

Custom rules let you flag combinations of evidence that matter in your environment. A rule pack is a local YAML file that you pass explicitly with `--rules`. It adds to the builtin rules and can never replace one. LASA never downloads rule packs, and rules cannot run commands, templates or expressions.

## A minimal pack

```yaml
schema: lasa.rules/v1
rules:
  - id: ACME-001
    version: "1"
    category: exposure
    subject: process
    title: Root process listening beyond loopback
    description: A process running as root in the initial user namespace owns a potentially reachable endpoint.
    severity: high
    confidence: high
    unknown: skip
    required_evidence: [network.potential, privilege.host_root]
    prerequisites:
      - Network access to the endpoint and a flaw in the service.
    scenario: A client that compromises this service would run code as root.
    impact: Host compromise through one network-facing service.
    remediation: Run the service as a dedicated account and restrict the bind address.
    when:
      all:
        - {predicate: network.potential, op: eq, value: true}
        - {predicate: privilege.host_root, op: eq, value: true}
```

Check it without scanning, then use it:

```sh
lasa rules validate acme-rules.yaml
lasa scan --rules acme-rules.yaml
```

## Fields

| Field | Required | Meaning |
| --- | --- | --- |
| `schema` | yes | Must be `lasa.rules/v1` at the top of the file |
| `id` | yes | Unique ID, at most 128 bytes; builtin IDs (`LASA-*`) cannot be reused |
| `version` | yes | Must be `"1"`; part of each finding's fingerprint |
| `category`, `title`, `description`, `remediation` | yes | Shown with every finding |
| `subject` | yes | `process` or `file` |
| `severity` | yes | `informational`, `low`, `medium`, `high` or `critical` |
| `confidence` | yes | `high`, `medium` or `low` |
| `unknown` | yes | Must be `skip`: unknown evidence never produces a finding |
| `required_evidence` | yes | Predicates that must be observed (not unknown) for a match |
| `prerequisites` | yes | What an attacker would need first |
| `scenario`, `impact` | no | Rule-specific consequence text; generic wording is used when omitted |
| `when` | yes | The condition tree below |

Unknown fields are rejected, so a misspelled key cannot silently weaken a rule. A pack is limited to 1 MiB and 256 rules.

## Conditions

Each condition node contains exactly one of `all: [...]`, `any: [...]`, `not: {...}`, or `predicate` with `op` and `value`. Boolean and string predicates accept `eq` and `neq`; numeric predicates also accept `gt` and `lt`. Booleans must be YAML booleans, not quoted strings.

Unknown evidence is preserved: `all` is negative as soon as one operand is known to be false, `any` matches as soon as one operand is known to be true, and `not` keeps unknown as unknown. A missing fact can never become a match through negation.

## Predicates

Run `lasa rules predicates` for the list supported by your installed version, with its subject, type and meaning (`--format json` for tooling). File predicates use the location-based `file.kind`; for example, `file.kind eq sudoers` matches `…/etc/sudoers` and direct children of `…/etc/sudoers.d`.
