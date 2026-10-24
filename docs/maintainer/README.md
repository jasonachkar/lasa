# Maintainer documentation

[Documentation home](../../README.md)

These files describe implementation and engineering decisions. Keep them in your private operator/developer distribution if you do not want customers to receive algorithmic details. A Markdown directory, filename or link is not access control; publication policy belongs to the repository owner.

## Reading order

1. [Implementation plan](../implementation-plan.md): intent, milestones and validation policy.
2. [Architecture](architecture.md): boundaries, scan flow and trust model.
3. [Code design](code-design.md): concrete packages, parsers, budgets and error handling.
4. [Data model](data-model.md): field semantics, identities and exported schemas.
5. [Detection catalog](rules.md): actual predicates and supported correlations.
6. [Rule authoring](rule-authoring.md): strict local declarative language.
7. [Threat model](threat-model.md): hostile input, access and disclosure boundaries.
8. [eBPF](ebpf.md): object generation, event ABI and runtime validation.
9. [Development and release](development.md): builds, tests, dependency policy and supply chain.
10. [Verification record](verification.md): measured results, failures, skipped checks and release gates.
11. [Distribution](distribution.md): existing licensing and documentation publication choices.
12. [Publishing from a Mac](publishing.md): automated release setup, APT signing, Linux Homebrew, trust and recovery.

## Engineering invariants

Unknown is never evidence of a secure state. Capability scope must precede host-privilege interpretation. Socket binding does not prove internet reachability. Metadata permission candidates do not become effective `CAN_WRITE` claims. Every finding's supporting relationships need observation references. A rule never executes arbitrary expressions or code. Optional sensor failure must stay visible. Report persistence is private, atomic and local. Successful compilation is not privileged runtime validation.

Every exported contract has its own version. Keep customer-facing descriptions accurate as implementation changes. Changes to predicates, fingerprint semantics, report fields and coverage/resolution policy need tests and explicit compatibility review.

- [Azure publishing and direct website recovery](azure.md)

- [Inspection architecture, permission model and provider trust boundaries](inspection-design.md)
- [Automated native VM validation from macOS](validation.md)

- [Native Linux package formats, repositories and signing](linux-distribution.md)
- [Full manual deployment from a Mac using a disposable local Linux publisher](local-deployment.md)
- [Local deployment review: architecture selection, failure boundaries and validation scope](deployment-review.md)
