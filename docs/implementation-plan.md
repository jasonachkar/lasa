# LASA implementation plan

Status: implementation and available local verification completed; privileged/runtime and broader VM release gates remain explicit in [verification](maintainer/verification.md). This document is for maintainers.

## Architecture and contracts

LASA is a local Linux scanner. Domain values and observations have explicit states and schema versions. Bounded collectors read Linux metadata through a constrained filesystem adapter. Application orchestration collects a snapshot, builds an indexed provenance graph, evaluates typed declarative rules, and emits scored findings. Reporting and persistence depend on the domain, never the collectors. CLI and daemon use the same application service. Static scans do not need cloud services, runtime sockets, or eBPF.

Data is untrusted. Do not read process environments, argument strings, private keys, network payloads, or arbitrary application contents. Only allowlisted kernel/proc metadata and explicitly scoped filesystem metadata are collected. Permission errors, vanished processes, truncation and namespace uncertainty remain visible. Wildcard listeners imply potential exposure only. Write permission bits imply potential access unless ACL, mount and identity checks establish effective access. Container identification is a hint unless established independently. Findings describe conditional consequences, never unproved exploitability.

Customer documentation will explain observed data, use, retention, limitations and remediation. Maintainer documentation will describe predicates, algorithms, internals, build and threat boundaries. This directory split is editorial, not access control; public source and public Git history cannot protect trade secrets. Existing MIT licensing remains unchanged pending an owner licensing decision.

## Working milestones

1. Foundation: domain, diagnostics, configuration, Linux filesystem adapter, CLI and tests.
2. Collection: bounded process, identity, network namespace, filesystem, container and kernel metadata, fixtures and parser tests.
3. Analysis: provenance graph, three-valued rule evaluation, strict YAML, supported builtin rules, scoring and correlation tests.
4. Usability: real scan, doctor, explain, deterministic JSON, terminal, HTML, SARIF, safe persistence, coverage-aware diff and suppression.
5. Operations: cancellable non-overlapping daemon, retention, deployment and operational tests.
6. Runtime: optional cilium/ebpf sensor with generated objects, feature diagnostics and bounded events. Unverified or unavailable sources must be reported explicitly.
7. Delivery: customer and maintainer documentation, CI/release/SBOM/signing configuration, AMD64/ARM64 binaries, verification record and committed checkpoints.

## Verification

Use supported Go 1.27.2 with module checksum verification. Run tests before implementation for each new behavior, then targeted and full tests, race, vet, lint, fuzz smoke, vulnerability scan, real unprivileged Linux/socket/CLI/daemon tests and deterministic builds. Validate report formats and restricted output writes. Use real kernel load/event tests only when capabilities permit; a build alone never verifies sensor attachment. Record exact commands and environment, skipped checks and blockers. Do not change host security settings or elevate automatically. Do not claim universal or complete production validation.

## Resource budgets

Default deadline 30 seconds; bounded process workers, PID count, file reads, file descriptors, directory entries, graph edges, report input and rule sizes. Profiles make visibility explicit; deep requires effective UID zero and never runs sudo. Sensor is opt-in; unsupported hooks stay disabled with diagnostics. No outbound requests in the scanner. Build tooling may download pinned dependencies and release tools over authenticated TLS.

## Configuration inspection expansion

The original metadata-only boundary remains the default. Explicit `--inspect` authorization now adds the providers and selected configuration access described in [inspection design](maintainer/inspection-design.md) and the [customer collection contract](customer/data-and-privacy.md). Native/API responses can include arguments/environment values transiently, which are discarded. This is a deliberate opt-in contract extension, not a reinterpretation of the baseline rules above.
