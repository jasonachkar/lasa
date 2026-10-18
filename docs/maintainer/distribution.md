# Commercial distribution and documentation boundaries

[Maintainer index](README.md)

## Existing license

The repository arrived with an MIT license. This implementation preserves it. MIT allows commercial sale, but also permits recipients to inspect, modify, copy and redistribute licensed source subject to its terms. The implementation does not add a proprietary license, paid enforcement, license server, obfuscation or access restriction.

The specification calls for an open-source scanner while the product request also expresses a desire to sell it and keep implementation know-how private. Technical documentation cannot make public source or public Git history secret. Choose the distribution/licensing model deliberately before public release, and obtain appropriate legal review for any change. Previously granted open-source rights cannot simply be revoked by hiding a Markdown file later.

## Documentation split

`docs/customer/` explains purpose, observable behavior, access, privacy, storage, results, limits, troubleshooting and operations. `docs/maintainer/` and `docs/implementation-plan.md` explain code, predicates, architecture, algorithms, tests and supply-chain internals. The root README links both so the owner can find them; a customer distribution can publish a separately curated index.

No access-control mechanism is implemented by this layout. The owner must configure repository visibility, site publishing, release contents and document access. If internal files were public, removing links or deleting the current files would not remove them from existing copies or history.

## What customers need to know

Customers should receive truthful information about data access, impact, errors, privacy and limitations. Do not omit prerequisites or unknowns to make a finding appear stronger. You can explain the operational contract and evidence meaning without publishing the implementation catalog in a customer manual. The code itself remains governed by its license.

Commercial value may come from reviewed detection content, update cadence, deployment, authenticated ingestion, reporting workflow, fleet operations and support. None of these are claimed as paid capabilities implemented here unless they exist in the product. SecureObs integration is a versioned local export contract, not a complete backend or subscription system.

## Third-party obligations

Retain the repository license and applicable third-party notices for distributed binaries and embedded code. Dependency versions appear in `go.mod`, `go.sum` and generated SBOMs. Review cilium/ebpf's MIT terms, Cobra Apache-2.0 and pflag BSD terms, x/sys BSD terms and YAML's licenses, plus libbpf helper header/BPF build provenance as applicable. The checked-in notices are an engineering inventory, not legal advice or a substitute for reviewing the exact dependency distribution.
