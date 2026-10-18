# SecureObs and local report ingestion

[Documentation home](../../README.md)

## Current integration boundary

LASA is independently usable. It requires no SecureObs credentials, APIs, database or frontend. The integration artifact is the local JSON snapshot with schema `lasa.report/v1`. No automatic upload or background remote transmission is implemented.

A SecureObs-side adapter can ingest authorized reports from a controlled file transfer, deployment agent or ingestion service. That adapter owns authentication, transport, tenant authorization, encryption, retention and audit logging. Never infer authorization from the report's host ID alone.

## Recommended ingestion contract

Preserve `schema`, `scanner_version`, `scan_id`, scan times, profile and host identity. Treat `scan_id` as the execution identity and the finding fingerprint as cross-scan issue identity. Preserve evidence references, observation state, provenance, confidence, exposure, prerequisites, scoring version and contributions, suppressions, coverage and diagnostics.

Ingest each `(tenant, authorized_asset_mapping, scan_id)` idempotently. Map the pseudonymous LASA host ID to an asset only through an authenticated inventory process. Container images cloned with the same machine ID can collide operationally; a host hash is not proof of asset identity.

Do not mark an issue resolved merely because a later report omits it. Preserve unknown and partial outcomes. LASA's `diff` output uses `lasa.diff/v1` and can guide this behavior, but the backend still needs policy for profiles, collection scope and rule/score-version transitions.

## Safe ingestion

Validate size and schema before storage. Restrict nesting and array counts, reject unsupported versions, preserve referential integrity and escape all displayed strings. JSON is data, never executable queries or template code. Do not make network requests to socket addresses, file paths, schema URIs or other strings found in a report.

For downstream code scanning integrations, SARIF exports logical runtime locations. GitHub repository views can have limited support for those locations; do not invent source-file coordinates to make a host finding appear inline.

The maintainer [data model](../maintainer/data-model.md) documents field semantics and versioning. That implementation-level reference is separate from this operational integration contract.
