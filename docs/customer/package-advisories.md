# Package advisories

[Documentation home](../../README.md)

Package inspection compares native installed-package versions against a local, release-specific advisory database. Scanning does not download advisories or upload a package inventory. Advisory retrieval is a separate, explicit network operation.

## Update from the official Debian tracker

Run this on your Linux management or scanning system. Choose the exact release codename:

```bash
lasa advisories update --release trixie --output ./advisories.json
lasa scan --inspect packages --advisories ./advisories.json \
  --format json --output packages.report.json
```

For Debian 12, use `--release bookworm`. The updater downloads the official Debian Security Tracker JSON over verified HTTPS, streams source-package records, preserves fixed vendor versions and records provenance and expiry. It refuses redirects, invalid data and download/cache size limits. The endpoint does not provide a detached JSON signature; LASA does not claim signed-vendor provenance for this download.

The database expires seven days after retrieval. Schedule the updater separately from scans using your approved scheduler. A failed update does not replace an existing database. Keep the failure visible; an expired database must not silently become a clean vulnerability result.

## Other vendor-derived databases

Import a database that has been prepared and authenticated through your organization's vendor-data process:

```bash
lasa advisories import --input vendor-advisories.json --output ./advisories.json
```

Import validates structure, supported schema and freshness. It does not authenticate an arbitrary file's claimed vendor identity or convert every vendor feed format. Built-in automatic retrieval currently targets Debian; Ubuntu and supported RPM-family distributions use the documented import format.

Use the exact distribution identifier and version reported by the inspected system. Debian uses its release codename when available. Ubuntu uses `ubuntu:VERSION_ID`; RPM-family systems use `ID:VERSION_ID` from `os-release`, including the minor release where present. A database for a different release is not substituted.

Example **synthetic** database:

```json
{
  "schema": "lasa.advisories/v1",
  "source": "https://vendor.example/security",
  "fetched_at": "2026-01-01T00:00:00Z",
  "expires_at": "2026-01-08T00:00:00Z",
  "records": [
    {
      "id": "VENDOR-EXAMPLE-001",
      "distribution": "ubuntu:24.04",
      "package": "example-service",
      "source_package": false,
      "introduced": "1.0-1",
      "fixed": "1.0-1ubuntu0.2",
      "severity": "high"
    }
  ]
}
```

The example is deliberately expired and does not represent a real advisory. Supply real vendor-derived timestamps and records; do not extend timestamps merely to silence expiry. Optional `source_updated_at` records an upstream timestamp when available. Optional `uncertain: true` preserves an undetermined vendor assessment instead of treating it as a confirmed affected or unaffected range.

Ranges include `introduced` and exclude `fixed`. An omitted `introduced` has no lower bound; an omitted `fixed` records an unresolved range. Supported severities are `informational`, `low`, `medium`, `high` and `critical`. `source_package: true` uses native source-package metadata where available. Preserve vendor epochs, release suffixes, security-update revisions and backport identifiers.

## Native version matching

Debian and Ubuntu use dpkg-style epoch/upstream/revision ordering. Supported RPM-family identifiers are `rhel`, `rocky`, `almalinux`, `centos`, `fedora`, `ol`, `sles` and `opensuse-leap`; matching uses RPM epoch/version/release ordering. Native inventory requires `dpkg-query` or `rpm` respectively.

This avoids assuming that an older-looking upstream version lacks a distribution's backported fix. Matching still depends on accurate vendor data and the package database. It does not verify every executable byte, inspect vendored application dependencies or establish exploitability. Unsupported distribution/version schemes remain unknown.

## Running-service association

LASA can associate an affected package with an observed process when the current executable path matches the captured device/inode metadata and the native database identifies its owner. Non-loopback listeners can then increase review priority.

Deleted, replaced, unowned, ambiguous or inaccessible executable paths remain explicit association gaps. Updating a package does not establish that every running process has restarted into the new code. Review the recorded identity and restart affected services through your operations process.

## Freshness and storage

`--advisory-max-age` defaults to 168 hours. `0` disables this additional age limit while retaining the database's own expiry check. A future fetch timestamp beyond clock tolerance, expired database, malformed file or missing release data produces a diagnostic. Known vendor uncertainty is preserved.

Cache files are written privately and atomically. They contain package/advisory data and source metadata, not scan reports. Reports store relevant installed versions, advisory identifiers, fixed versions, severity, data provenance and selected running-service relationships. They do not embed the complete advisory cache or package database.

Treat imported database producers as part of your security trust boundary. See [data access and privacy](data-and-privacy.md) and [detection coverage](detection-coverage.md).
