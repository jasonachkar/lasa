# Security policy

LASA is an initial implementation. The current release's verified capabilities and remaining production risks are recorded in [verification](docs/maintainer/verification.md). Do not assume untested privileged/kernel combinations are supported.

Do not post credentials, private keys, full process environments or unredacted infrastructure reports in public issues. Use the repository's private vulnerability reporting feature if the owner has enabled it. Otherwise contact the repository owner through an established private channel to arrange secure disclosure before sharing sensitive details. No fictional security email or response SLA is asserted.

Include the scanner version, affected component, a minimal reproduction/fixture, platform/kernel context, impact and non-sensitive diagnostic codes. A kernel verifier failure should include its relevant log through an approved private channel. Do not disable verification or run exploitation on systems you are not authorized to test.

Maintainers should triage whether the issue affects collection safety, evidence integrity, report disclosure, dependency supply chain or inference accuracy; add a regression test and update advisories/documentation when necessary.
