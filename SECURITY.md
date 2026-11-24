# Security policy

LASA is an initial implementation. The current release's verified capabilities and remaining production risks are recorded in [verification](docs/maintainer/verification.md). Do not assume untested privileged/kernel combinations are supported.

Use [GitHub private vulnerability reporting](https://github.com/jasonachkar/lasa/security/advisories/new) to report a vulnerability to the owner. Limit initial reports to the evidence needed to reproduce the issue. Keep credentials, private keys, full process environments, and unredacted infrastructure reports in your own secure systems.

Include the scanner version, affected component, a minimal reproduction/fixture, platform/kernel context, impact and non-sensitive diagnostic codes. A kernel verifier failure should include its relevant log through an approved private channel. Do not disable verification or run exploitation on systems you are not authorized to test.

Maintainers should triage whether the issue affects collection safety, evidence integrity, report disclosure, dependency supply chain or inference accuracy; add a regression test and update advisories/documentation when necessary.
