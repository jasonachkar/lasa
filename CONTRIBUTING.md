# Contributing

Use Linux and Go 1.27.2. Read [architecture](docs/maintainer/architecture.md), [threat model](docs/maintainer/threat-model.md) and [development](docs/maintainer/development.md) before changing collection or inference.

Add tests before changing behavior. Preserve the distinction between observed, derived, unknown and conditional. Never add credential/argv/payload collection or active probing as an incidental feature. Every finding needs provenance, prerequisites, uncertainty and actionable remediation. Missing evidence must not become a negative result or resolution.

Run `make tools`, add the tool binary directory to PATH, then `make check fuzz reproducible`. Regenerate schemas for contract changes and BPF objects for sensor changes. Document platform-specific skipped checks. Privileged tests belong on explicitly authorized disposable VMs, not untrusted pull requests or shared runners.

Keep commits cohesive, preserve unrelated user changes and do not force-push. Report bugs with minimized non-sensitive fixtures. Follow [SECURITY.md](SECURITY.md) for security-sensitive reports.
