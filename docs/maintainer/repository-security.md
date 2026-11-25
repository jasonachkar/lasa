# LASA repository security

The [initial audit](../../LASA_PUBLIC_RELEASE_SECURITY_AUDIT.md) records the original private configuration and findings. Audit the current source and package-site repositories with the owner's authenticated GitHub CLI session.

```sh
bash scripts/security/audit-repository.sh
```

The legacy settings planner is for the initial private-source setup. Use the public repository's active rulesets and the read-only inventory above to verify current enforcement.

The source branch and tag write rules name the owner account explicitly. Main additionally requires a squash pull request, resolved conversations, the canonical hosted LASA gate, and CodeQL. The main ruleset has no bypass actor. Version tags cannot move or be deleted, and GitHub Releases are immutable after publication. Fork workflows require owner approval, default workflow permissions are read-only, and GitHub Actions actions must be SHA-pinned.

The `release` environment admits `main` and requires owner approval before attestation or publication. The owner creates immutable release tags. CI verifies the tag and publishes package metadata using a dedicated APT signing subkey and a package-site deployment key. The source branch rules retain owner-only writes and the package site's history rules block force pushes and deletion. See [publishing](publishing.md) for activation, rotation and recovery.

Verify personal account security from GitHub's settings pages. The GitHub CLI inventory cannot enumerate all installed apps or read the owner's two-factor configuration with the standard login.

## Local validation

Review the [development](development.md) and [publishing](publishing.md) prerequisites. Run checks in a Linux VM. Keep disposable privileged test VMs separate from review runners and signing environments.

```sh
make tools security-tools
export PATH="$(go env GOPATH)/bin:$PATH"
make check coverage fuzz reproducible
actionlint
bash scripts/security/scan-history.sh
VERSION=0.0.0 make packages
VERSION=0.0.0 bash test/distribution.sh
bash test/release-security.sh
bash test/release-automation.sh
bash test/setup-ci-publishing.sh
bash test/publish-site.sh
```

The release tests use an isolated GitHub CLI mock, disposable signing keys and temporary APT state. The required PR gate includes installed-package checks on Debian and Ubuntu, syscall tracing of scanner boundaries, a Go coverage floor, longer parser fuzzing, CodeQL's separate required status check, and workflow, dependency, container and secret checks. Test the live eBPF sensor only on an authorized disposable Linux VM with tracefs and BTF. See [eBPF](ebpf.md) for the command and reporting expectations.
