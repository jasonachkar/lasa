# LASA repository security

The [initial audit](../../LASA_PUBLIC_RELEASE_SECURITY_AUDIT.md) records the original private configuration and findings. Audit the current source and package-site repositories with the owner's authenticated GitHub CLI session.

```sh
bash scripts/security/audit-repository.sh
```

The legacy settings planner is for the initial private-source setup. Use the public repository's active rulesets and the read-only inventory above to verify current enforcement.

The source branch and tag write rules name the owner account explicitly. Main additionally requires a squash pull request, resolved conversations, the canonical hosted LASA gate, and CodeQL. The main ruleset has no bypass actor. Version tags cannot move or be deleted, and GitHub Releases are immutable after publication. Fork workflows require owner approval, default workflow permissions are read-only, and GitHub Actions actions must be SHA-pinned.

The `release` environment admits `main` and requires owner approval before attestation. The release workflow has no contents-write token or signing or deploy secrets. Both official repositories accept branch and tag writes from the owner account. GitHub Pages builds the published package site from the owner's `main` push. See [publishing](publishing.md) for the manual release steps.

Verify personal account security from GitHub's settings pages. The GitHub CLI inventory cannot enumerate all installed apps or read the owner's two-factor configuration with the standard login.

## Local validation

Review the [development](development.md) and [publishing](publishing.md) prerequisites. Run checks in a Linux VM. Keep disposable privileged test VMs separate from review runners and signing environments.

```sh
make tools security-tools
export PATH="$(go env GOPATH)/bin:$PATH"
make check fuzz reproducible
actionlint
bash scripts/security/scan-history.sh
VERSION=0.0.0 make packages
VERSION=0.0.0 bash test/distribution.sh
bash test/release-security.sh
```

The release test uses an isolated GitHub CLI mock and fixture inputs. The APT integration uses fresh test signing keys and a temporary package state. Test the live eBPF sensor only on an authorized disposable Linux VM with tracefs and BTF. See [eBPF](ebpf.md) for the command and reporting expectations.
