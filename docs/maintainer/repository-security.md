# LASA repository security

Keep the source repository private until the owner makes the public-source decision in [the audit](../../LASA_PUBLIC_RELEASE_SECURITY_AUDIT.md). Use the existing GitHub CLI login on github.com for administrative changes. The scripts print allowlisted settings and names of secrets. Keep their output with the private audit evidence.

## GitHub settings

```sh
bash scripts/security/audit-repository.sh
bash scripts/security/harden-repository.sh
bash scripts/security/harden-repository.sh --stage distribution
bash scripts/security/harden-repository.sh --stage governance
bash scripts/security/verify-repository.sh
bash scripts/security/verify-repository.sh --stage distribution
bash scripts/security/verify-repository.sh --stage governance
```

Hardening defaults to a dry run. Review the endpoint and request body for each operation before adding `--apply`. The governance stage also requires `--sha` identifying a successful hosted `ci.yml` run from this repository. It activates the new `main` protections before moving the legacy admin-only ref policy off `main`. Unknown or changed settings stop the script for review. Keep release credentials in the protected `release` environment. Credential maintenance and billing belong to the owner account.

GitHub's `main` policy uses a strict required check from the GitHub Actions integration, squash merging, resolved conversations and no admin bypass actor on that ref. One maintainer can merge their reviewed PR after checks pass. `CODEOWNERS` routes changes in sensitive areas to the maintainer. A repository administrator can still edit the rules themselves. Review workflow and gate changes carefully since a required status check binds the name and GitHub App identity.

Release tags use two rulesets. The admin role may create a version tag. Tag updates, force moves and deletions have a separate active rule without bypass actors. Immutable releases protect published assets at the repository level. The release environment accepts only `main` and has admin bypass disabled. The existing single-maintainer private plan uses explicit workflow dispatch as operator authorization. A public repository can use its required reviewer protection with the owner as the reviewer and self-review enabled. Recheck the available GitHub features and the release process before adding any reviewer requirement.

Private fork runs and cross-repository Actions access are disabled for LASA. GitHub exposes its public fork approval setting only on a public repository. If the owner authorizes visibility later, recheck the public fork approval policy and configure approval for all outside collaborators before approving their runs. Use isolated GitHub-hosted verification only. Check the account's GitHub App installations directly if the active GitHub CLI token cannot enumerate them.

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

The distribution repository permits signed-package automation to fast-forward its Pages branch with a dedicated deploy key. It rejects default-branch deletion and non-fast-forward updates. The deploy key remains able to write any path on that repository. Protect credentials and review the Pages publication routes before changing how package automation authenticates.
