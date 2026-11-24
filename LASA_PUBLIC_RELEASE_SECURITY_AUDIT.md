# LASA public release security audit

**Decision — NOT READY FOR PUBLIC SOURCE RELEASE**

**Production binary release — blocked**

On November 19, 2026, GitHub reported that `jasonachkar/lasa` was private. Requests without authentication received HTTP 404 for both repository and release metadata. The existing GitHub CLI login had administrator access. The source default branch remained at `086c56e74987`. The changes are in [draft PR #5](https://github.com/jasonachkar/lasa/pull/5).

The audit hardened live repository settings and found runtime, evidence integrity and publishing issues. GitHub refused to start hosted verification because of an account payment or Actions spending limit. The new required check cannot be activated safely until it has passed on GitHub. The local results below are separate from that hosted result.

## Repository access and permission assessment

| Surface | Verified GitHub state |
| --- | --- |
| Source repository | Private, personally owned, default branch `main`. The owner is the only listed collaborator and has administrator access. There were no pending invitations. |
| Source credentials | No repository-scoped Actions secrets, Dependabot secrets, deploy keys or webhooks. The `release` environment lists `APT_SIGNING_KEY`, `DISTRIBUTION_DEPLOY_KEY` and `APK_SIGNING_KEY`. The current workflow uses the first two. No environment variables were listed. Repository variables were inventoried by name only. |
| Existing access | No self-hosted runners. Actions default to read-only tokens and cannot approve PRs. Private fork workflows, write tokens/secrets for private fork jobs and cross-repository Actions access are disabled. |
| App installations | The existing login cannot enumerate all app installations. The repository installation endpoint requires an app JWT and the user installations endpoint requires app authorization. Verify the installations in the owner account before public release. |
| Distribution repository | `jasonachkar/homebrew-lasa` is already public and personally owned. The owner is its only listed collaborator. One verified deploy key has write access. No pending invitations, webhooks, repository secrets, repository variables or self-hosted runners were listed. |
| Pages | GitHub API confirms public branch-based Pages on distribution `main` with HTTPS enforced. Its deployment environment now allows only `main`. The source Pages endpoint returned 404 and was recorded as unverified. |
| Published assets | The only source release is the empty draft `v0.1.0`. Its tag resolves to a commit outside the history of the current `main`. The distribution tree contains preview documentation and has no APT index or Homebrew formula at its root. Production asset signatures and downloads could not be validated. |

No new authentication token was created. Existing credentials and keys were used only through their configured services or inventory metadata. No production credential values appeared in the audit or tests.

## Confirmed findings and remediation

| Severity | Component and evidence | Impact | Remediation and verification |
| --- | --- | --- | --- |
| High | The former `version.yml` created release tags on pushes to `main` independently of the verification result. The release workflow also ran on version tags and accepted tagged feature commits. The existing off-main draft shows the latter path existed. | An owner or credential able to start the legacy flow could publish from unverified source. | Disabled automatic versioning remotely and removed it from the branch. The new workflow requires explicit dispatch from `main`, an immutable tag that identifies the exact tested commit, continued ancestry in `main`, a successful canonical push run and a passing aggregate gate. Fixture tests cover a feature ref, tag/SHA mismatch, unrelated main history, skipped/failed verification and rejected provenance. |
| High | The release environment originally accepted any branch or tag and allowed admin bypass. The privileged workflow had no specific ref restriction and targeted a self-hosted runner label. There were no registered runners. | Release credentials or privileged execution could become available on a wider set of revisions if a maintainer dispatched a modified workflow or registered the runner. | Restricted release deployment to `main`, disabled admin deployment bypass and disabled the legacy privileged workflow. Removed self-hosted workflows on the branch. Read back the environment policy, runner count, secret scope and disabled workflow state. Used a separate VM for the live eBPF test. |
| High | GitHub's existing `main` ruleset targets all branch refs, requires one approval and grants the repository-admin role an always-allowed bypass. No required CI status was listed. | The sole maintainer can use normal admin operations to skip the effective PR policy, and a non-bypass merge would require another reviewer. | Prepared a no-bypass `main` policy with successful GitHub Actions checks, up-to-date branches, PRs, resolved conversations and squash merges. The legacy non-default branch policy is preserved in the plan. Activation is blocked on a successful hosted gate. |
| High | Release tags had no repository ruleset. Published release assets were mutable at the repository level. The legacy retry accepted a downloaded checksum list without binding it to the exact source SHA and workflow. | A moved tag or altered assets could break the link between reviewed source and customer downloads. | Activated separate tag creation and integrity rules and enabled immutable releases. The new branch validates the artifact SHA, flat expected inventory, digests and SBOMs, and verifies GitHub-hosted workflow provenance tied to `main` and the tested SHA. The release retry fixture rejects different bytes and a denied attestation. |
| Medium | The daemon checked the permissions of a state path, then reopened that path for locking, persistence and retention. A deterministic fixture swaps the pathname during a scan. | Locking and report operations could address different directory inodes. Report persistence could occur outside the originally validated state directory. | Open and validate a scanner-owned private directory once, then lock, write and prune relative to that descriptor. The test confirms that the replacement directory receives no output. |
| Medium | Metadata input readers opened paths for I/O before checking file type. The fixture uses a local FIFO. | Special-file opens can have side effects, and FIFO/device data can be mistaken for a regular metadata source. | Check the pinned inode before opening it for reading. Tests verify rejection of nonregular input and preserve ordinary read-only Linux and container collection. |
| Medium | The v1 JSON decoders accepted duplicate and case-ambiguous object members in snapshots and suppression policies. | Different consumers could assign different effective values to scan identity, evidence or suppression entries. | Decode with Go 1.27's strict JSON v2 API. Valid existing LASA JSON remains readable. Tests cover duplicate, case-variant and trailing data in both parsers. [Go JSON decoding behavior](https://go.dev/doc/go1.27#standard-library) |
| Medium | The embedded eBPF object failed to load on a live Ubuntu ARM64 kernel. The verifier rejected a call from the accept tracepoint entry point to another entry point. | The optional sensor could fail before attaching, leaving runtime evidence unavailable. | Both entry points now inline a shared routine. Regenerated the embedded object and verified live process, connect, bind and accept event delivery in a disposable VM. |
| Medium | The public distribution default branch had no ruleset, and a full-repository deploy key could change its Pages content. A stale deployment policy allowed an absent `gh-pages` branch. | A compromised publisher could overwrite distribution content. | Added branch deletion and non-fast-forward protection, removed the stale Pages policy and enabled private vulnerability reports. A stolen key can still fast-forward changes to any path in the distribution repository. No key was revoked. |
| Medium | The APT publisher signed metadata without `Valid-Until`. APT uses an unattended long-lived signing key. | Old signed metadata can be replayed to a client that accepts it. A stolen signing key can sign replacement metadata. | Added opt-in signed expiry and tested expiry enforcement with an isolated APT client. Production expiry remains unset until there is a verified refresh process. Credential rotation and a new trust anchor require separate owner authorization. |
| Low | Package maintainer and bootstrap signing metadata contained a personal email in tracked files. One non-noreply author identity also appears in available history. | Publishing the source could disclose that identity and old contact details. | Current package metadata uses the owner GitHub noreply address. New signing identities omit the personal address. Review whether the existing history can be released as-is. No history or key was changed. |

No critical finding or live credential exposure was confirmed. GitHub ownership still grants the power to edit repository rules. The hardened policy can require the GitHub Actions app and check name, while owner review remains important for any PR that changes the check itself.

## Live changes and effective protection

Ten source changes and three distribution changes were applied through the existing login. Both verification commands subsequently reported zero drift in those stages.

| Scope | Applied and read back |
| --- | --- |
| Source workflows | Disabled `version.yml` and `privileged.yml`. Enabled full-commit-SHA pinning for Actions while retaining the existing Actions allow policy. |
| Source environment | Enabled a custom deployment policy, added the `main` branch rule and disabled administrator bypass. No tag rule or required reviewer was added. |
| Source tags and releases | Active `LASA release tag creation` and `LASA release tag integrity` rulesets cover `refs/tags/v*`. The administrator role is the only exception on creation. The separate rule for update, deletion and non-fast-forward changes has an empty bypass list. Immutable releases are enabled. |
| Vulnerability management | Dependabot alerts and security updates are enabled. Listing individual Dependabot alerts returned an authorization error with the current login. |
| Distribution | Effective default-branch rules prohibit deletion and non-fast-forward updates. Private vulnerability reporting is enabled. The existing HTTPS Pages source is still operational on `main` at the API level, with only `main` allowed for deployment. |
| Main migration | Pending. The legacy all-branch ruleset remains effective. GitHub logged the existing admin bypass when creating and updating the dedicated review branch. The governance apply guard rejected the unverified candidate before making changes. No push or merge to `main` occurred. |

GitHub's actual tag and branch rules were read through the API. The audit used anonymous read denials and isolated mock release tests. There was no outside contributor account granted access for live push, fork PR, deployment or secret-access tests.

## Actions and supply-chain assessment

- Ordinary CI and documentation verification run on GitHub-hosted jobs with read-only repository permissions, disabled checkout credential persistence and no publishing secrets. There are no `pull_request_target` or `workflow_run` privilege transfers. Python docs dependencies require pinned hashes. Go module checksums and the linked module allowlist are checked. Build caches are disabled in the updated workflows.
- Release checks take shell inputs from quoted environment variables and validate the version format. Release build, attestation, GitHub upload and cross-repository distribution use separate permissions or jobs as applicable. Artifacts come from the same run. A signed checksum manifest covers the exact payload and name set. Existing drafts accept only missing assets or matching digests, and existing published releases are verified again on retry.
- The distribution job accesses the signing and SSH credentials as explicit step inputs. It authenticates SSH host keys through GitHub's HTTPS API. The Homebrew formula embeds architecture-specific SHA-256 hashes. APT checks a pinned OpenPGP fingerprint, a repository-specific keyring and signed index metadata. The installer and key are delivered from the same site for initial trust, so the production fingerprint needs a separately trusted reference.
- The Go toolchain is pinned to Go 1.27.4. BPF builds use a digest-pinned Debian 13.6 OCI index and fixed Clang, LLVM and libbpf versions. Release runner system packages come from signed Ubuntu repositories. Reproducibility was checked for repeated local builds and packages. Release runner image differences and external publishing remain unverified. [Go release history](https://go.dev/doc/devel/release)
- Identity-based GitHub provenance is in the workflow. On the current personal private repository, native GitHub artifact attestations require Enterprise Cloud. Provisioning a new credential or plan was outside the audit. A real OIDC attestation, live deployment and public Homebrew fetch were not run. [GitHub artifact attestation availability](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

## History and disclosure audit

Gitleaks 8.30.1 reported zero findings in the original 30 commits across the available refs, commit-message text and the audited source tree. The audit branch was also scanned with full refs, tracked tree content and commit messages. Credential reports were redacted and kept out of Git. Filename checks found no tracked ENV, IDE, obvious key, report or archive filenames in the baseline history. The compiled sensor is a tracked binary and detection in binary contents is limited. The older checkout's staged and untracked IDE files were excluded from the audit commits. The clean checkout ignores IDE files, local build outputs and report exports.

Maintainer documentation, implementation notes, package metadata, public site references and current scripts were reviewed for disclosure. The strict website build uses a customer-documentation allowlist. Making the repository public would publish its Git history and tracked maintainer material. Decide whether to retain the historical author identity, old package metadata and maintainer documents before making that change.

## Runtime and verification evidence

Local Linux testing ran in a disposable, credential-free Ubuntu 24.04.5 ARM64 VM with Linux `6.8.0-147-generic`, tracefs and kernel BTF. The pinned Go toolchain was verified against its upstream SHA-256. The tests targeted code revision `3730adc9f5a730b1a6b89a73b07829842b5c688b`. The audit report is a subsequent documentation change.

| Check | Result |
| --- | --- |
| `go test -count=1 -json ./...` | Passed across 21 packages. 84 passing test/subtest events, zero failures. The privileged sensor test was skipped in this invocation and passed in its separate VM run. |
| `CGO_ENABLED=1 go test -race -count=1 -json ./...` | Passed across 21 packages. 84 passing test/subtest events, zero failures or race reports. The privileged sensor test was skipped in this invocation. |
| `go vet ./...`, Staticcheck 0.8.2, `make deps`, and Govulncheck 1.9.0 | All commands exited 0. Module checksums verified and the linked dependency allowlist matched. Govulncheck reported no vulnerabilities. Go formatting also passed. |
| `make fuzz` | Passed all seven three-second fuzz targets. Stat, Status, Socket, SocketTable, MountInfo, Load and Decode. |
| Pinned BPF regeneration and privileged sensor integration | Passed. Pinned Debian ARM64 regeneration matched the tracked Go wrapper and object byte-for-byte. Live `TestPrivilegedSensorEventDelivery` passed in 3.04 seconds. |
| `VERSION=0.0.0 make reproducible packages` | Passed for Linux AMD64 and ARM64. Repeated builds and packages matched. Both CycloneDX SBOMs passed platform and dependency checks and reproduced byte-for-byte. The verifier accepted the nine-asset SHA-256 manifest from the fixture build. |
| `VERSION=0.0.0 bash test/distribution.sh` | Passed reproducible DEB/archive creation, extraction, real signed APT downloads for both architectures, expiry rejection, tamper/key rejection, and retry/rollback guards. |
| Restricted container and offline report rendering | Passed non-root container doctor and scan with networking disabled, all capabilities dropped and a read-only filesystem. Offline HTML rendering succeeded. |
| Actionlint, ShellCheck, history scan and settings tests | Actionlint and ShellCheck exited 0. Gitleaks history, commit message and tracked tree passes found zero leaks. All four mocked repository-settings tests passed. |
| Release, provisioning, domain, versioning and documentation fixtures | All five fixtures exited 0. Release required the tested main commit and exact assets. Bootstrap/DNS APIs were mocked. Version allocation, strict docs and isolated multi-version deployment passed. |
| Hosted Linux verification | Blocked before job execution. GitHub annotated the check with an account payment or Actions spending-limit failure. [Failed hosted run](https://github.com/jasonachkar/lasa/actions/runs/44669555123) |
| Hosted CodeQL | Skipped on private LASA. API reported repository code scanning unavailable to this session. |
| End-to-end hosted production release | Not executed. There is no live provenance, Pages APT delivery, immutable release upload or Homebrew download test. |

Reviewed filesystem traversal and symbolic link handling, metadata budgets and parser boundaries, Linux capability and systemd settings, BPF attachment/cleanup, report encoding, and SecureObs export. LASA's scanner remains local and read-only. Container testing used no network, no added capabilities and a read-only filesystem. The optional kernel sensor was tested natively on ARM64. Native AMD64 kernel attachment and hosted AMD64 BPF regeneration are unverified. The audit does not establish safety for every kernel, large input or external tool that renders SARIF.

## Unavailable features and residual risks

- GitHub billing prevents required hosted verification. CodeQL and native secret scanning were not enabled on this private repository. The API explicitly reported secret scanning disabled. Gitleaks and Govulncheck give local coverage. CodeQL is configured on the branch and gated by repository visibility or a confirmed private entitlement.
- GitHub's public-only outside contributor approval setting and source private vulnerability reporting cannot be verified for a later public repository state. The existing private fork policy currently denies fork workflow runs. Before approving an outside public contribution, verify manual approval for all outside contributors, read-only fork tokens and no publishing secrets. [GitHub Actions repository controls](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
- Review account GitHub App installations using the owner UI. Review the unused `APK_SIGNING_KEY` and production signing identities without exposing key values or changing credentials. Repository administration remains a trusted role.
- The release job uses an explicit owner dispatch as the independent release decision while private. GitHub withholds required deployment reviewers on ordinary private plans. If the public configuration uses the owner as the required environment reviewer, self-review must remain available for this sole-maintainer repository. [GitHub deployment environment availability](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
- Package signing is an unattended trust boundary. The existing SSH key is scoped to the distribution repository but can alter all its paths. Production APT expiry stays opt-in until an authenticated refresh schedule and alerts have been validated. GitHub OIDC provenance is applicable to binaries and manifests, while APT still needs a compatible signing key and client trust anchor.

## Public-source gate

1. Resolve the account Actions billing or spending issue and get a green **LASA verification gate** on the current draft PR, including both Linux architectures, security scans and docs.
2. Apply the prepared single-maintainer governance change with a verified PR head SHA. Then read back the effective rules and obtain a controlled PR merge under those rules. Review the workflow and sensitive paths as the owner.

   ```sh
   gh pr checks 5 -R jasonachkar/lasa --watch --fail-fast
   sha=$(gh pr view 5 -R jasonachkar/lasa --json headRefOid --jq .headRefOid)
   bash scripts/security/harden-repository.sh --stage governance
   bash scripts/security/harden-repository.sh --stage governance --sha "$sha" --apply
   bash scripts/security/verify-repository.sh --stage governance
   ```

3. Complete the app access and historical privacy reviews. Record which private-plan security features are unavailable and verify the local alternatives.
4. Make a separate owner decision about visibility. Consult the GitHub public-fork workflow policy and private vulnerability reporting settings when authorizing any visibility change. Keep the repository private until the above gates are satisfied.

## Production-binary gate

Require a successful hosted push verification run for the protected `main` SHA and a non-publishing release dispatch for an existing version tag on that SHA. Reserve a fresh version because the existing `v0.1.0` draft points outside `main`. Keep the existing tag and draft for owner review. Verify native hosted provenance support and the expected signing workflow identity. Validate immutable published bytes, package signatures, the APT trust anchor and freshness policy, the public Homebrew download and exact served Pages metadata using authorized staging or the separately approved production release. The audit did not publish binaries or change visibility.
