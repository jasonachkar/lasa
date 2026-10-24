# Local deployment review

[Maintainer index](README.md) · [Local deployment](local-deployment.md) · [Verification evidence](verification.md)

## Architecture failures and corrections

The reported `no matching manifest for linux/arm64/v8` occurred because the original package-client matrix selected AMD64 at execution but left pulls to Docker's default architecture. A subsequent owner run completed Fedora installation/upgrade/removal and reported a QEMU `SIGSEGV` around its remaining rejection check. The current pipeline uses native clients on each publisher architecture, removing cross-architecture emulation from local verification.

The reviewed local path now uses these explicit choices:

| Operation | Intel guest | Apple Silicon guest |
| --- | --- | --- |
| Go/Python/build tools | Native AMD64 | Native ARM64 |
| Artifact builds | AMD64 and ARM64 | AMD64 and ARM64 |
| Alpine repository generation | AMD64 Alpine tool | ARM64 Alpine tool |
| Fedora/openSUSE/Alpine client matrix | Native AMD64 | Native ARM64 |
| Pacman protocol | Official Arch AMD64 client | Native Ubuntu ARM64 Pacman/libalpm fixture |
| Worker failure-boundary fixture | Native AMD64 Ubuntu | Native ARM64 Ubuntu |

`scripts/package-containers.sh` holds the pins, validates cached image architectures, pulls with `--platform`, and smoke-tests actual package-tool execution. The publisher uses the same platform selection and explicitly selects its native platform for each Alpine run. Image/daemon/registry failures identify their boundary before expensive compilation or credential transfer. ARM64 Fedora/openSUSE references come from the original reviewed image indexes. The native Pacman fixture is built before verification from the pinned Ubuntu platform image and Ubuntu-signed packages; its cache key includes its base, Dockerfile and architecture.

A second issue appeared during review: classic Docker rejected replacing a cached Alpine image-index digest with another architecture (`cannot overwrite digest`). Alpine now uses different platform-manifest references for AMD64 and ARM64. Both references were resolved from the existing pinned index, preserving the reviewed image content. This requires no cache deletion and prevents architectures from sharing an ambiguous cache reference.

The earlier review fixed QEMU registration, but registration and version probes did not establish that every Fedora cryptographic path would work under emulation. QEMU is now absent from the deployment prerequisites and verification strategy. The Ubuntu ARM64 Pacman fixture verifies the package/repository protocol, not an Arch ARM operating-system distribution. Native target-distribution certification remains a separate compatibility gate.

## Deadlines and rejection semantics

`run-package-container.sh` applies explicit deadlines, records each container ID in a private temporary directory and removes only that container on exit or interruption. Readiness/indexing commands receive 60 seconds; full client scenarios receive five minutes. The worker regression uses 30 seconds per injected failure case. Metadata/daemon checks are bounded at 30 seconds, pulls at five minutes and the fixture build at ten minutes. Diagnostics name the client/platform and distinguish timeout, crash and ordinary failure.

`assert-package-rejection.sh` rejects a successful tampered operation, an unrelated failure, a signal exit or a QEMU crash message. A crash containing a GPG keyword cannot pass merely because a broad signature regex matches. Positive Pacman transactions must also have no reported hook/transaction error. The Ubuntu protocol fixture needs `SYS_CHROOT` for native libalpm hooks; that capability is limited to the disposable Pacman client container, which receives only public test mounts.

## Other reviewed boundaries

- Source selection, clean/pushed branch checks, revision matching, the Mac lock and journaled VM cleanup remain enforced.
- Guest tools remain native and pinned. The documentation environment is checked as the ordinary publisher account; no bare `python` alias is required.
- Verification reports individual stages and clears any previous approval record before the container checks. No failure can authorize publication using that stale record.
- Signed package generation still verifies OpenPGP, native RPM and Alpine signatures. Arch indexing retains the Pacman 6/7 compatibility fix and independent checks of embedded signatures and package metadata.
- Release orchestration retains immutable version/tag checks, source/provider rechecks, draft repair and reuse of authenticated published assets. No verification gate or signature requirement was removed.
- Documentation tests preserve native repository directories, older versions and the domain configuration. Domain tests cover certificate polling/repair and errors without exposing credentials.
- The Mac transfers publication credentials only after successful revision-bound verification. Tests cover rejection before transfer and cleanup after failure. Owner keys are reused; the reviewed changes do not rotate keys or modify unrelated Pages sites.

## Evidence and limits

The detailed execution record is in [verification evidence](verification.md). Tests distinguish actual container/crypto operations from fixture GitHub, DNS, Multipass and release-service boundaries.

The cloud host is AMD64. Setting its Docker default to ARM64 exercises implicit selection failures, but does not turn it into an Apple Silicon machine. The complete AMD64 matrix and actual Ubuntu Pacman protocol fixture are tested with real signed packages; fixture tests separately establish that ARM64 selection issues only ARM64 pulls/builds/runs. Native ARM64 execution of the full matrix and actual macOS/Multipass orchestration must still run on the owner's machine. No complete owner deployment is inferred from these checks.

Live release permissions, registry/service availability, the current Go vulnerability database and Pages/certificate propagation remain checked by normal deployment. No owner release or hosted site change is performed by these local fixtures, and no clean current vulnerability-service result is inferred from them.

## Retry

From the existing clean, pushed Mac checkout:

```bash
git pull --ff-only
bash "$(git rev-parse --show-toplevel)/scripts/deploy-local.sh"
```

The command selects native clients, prepares the required fixture, checks them before compilation and removes its disposable VM. No emulator setup, manual Docker platform setting, image removal or signing-key reset is needed. If an external prerequisite fails, the output identifies the verification stage and, for container failures, the requested image/platform and time budget.
