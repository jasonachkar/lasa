# Local deployment review

[Maintainer index](README.md) · [Local deployment](local-deployment.md) · [Verification evidence](verification.md)

## Architecture failures and corrections

The reported `no matching manifest for linux/arm64/v8` occurred because the package-client matrix selected AMD64 at container execution but left image pulls to Docker's default architecture. Arch's pinned image does not provide ARM64. AMD64-only test clients still need AMD64 images on an Apple Silicon publisher.

The reviewed local path now uses these explicit choices:

| Operation | Intel guest | Apple Silicon guest |
| --- | --- | --- |
| Go/Python/build tools | Native AMD64 | Native ARM64 |
| Artifact builds | AMD64 and ARM64 | AMD64 and ARM64 |
| Alpine repository generation | AMD64 Alpine tool | ARM64 Alpine tool |
| DNF/Zypper/Pacman/APK client matrix | Native AMD64 | AMD64 through static QEMU |
| Worker failure-boundary fixture | Native AMD64 Ubuntu | Native ARM64 Ubuntu |

`scripts/package-containers.sh` holds the pins, validates cached image architectures, pulls with `--platform`, and smoke-tests actual package-tool execution. The publisher uses the same platform selection and explicitly selects its native platform for each Alpine run. Image/daemon/registry/emulator failures identify their boundary before expensive compilation or credential transfer.

A second issue appeared during review: classic Docker rejected replacing a cached Alpine image-index digest with another architecture (`cannot overwrite digest`). Alpine now uses different platform-manifest references for AMD64 and ARM64. Both references were resolved from the existing pinned index, preserving the reviewed image content. This requires no cache deletion and allows the native repository tool and emulated clients to coexist.

Ubuntu 24.04's QEMU package supplies `/usr/lib/binfmt.d/` rules using the `OPF` flags. ARM64 preparation reloads `systemd-binfmt.service` and verifies the enabled AMD64 handler and `F` flag, replacing the legacy `update-binfmts` invocation. Verification then actually executes the selected tools, because a registered handler alone does not prove execution works.

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

The cloud host is AMD64. Setting its Docker default to ARM64 exercises implicit selection failures, but does not turn it into an Apple Silicon machine. Additional ARM64 Alpine execution uses an explicit QEMU interpreter without installing a host-wide handler. These checks do not establish native ARM64 package-client compatibility or completion of a real macOS/Multipass deployment.

Live release permissions, registry/service availability, the current Go vulnerability database and Pages/certificate propagation remain checked by normal deployment. No owner release or hosted site change is performed by these local fixtures, and no clean current vulnerability-service result is inferred from them.

## Retry

From the existing clean, pushed Mac checkout:

```bash
git pull --ff-only
bash "$(git rev-parse --show-toplevel)/scripts/deploy-local.sh"
```

The command prepares the emulator, selects the correct images, checks them before compilation and removes its disposable VM. No manual Docker platform setting, image removal or signing-key reset is needed. If an external prerequisite fails, the output now identifies the precise verification stage and, for container failures, the requested image and platform.
