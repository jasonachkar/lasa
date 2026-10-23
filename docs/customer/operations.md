# Operations and deployment

[Documentation home](../../README.md)

## One-shot operation

Prefer a scoped ordinary-user scan for initial evaluation. Record the scanner version, profile, roots, time and visibility limitations with the report. Treat finding thresholds as operational policy rather than a substitute for review.

Do not grant broad capabilities to suppress diagnostics. Check the failing operation and namespace first. A rootless container, restricted procfs mount or host ptrace policy can legitimately prevent observation. A deep profile is an explicit decision to inspect more metadata; it is not an automatic escalation feature.

## Daemon lifecycle

```sh
lasa daemon --state-dir /path/to/private/lasa --interval 15m --retention 96
```

LASA creates missing state directories without following symlinks and requires the final directory to be private. An advisory exclusive lock prevents two LASA daemons from using the same state directory. Each scheduled scan finishes before the interval timer for the next scan starts. This avoids overlapping work even when scanning takes longer than expected.

Snapshots are written as `scan-TIMESTAMP-SCANID.json`, with mode `0600`, sync and atomic replacement. A crash can leave a hidden `.lasa-*.tmp` file; it is not a valid completed snapshot and is ignored by report retention. A write or retention failure is fatal to the daemon, making storage failures visible to its supervisor.

Send SIGTERM or SIGINT for graceful shutdown. An in-progress scan receives cancellation and can persist a partial result before exit. Kernel filesystem operations cannot always be interrupted promptly; configure your supervisor's stop timeout accordingly. There is no concurrent web server or remote management listener.

## Retention and capacity

Retention limits snapshot **count**. At 96 reports and a 15-minute delay, the nominal window is about a day plus scan time, but timing, restarts and errors change it. Large reports can consume substantial storage. Set disk monitoring and an external byte/time retention policy if required; Use `--retention-bytes` to add a managed-snapshot byte quota and `--min-free-bytes` to reserve space before the next report. Neither is a quota on unrelated files or a guarantee against concurrent disk exhaustion.

Only correctly named, scanner-owned regular snapshots are removed by built-in retention. Unrelated files, symlinks, locks and leftover temporary files are retained. Do not use the state directory as a general-purpose document directory. Backups and copied reports need their own access and deletion policies.

## systemd

Two example units are supplied:

- [`lasa.service`](../../deploy/systemd/lasa.service): static ordinary service account, constrained kernel/device access, empty capability set and local state directory. Visibility is intentionally limited.
- [`lasa-deep.service`](../../deploy/systemd/lasa-deep.service): explicit root metadata inspection, with only read/search and ptrace capabilities listed for the relevant collection operations. It does not enable eBPF.

Example installation for the ordinary-user unit, after reviewing the file:

```sh
getent passwd lasa >/dev/null || sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin lasa
sudo install -m 0755 bin/lasa /usr/local/bin/lasa
sudo install -m 0644 deploy/systemd/lasa.service /etc/systemd/system/lasa.service
sudo systemctl daemon-reload
sudo systemctl enable --now lasa.service
sudo journalctl -u lasa.service
```

Inspect the first persisted report and its coverage. The units avoid `ProtectProc=invisible`, `ProcSubset=pid` and private user namespaces, which would conceal evidence. The units intentionally leave `ProtectSystem` and `ProtectHome` disabled because read-only bind mounts would change writeability metadata and suppress relevant file permission candidates. Analysis remains read-only in the scanner code. The static service account also avoids DynamicUser state-directory symlinks, which the storage boundary rejects. Kernel/device protections can still alter their specific views. Choose host visibility and service hardening together and validate coverage on your target distribution.

The examples are deployment starting points, not verified unit compatibility on every systemd/kernel version. Neither unit is a complete sensor deployment. Sensor operation needs explicit BTF/tracefs visibility, BPF/perf permissions, memory limits and a kernel validation run described in the maintainer sensor guide.

## Container deployment

Build the architecture-matching binary, then the optional minimal image:

```sh
make build
docker build -f deploy/container/Dockerfile -t lasa:local .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges lasa:local
```

ARM64 hosts need the ARM64 binary. The scratch image has no shell or package manager and runs as UID 65532. Its default command declares a container view. Procfs and root filesystem content in that view differ substantially from the host; a useful container report can be partial.

Do not add `--privileged`, mount the entire host root or expose runtime sockets just to remove warnings. Host scanning from a container requires a separately reviewed deployment and tests for PID, user, mount and network namespaces. No privileged host-container recipe is presented as universally correct.

## Sensor windows

`lasa scan --profile sensor --sensor-duration 5s` requests static scanning plus a finite metadata event window. `lasa daemon --profile sensor` repeats those windows on its scan schedule. This is not continuous observation: gaps exist between windows. Ring-buffer, event-retention and namespace-correlation limits appear in coverage and diagnostics. A failed attachment is not represented as successful runtime coverage.

## Operational acceptance

Before a fleet rollout, verify useful unprivileged observations, expected privileged visibility if required, report file access, coverage policy, retention, graceful shutdown, alert delivery and the behavior of incomplete comparisons. Add representative Linux VM tests for your distributions, kernels, container runtimes and service manager. Preserve diagnostics in central ingestion so a missing permission cannot appear as a healthy host.

## Scheduling inspections

```bash
sudo lasa daemon --profile deep --inspect systemd,ssh,sudo,permissions,scheduler   --state-dir /var/lib/lasa --interval 15m --timeout 2m   --retention 96 --retention-bytes 1073741824 --min-free-bytes 67108864
```

Review the [expanded collection contract](security-inspections.md) and the required native providers before deployment. The example metadata-only systemd units do not automatically grant all optional inspection permissions or install native tools. Package checks additionally require a current local advisory database; schedule its refresh separately and monitor failures.

A collector fault is isolated and recorded as incomplete coverage. Fatal persistence/retention failures stop the daemon with a specific error so its process supervisor can alert/restart it. Reports are not silently discarded to make a scan appear successful. Validate shutdown, disk pressure, retained-byte limits and restart behavior under your own workload.
