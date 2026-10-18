# Optional eBPF runtime sensor

[Maintainer index](README.md)

## Scope and current validation status

Static scans never need BPF. Sensor profile adds a bounded metadata observation window to static collection. The loader and precompiled CO-RE object are implemented and the object is compiled/inspected in automated tests. **Kernel loading, attachment and real event delivery must be validated on authorized representative VMs.** This cloud instance lacks usable kernel BTF/tracefs and capabilities; no successful sensor runtime claim is made from compilation alone.

The sensor is observational, never an enforcement or blocking mechanism. It does not collect payloads, environments, full arguments or executable filenames. It does not establish external exposure or automatically replace static evidence with runtime assumptions.

## Event sources

| Hook | Event meaning | Limits |
| --- | --- | --- |
| `sched:sched_process_exec` | A process executed | Bounded comm, PID/TID, UID helper result, parent/start metadata; no argv/filename |
| `syscalls:sys_enter_connect` | An IPv4/IPv6 connection **attempt** | Destination endpoint only; syscall can later fail |
| `syscalls:sys_enter_bind` | An IPv4/IPv6 bind **attempt** | Not proof bind/listen succeeded or traffic was reachable |
| `syscalls:sys_exit_accept4`, `sys_exit_accept` | A successful accepted-connection syscall | Returned descriptor, no payload or peer identity capture |
| `syscalls:sys_enter_unshare` + `sys_exit_unshare` | A successful unshare with selected namespace flags | Does not cover every clone/clone3/setns path or prove full namespace topology |

Unsupported hooks produce attachment diagnostics. There is no fabricated listen-success event or universal namespace-creation coverage. Connect/bind only read a bounded sockaddr family and the relevant 16/28 address bytes. They do not inspect socket payloads or unrelated user memory.

## ABI and kernel dependency

`bpf/lasa.bpf.c` defines a fixed **88-byte little-endian** ring event; C has a size assertion and Go tests assert the decoder layout. The record includes boot-relative event/start nanoseconds, initial namespace PID/TID/parent, helper UID, kind/result/flags, family/port/address and a 16-byte command name.

CO-RE reads only the task fields needed for parent and start identity. BTF and supported helpers are required. Kernel version alone is insufficient. The loader requests kernel BTF, probes tracepoint/ring-buffer support, loads the embedded collection and attempts each configured tracepoint. Verifier rejection includes the verifier output; no verification bypass or automatic host-policy change is permitted.

A supported runtime may need CAP_BPF and CAP_PERFMON in the appropriate initial user namespace, tracefs/BTF visibility, adequate memory locking on older kernels and host-policy authorization. These requirements are not satisfied by a profile name or a visible BTF file alone. Do not recommend CAP_SYS_ADMIN as a blanket workaround.

## Budgets and lifecycle

The kernel ring buffer is 1MiB. A per-CPU counter tracks ring reservation failures; the namespace flag map is bounded to 4,096 outstanding entries and insertion failures count as loss. User-space retention defaults to 4,096 events per window; extra records are drained and counted as lost rather than growing memory. The maximum supported retained-event setting for the internal collector is 65,536.

Windows default to 3 seconds and are bounded to 1ms–10 minutes by configuration. The ring reader uses short deadlines so context cancellation is checked. Links, maps and reader are owned by the collector and closed on exit; close errors are reported. Losses make coverage incomplete. A successful attachment with zero events means only that no retained event was seen during that window, not that the host was inactive or secure.

Daemon sensor mode repeats windows on the schedule. It is not a continuous streaming sensor: gaps between scans/windows are expected and documented. The syscall ABI implementation targets the supported Linux 64-bit little-endian architectures; validate on both before advertising runtime support.

## Static/runtime correlation

Keep runtime events separate in the report. Link an event to a static subject only when boot identity, initial PID namespace, numeric PID and start ticks agree. Start nanoseconds convert to Linux userspace ticks on the supported ABIs. Container-relative PID ambiguity or a zero/missing start value must leave the event unlinked. Event timestamps do not establish an upstream attack path, and a connection attempt never becomes confirmed external exposure.

## Regeneration

The checked-in object permits self-contained CGO-free normal builds. Maintainers regenerate using pinned Clang 19 and libbpf headers:

```sh
make bpf
```

The directive calls `scripts/generate-bpf.sh`, which uses the cilium/ebpf version pinned in `go.mod`, fixed flags and source-path remapping. `BPF_CFLAGS` can supply a trusted include directory. `bpf/Dockerfile` pins a Debian 13.6 AMD64 manifest and explicit compiler/header package versions. Mount a checksum-verified Go 1.27.2 toolchain read-only at `/opt/go` and the checkout at `/src`; see the BPF CI job for the complete container invocation.

Review source and generated diffs together. Do not replace the object with one downloaded from an unverified URL. Do not alter artifact checksums to silence a mismatch. Binary/object compilation is a supply-chain check; event delivery remains a separate test.

## Privileged VM validation

Use disposable, dedicated Linux VMs with BTF, tracefs and explicitly authorized capabilities. Do not run untrusted pull-request code on these machines. The manually invoked `privileged.yml` workflow uses a dedicated runner label and environment gate.

```sh
LASA_PRIVILEGED_TESTS=1 go test -count=1 -v ./test/integration -run Privileged
```

Without explicit opt-in the test skips. With opt-in it fails if configured sources cannot attach or if real exec/connect/bind/accept events are not delivered. It creates local loopback workload only. Add matrix evidence for representative kernels, AMD64/ARM64, event loss/backpressure, partial hooks, process exits and successful namespace events before promoting runtime claims. The current required event test does not prove every unshare/clone variant.
