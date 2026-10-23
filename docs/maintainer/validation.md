# Native Linux validation from macOS

[Maintainer index](README.md) · [Inspection design](inspection-design.md) · [Verification record](verification.md)

## One command on the Mac

From the clean committed checkout:

```bash
bash scripts/validate-on-mac.sh
```

The wrapper installs Multipass through the existing Homebrew installation if needed, creates an Ubuntu 24.04 VM with 2 CPUs/4GiB RAM/16GiB disk, transfers only `git archive HEAD`, runs the privileged harness, retrieves private results under `.build/validation/`, and deletes only the VM it created. It does not transmit `.git`, local scan state, signing keys, cloud credentials or untracked files. A source SHA is passed as public provenance. Use `--keep-vm` for investigation; failures retrieving results retain the VM and identify it.

Apple Silicon validates native ARM64; an Intel Mac validates native AMD64. One machine does not establish the other architecture's kernel behavior. Run the same Linux harness on an authorized VM of the other architecture to complete both sides of the matrix. Multipass installation/service authorization can require macOS owner/admin interaction; the script cannot bypass operating-system consent.

## Direct Linux VM command

```bash
sudo bash scripts/validate-linux-vm.sh --disposable-vm
```

The harness refuses a bare-metal or container target and requires a detected VM and effective UID 0. It installs native administration/build prerequisites through apt or dnf, verifies the pinned Go archive against the official verified-HTTPS release manifest, and records architecture/kernel/toolchain results. It changes only its disposable VM and creates short-lived fixture resources.

Full inspection validation requires systemd, supported native provider versions, POSIX ACLs, BTF, tracefs and BPF/perf permissions. An unsupported provider/kernel fails its relevant gate; do not weaken host security controls merely to obtain a passing report. On distributions with older OpenSSH, configuration-only SSH mode can be an explicit compatibility limit.

## What executes

- Unit/parser/rule/integration/end-to-end tests and the race detector against the native architecture.
- A real kernel DAC comparison using an isolated UID fixture and POSIX ACL masks; scanner predictions are checked against actual fixture-only open attempts.
- A configuration-only native SSH test with Match contexts and a host-key FIFO that must not be opened.
- Real eBPF attach/event-delivery validation with explicit opt-in, including required exec/connect/bind/accept observations.
- A short-lived root service with an intentionally writable synthetic script; the effective systemd inspection must find it.
- A separate anonymous network namespace with a dummy interface, local synthetic listener and nftables policy; the supported firewall inspection must find the recorded permit. No initial-namespace firewall/interface changes are made.
- Isolated hidepid/PID and nested user-namespace views; user-namespace root must not become initial-namespace root.
- A bounded synthetic process-pressure check and a private tmpfs disk-full fixture; atomic persistence must preserve previous output and report ENOSPC.
- A sensor scan, private native reports and a machine-readable result/provenance summary.

The fixture service/directory is removed on exit. Results include sensitive VM metadata and stay private. The wrapper retrieves them before deleting its VM. Nonzero exits, skipped prerequisites and provider failures remain evidence of incomplete validation, not a pass.

## Matrix and CI

`.github/workflows/privileged.yml` is manual-only and uses dedicated disposable self-hosted Linux runners labeled `lasa-privileged` plus `X64` or `ARM64`. No PR trigger runs privileged code. Protect its environment, review source before queuing and keep signing/publishing credentials off these runners. Hosted job availability and runner registration are owner/provider boundaries; the local Mac workflow does not need GitHub Actions minutes or an Azure agent.

The harness records a result for the VM that actually ran. Repeat across supported distributions and kernel/provider versions before claiming a broader compatibility matrix. Additional namespace combinations, fleet-scale host pressure, runtime-provider versions, uncommon policy syntax and other failure injection remain target-specific validation work; this harness is not a certification of every Linux deployment.

## Interpreting failure

Read `harness.log`, structured Go test events, race output and `result.json`. Preserve the exact source revision and kernel/provider versions. The network helper refuses the initial network namespace before changing interfaces/rules. The private reports retain ordinary scanner coverage/diagnostics; success of a fixture-specific assertion does not make every unrelated host check complete.

Use the standard verification gates as well:

```bash
make fmt vet test race lint deps
make fuzz reproducible
bash test/docs.sh
```

A current official vulnerability check and any required release/package checks remain part of release approval. Local advisory snapshots or generated workflow files must not be described as successful live checks.
