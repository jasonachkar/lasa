# CLI reference

[Documentation home](../../README.md)

## Conventions and global options

Run `lasa --help` or `lasa COMMAND --help` for help generated from the implementation. `--diagnostics-format text|json` controls fatal command diagnostics on stderr. When an output format is selected, stdout contains that output only. If `--output` is provided, the report is written privately to that path instead of stdout.

Shell completion is built in:

```sh
lasa completion bash > lasa-completion.bash
lasa version
```

## `lasa scan`

```sh
lasa scan --profile standard --timeout 30s
lasa scan --format json --output host.report.json --strict
lasa scan --format sarif --output host.sarif --fail-on high
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--profile` | `standard` | `standard`, `deep`, `container`, `sensor` |
| `--timeout` | `30s` | Cooperative collection deadline, 1ms through 24h |
| `--workers` | `4` | Process collection workers, 1–32 |
| `--max-processes` | `4096` | Visible PID inspection budget, maximum 65,536 |
| `--max-fds` | `512` | Descriptors inspected per PID, maximum 65,536 |
| `--max-files` | `4096` | File metadata budget, maximum 100,000 |
| `--roots` | See privacy guide | Comma-separated explicit metadata roots, replaces defaults |
| `--sensor-duration` | `3s` | Optional event window, 1ms–10m, only used by sensor profile |
| `--format` | `terminal` | `terminal`, `json`, `html`, `sarif` |
| `--output` | stdout | Atomic private destination; existing regular files are replaced |
| `--rules` | none | Explicit additional local YAML rule pack; builtin IDs cannot be overridden |
| `--suppressions` | none | Explicit versioned local JSON suppression file |
| `--strict` | false | Incomplete collection yields exit 3 after report output |
| `--fail-on` | disabled | Unsuppressed severity threshold: informational, low, medium, high, critical |

Timeouts are cooperative, checked between bounded operations. A blocked kernel or remote-filesystem syscall may not return immediately at the deadline. Root `/`, traversal paths, unnormalized roots and more than 128 roots are rejected. Other fixed internal budgets bound namespaces, tables, graph edges, rule size and report input; hitting them produces a diagnostic.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Command completed; a scan can be partial unless `--strict` was requested |
| `1` | At least one unsuppressed finding met `--fail-on` |
| `2` | Fatal command, configuration, platform, input or output error |
| `3` | Strict-mode scan had incomplete collection; the report was still written |
| `130` | Interrupted scan/command where interruption is reported |

Fatal errors take precedence. When both strict incompleteness and a severity threshold apply, exit 3 takes precedence. Suppressed findings remain in the report but do not trigger `--fail-on`. A daemon normally exits 0 on graceful SIGTERM.

Shell example that preserves the scanner's status:

```sh
status=0
lasa scan --strict --fail-on high --format json --output host.report.json || status=$?
case "$status" in
  0) echo 'scan completed within selected acceptance policy' ;;
  1) echo 'review severity threshold findings' ;;
  3) echo 'review incomplete coverage before interpreting findings' ;;
  *) echo "command failed with status $status" >&2; exit "$status" ;;
esac
```

## `lasa doctor`

```sh
lasa doctor
lasa doctor --format json
```

Checks Linux compatibility, the scanner's own procfs/security/socket/mount access and optional BTF/tracepoint visibility. Optional failures do not prevent the static prerequisite result from succeeding. Doctor does not prove that all other processes are accessible or that a BPF program can load; the selected sensor performs actual feature probing and attachment.

## `lasa explain <finding-id> --report <path>`

```sh
lasa explain FULL_FINGERPRINT --report host.report.json
lasa explain FULL_FINGERPRINT --report host.report.json --format json
```

Uses the full finding fingerprint, not the rule ID. Shows the stored finding, its evidence and the matching recorded evaluation. It does not rescan or test exploitability. A missing fingerprint produces `FINDING_NOT_FOUND`. JSON output uses `lasa.explanation/v1`.

## `lasa diff <previous-report> <current-report>`

Produces JSON with `new`, `continuing`, `changed`, `resolved` and `unknown` categories. Different host identities are rejected. Unavailable assets, changed profile, incomplete collection or a missing explicit negative evaluation keep old findings in `unknown`. LASA deliberately favors uncertainty over a false resolution claim.

## `lasa report --input <path> --format <format>`

```sh
lasa report --input host.report.json --format html --output host.report.html
lasa report --input host.report.json --format sarif --output host.sarif
```

Renders without contacting or inspecting the scanned host. Inputs are capped at 64MiB, must be regular files, must use the supported report schema and must preserve valid evidence references. Unknown JSON fields are rejected for this schema version.

## `lasa rules list`

`--format terminal|json` lists builtin rule versions, categories, conditions and remediation. `--rules PATH` appends an explicit local pack for inspection. No rule pack is downloaded automatically and no shell/expression code is executed from rules. See the maintainer authoring guide if you operate custom packs.

## `lasa daemon`

The scan flags for profile, timeout and resource scope apply. Additional flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--state-dir` | `~/.local/state/lasa`, or `./lasa-state` if home lookup fails | Private state directory and exclusive daemon lock |
| `--interval` | `15m` | Delay after a completed snapshot, minimum 1s |
| `--retention` | `96` | Retained LASA snapshot count, 1–10,000 |
| `--rules` | none | Local additional rule pack, loaded at startup |
| `--suppressions` | none | Suppression policy, loaded at startup |

```sh
lasa daemon --state-dir ./private-state --interval 15m --retention 96
```

The daemon runs scans sequentially, persists one JSON report at a time and logs snapshot status to stderr. It does not overlap scans or make remote API calls. Stop with SIGINT or SIGTERM; allow the in-progress scan and bounded filesystem operations time to finish. Persistence, retention or fatal scan failures terminate the daemon with a diagnostic so a supervisor can alert and restart it.
