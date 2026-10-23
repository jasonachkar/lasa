# Inspection design and trust boundaries

[Maintainer index](README.md) · [Native validation](validation.md) · [Public access contract](../customer/data-and-privacy.md)

## Pipeline and contracts

`internal/application/Linux` retains the staged process/kernel, network/namespace and filesystem collectors. When selected, a final stage runs at most eight `internal/inspection.Collector` instances against the already captured snapshot. The snapshot pointer is read-only to these collectors; each returns a batch. Results merge deterministically before graph building and rule evaluation.

New scans use `lasa.report/v2`. `Asset` provides an ID, stable ID, kind and label for native configuration/identity/endpoint/package subjects. Details remain allowlisted typed observations. `Assets`, `Inspections`, `RequestedRoots` and `ScopeFingerprint` extend the report; the legacy v1 schema remains intact. The decoder accepts legacy v1 but rejects inspection extensions mislabeled as v1. Old consumers do not become v2-compatible automatically.

Graph nodes for inspected assets have kind `asset`. `INSPECTED_ON` edges reference the asset-kind observation. Supported `asset.related_subject` observations create evidence-backed `INSPECTS` edges to already collected nodes. New rules use the registered `asset.kind` string predicate plus closed boolean predicates. Other asset kinds do not become matches merely because a similarly named predicate exists elsewhere.

The base 15 rule definitions remain available. Eighteen inspection definitions bring the catalog to 33. They use the existing rule engine, scoring, suppression, explain and terminal/JSON/HTML/SARIF pipelines. They are not a separate unaudited finding emitter. The catalog tests include positive, negative, missing, unknown, not-applicable and conflicting evidence cases for every rule.

## Native command boundary

`NativeRunner` has a closed tool allowlist and fixed system search locations. PATH, dynamic-loader, locale, pager and session-bus variables from the caller are not inherited. Executable paths resolve through administrator-controlled ancestry and are pinned through an `O_PATH` descriptor passed as fd 3. Writable/non-root-controlled tools are refused. There is no shell command interpolation or automatic elevation.

Native child commands have per-command deadlines, bounded stdout/stderr, a separate process group and cancellation that terminates the group. Raw output is never used as an error message. Recognized provider errors retain safe classification/location information, while values that could contain secrets are withheld. Native tools and their system configuration/plugins remain part of the host trust boundary; this does not make a compromised host trustworthy.

A collector panic is isolated at the application boundary. Its partial batch is discarded, a version/component/stack fingerprint diagnostic is recorded, and other collectors can complete. Panic payloads and stacks are not copied into customer reports.

## Effective configuration

Systemd inventory includes loaded and enabled/linked units. Selected manager properties establish effective user, activation, root/working-directory context, execution paths and named environment files. The parser retains paths, not argv. Supported interpreter flags are handled explicitly; option arguments must not become fake script paths. Inline programs, unknown interpreter options, ambiguous escaping, privileged prefixes under non-root unit identities and alternate root contexts remain coverage gaps.

SSH uses `sshd -G -C`, requiring OpenSSH 9.3+. `-T` is deliberately not a fallback because it performs additional validation involving host keys. Contexts are explicit and validated; localhost root is the documented default. AuthenticationMethods alternatives distinguish a password-only method from required multi-factor sequences. No account-unlock or successful-login claim is made.

Sudo uses native noninteractive long-list queries for local identities instead of attempting a second sudoers evaluator. The supported output parser handles explicit root/ALL RunAs and exclusions conservatively, preserves password-authentication context, and inspects selected command paths. Unresolved expressions and output formats stay unknown. Command digests, argument constraints, identity-provider behavior and actual command invocation remain qualifications.

## Discretionary access

`internal/access` reads local identity/group metadata and discards password/GECOS fields. POSIX ACL validation checks version, tags, object entries, named IDs, masks, duplicates and permissions. Owner, named-user, matching-group union/mask and other-class semantics are evaluated separately; a denied owner/named-user class does not fall through to a more permissive class.

Permission inspection opens only metadata descriptors. Normal symlink resolution is explicitly authorized for these named execution/configuration paths, confined to the scanner's root with `RESOLVE_IN_ROOT`; procfs magic links remain rejected. Both link-entry and canonical-target ancestry matter. Direct file/socket write candidates and directory replacement candidates consider search permission, sticky ownership, mount IDs and read-only state. Mount points are not treated as replaceable directory entries. Relevant identity/ACL/component evidence is retained.

A second metadata pass detects selected inode/ctime/mount changes. The scan is still not an atomic filesystem transaction. No write is attempted. Immutable flags, mandatory policy, remote filesystem authorization, arbitrary external membership and future activation are not proven. Missing required metadata remains unknown.

## Local firewall model

The nftables adapter reads only the scanner network namespace. The supported packet model handles selected TCP/UDP new-connection conditions, literal/prefix/range/inline-set values, ingress interfaces, chain policy and supported jumps/returns. All relevant base chains are considered; an early accept cannot override a later drop. Unsupported expressions, named sets, transformations, unrelated hook dependencies or missing context remain unknown. This is not a complete netfilter symbolic executor and does not establish upstream reachability.

## Runtime API

The containers adapter uses GET requests through an explicit UNIX socket. It negotiates a supported Docker-compatible API range, bounds response sizes/time and rejects redirects. Selected configuration groups/fields are validated before negative conclusions. It does not speak native containerd gRPC or Kubernetes APIs. Inspect responses can contain environment values transiently; typed extraction discards those fields before persistence. Rootless/user-namespace distinctions are not silently converted into host-root assertions.

Runtime facts cover running privileged containers, host PID mode, runtime socket mounts regardless of bind read-only status, sensitive writable binds and dangerous added capabilities with explicit unconfined settings. Labels remain conditional on the selected daemon's scope and authorization.

## Packages and advisories

Native inventory preserves binary/source versions, epoch, release revision and architecture. `internal/advisory` implements dpkg and RPM comparison semantics; Debian vectors are cross-checked against the native dpkg comparator in tests. Matching is against the exact release identifier. Executable ownership association requires captured device/inode agreement; deleted/replaced/ambiguous associations remain gaps.

The scan reads a local bounded `lasa.advisories/v1` cache. Fetch/expiry/max-age validation is mandatory. Vendor-undetermined records preserve uncertainty. The explicit Debian updater streams the official tracker over verified HTTPS, retains release-specific source-package fixed versions, and performs no inventory upload. The upstream JSON has no detached signature; the product does not claim one. Other supported version ecosystems use authenticated canonical import; arbitrary vendor formats are not automatically converted.

No library-loading inventory or application dependency resolver is implied by executable ownership. Package metadata is not binary-integrity or exploitability proof.

## Scheduler

The scheduler reads supported system crontabs, root spool locations and active systemd timers. It retains source/line, user and selected literal paths, not raw commands or unrelated environment values. Unsupported shell expansion/control flow, wrappers, relative scripts or execution-altering environment settings remain explicit gaps. One unsupported line does not hide subsequent independent jobs. PATH handling preserves lookup order and checks potential planting locations. Anacron and arbitrary startup-program semantics are not claimed.

## Drift, storage and resource boundaries

`lasa.diff/v2` compares actual evidence sets as well as finding attributes and adds bounded surface-change records. Scope fingerprints include profiles, roots, module set, SSH contexts, packet context, runtime endpoint and advisory path. Changed scope and missing fingerprints prevent automatic resolution. Relevant evidence-collector coverage, rather than an unrelated global failure, governs resolution. Unenumerated subjects remain unknown. Surface absence is not universal reachability proof.

New inspectors enforce work/evidence budgets and the application enforces report/evaluation cardinality limits. JSON export remains capped at 64MiB. Native/API cancellation is bounded; uninterruptible kernel filesystem calls still need external process supervision. The daemon supports managed-snapshot count/byte retention and free-space preflight, with normal atomic-write failure handling if space changes concurrently. Unrelated files are excluded from the quota. A newest snapshot larger than its quota produces an explicit failure and is retained.

See [verification](verification.md) for executed checks and the separate [VM validation guide](validation.md) for native kernel/provider gates. Test fixtures and an unexecuted workflow are not a claim of universal production compatibility.
