#!/usr/bin/env bash
# Acceptance test for an installed LASA binary on a real Linux host.
#
# Runs as an ordinary user against the lasa on PATH and exercises scanning,
# rendering, remediation tracking, output safety, input validation, report
# size limits, the daemon, custom rules, command errors and packaging.
#
#   bash test/installed-smoke.sh                 # test the installed lasa
#   EXPECTED_VERSION=0.2.1 bash test/installed-smoke.sh
#   KEEP=1 bash test/installed-smoke.sh          # keep the work directory
#
# Checks that need something the host may not provide (a free port 6379,
# systemd-run --user, package-installed files) are reported as SKIP.
# Exit status: 0 when nothing failed, 1 otherwise.
set -u
umask 077

for tool in lasa python3 script timeout; do
  command -v "$tool" >/dev/null || { echo "Missing required tool: $tool" >&2; exit 2; }
done
work=$(mktemp -d)
if [[ ${KEEP:-} == 1 ]]; then echo "Work directory: $work"; else trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT; fi
cd "$work" || exit 2

pass=0 fail=0 skip=0
ok()      { pass=$((pass + 1)); printf 'PASS  %s\n' "$1"; }
bad()     { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; }
skipped() { skip=$((skip + 1)); printf 'SKIP  %s (%s)\n' "$1" "$2"; }
# check NAME COMMAND...: the command's exit status decides the result.
check() {
  local name=$1
  shift
  if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}
py() { python3 -I -c "$@"; }
plain() { sed 's/\x1b\[[0-9;]*m//g;s/\r//'; }
# render REPORT COLUMNS: terminal output as a user sees it, colors removed.
render() { script -qc "stty cols $2; lasa report --input $1" /dev/null | plain; }
findings() { py 'import json,sys;print(" ".join(sorted(f["rule_id"] for f in json.load(open(sys.argv[1]))["findings"])))' "$1"; }

echo "== Version"
if [[ -n ${EXPECTED_VERSION:-} ]]; then
  check "installed version is $EXPECTED_VERSION" test "$(lasa version)" = "$EXPECTED_VERSION"
else
  echo "      lasa $(lasa version)"
fi

echo "== Baseline scan and formats"
lasa scan --format json --output std.json >/dev/null 2>&1
check "default scan writes a JSON report" test -s std.json
check "report is private (0600)" test "$(stat -c %a std.json)" = 600
check "no null collections in JSON" bash -c '! grep -q ": null" std.json'
check "established absences do not make coverage partial" py '
import json, sys
d = json.load(open("std.json"))
gap = {"SYMLINK_NOT_FOLLOWED", "NOT_PRESENT", "NOT_SUPPORTED_BY_KERNEL"}
expected = sum(1 for x in d["diagnostics"] if x["code"] in gap)
unsupported = sum(c["unsupported"] for c in d["coverage"])
sys.exit(0 if unsupported == expected else 1)'
lasa report --input std.json --format html --output std.html
check "HTML has a strict CSP and no scripts" bash -c "grep -q \"default-src 'none'\" std.html && ! grep -q '<script' std.html"
render std.json 100 > std.txt
check "terminal shows findings and design exclusions separately" bash -c "grep -q '^FINDINGS' std.txt && grep -q '^NOT INSPECTED BY DESIGN' std.txt"
check "terminal has no generic impact text" bash -c '! grep -q "impact:" std.txt'

echo "== Planted misconfigurations"
fx=$work/fx
mkdir -p "$fx/etc/sudoers.d" "$fx/etc/systemd/system" "$fx/home/alice/.ssh" "$fx/decoy/sudoers.d"
for f in etc/sudoers.d/evil etc/systemd/system/evil.service home/alice/.ssh/authorized_keys decoy/sudoers.d/evil; do
  touch "$fx/$f"
  chmod 666 "$fx/$f"
done
roots="$fx/etc/sudoers.d,$fx/etc/systemd/system,$fx/home/alice/.ssh,$fx/decoy/sudoers.d"
listener=""
if python3 -I -c 'import socket;s=socket.socket();s.bind(("0.0.0.0",6379))' 2>/dev/null; then
  python3 -I -c 'import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",6379));s.listen();time.sleep(30)' &
  listener=$!
  sleep 1
fi
lasa scan --roots "$roots" --format json --output fx.json >/dev/null 2>&1
[[ -n $listener ]] && kill "$listener" 2>/dev/null
echo "      findings: $(findings fx.json)"
check "detects writable sudoers, unit and authorized_keys" bash -c "[[ '$(findings fx.json)' == *LASA-008*LASA-009*LASA-013* ]]"
if [[ -n $listener ]]; then
  check "detects a management port open on all addresses" bash -c "[[ '$(findings fx.json)' == *LASA-003* ]]"
else
  skipped "detects a management port open on all addresses" "port 6379 in use"
fi
check "a sudoers.d outside /etc is not sudoers configuration" py '
import json, sys
d = json.load(open("fx.json"))
labels = {n["id"]: n["label"] for n in d["graph"]["nodes"]}
sys.exit(1 if any("/decoy/" in labels.get(f["subject"], "") for f in d["findings"]) else 0)'
render fx.json 110 > fx.txt
check "findings show mode and owner" grep -q 'mode 0666 (rw-rw-rw-), owner uid' fx.txt
check "findings use rule-specific risk text" bash -c "grep -q 'add its own SSH key' fx.txt && ! grep -q 'If an attacker first gains control' fx.txt"
check "permission findings offer a copyable command" grep -q "\$ sudo chmod go-w -- '" fx.txt
check "file findings show exposure n/a" grep -q 'exposure n/a' fx.txt
lasa report --input fx.json --format sarif --output fx.sarif
check "SARIF names the file with a file:// location" bash -c "grep -q 'file://' fx.sarif && grep -q 'etc/sudoers.d/evil' fx.sarif"
id=$(py 'import json;print([f["id"] for f in json.load(open("fx.json"))["findings"] if f["rule_id"]=="LASA-013"][0])')
check "explain accepts a 6-character prefix" bash -c "lasa explain ${id:0:6} --report fx.json | grep -q 'RECORDED EVIDENCE'"
check "explain accepts a rule ID from standard input" bash -c "lasa explain LASA-013 --report - --format json < fx.json | grep -q lasa.explanation"
check "explain omits unrelated diagnostics" bash -c "! lasa explain ${id:0:8} --report fx.json | grep -q 'COLLECTION GAPS'"
lasa scan --roots "$roots" --fail-on high --format json --output f1.json >/dev/null 2>&1
check "--fail-on high exits 1" test $? -eq 1
py 'import json;print(json.dumps({"schema":"lasa.suppressions/v1","entries":[{"fingerprint":f["id"],"justification":"smoke test fixture","expires":"2099-01-01T00:00:00Z"} for f in json.load(open("fx.json"))["findings"] if f["severity"]=="high"]}))' > suppressions.json
lasa scan --roots "$roots" --suppressions suppressions.json --fail-on high --format json --output f2.json >/dev/null 2>&1
check "suppressed findings do not trigger --fail-on" test $? -eq 0

echo "== Remediation tracking"
lasa scan --roots "$roots" --format json --output before.json >/dev/null 2>&1
chmod 644 "$fx/home/alice/.ssh/authorized_keys" "$fx/etc/systemd/system/evil.service"
lasa scan --roots "$roots" --format json --output after.json >/dev/null 2>&1
lasa diff before.json after.json > diff.json
check "fixed files diff as resolved" py 'import json,sys;d=json.load(open("diff.json"));sys.exit(0 if len(d["resolved"])==2 and not d["unknown"] else 1)'
check "diff categories are never null" bash -c '! grep -q null diff.json'
check "diff --format terminal lists resolutions" bash -c 'lasa diff before.json after.json --format terminal | grep -q "^RESOLVED"'
lasa diff after.json before.json --fail-on-new high >/dev/null
check "diff --fail-on-new exits 1 on a regression" test $? -eq 1
lasa scan --roots "$fx/etc/sudoers.d" --format json --output narrow.json >/dev/null 2>&1
check "a narrower scope keeps findings unknown, with reasons" bash -c 'lasa diff before.json narrow.json | python3 -I -c "import json,sys;d=json.load(sys.stdin);sys.exit(0 if d[\"unknown\"] and all(d[\"unknown_reasons\"].values()) else 1)"'

echo "== Output safety"
ln -s "$work/target" link.json
lasa scan --roots "$fx/etc/sudoers.d" --format json --output link.json >/dev/null 2>&1
check "refuses a symlink output" bash -c "[[ $? -eq 2 && ! -e '$work/target' ]]"
mkdir adir
lasa scan --roots "$fx/etc/sudoers.d" --format json --output adir >/dev/null 2>&1
check "refuses a directory output" test $? -eq 2
echo x > exist.json && chmod 644 exist.json
lasa scan --roots "$fx/etc/sudoers.d" --format json --output exist.json >/dev/null 2>&1
check "a replaced report becomes 0600" test "$(stat -c %a exist.json)" = 600
check "relative --roots resolve against the working directory" bash -c "cd '$fx' && lasa scan --roots etc/sudoers.d --format json --output '$work/rel.json' >/dev/null 2>&1; grep -q 'etc/sudoers.d/evil' '$work/rel.json'"

echo "== Hostile file names"
hostile=$work/h/etc/sudoers.d
mkdir -p "$hostile"
touch "$hostile/$(printf 'a\033[31mRED\033]0;pwned\007')" "$hostile/<img src=x onerror=alert(1)>" "$hostile/$(printf 'nl\nFAKE: line')"
chmod 666 "$hostile"/*
lasa scan --roots "$hostile" --format json --output h.json >/dev/null 2>&1
check "terminal output escapes control characters" bash -c "! lasa report --input h.json | grep -q \$'\\033'"
lasa report --input h.json --format html --output h.html
check "HTML escapes markup" bash -c "! grep -q '<img src=x' h.html"
check "no suggested command for names that need escaping" bash -c "! lasa report --input h.json | grep -q 'chmod go-w -- .*RED'"

echo "== Report input validation"
echo '{bad' > malformed.json
lasa report --input malformed.json >/dev/null 2>&1
check "malformed JSON is rejected" test $? -eq 2
py 'import json;d=json.load(open("fx.json"));d["findings"][0]["evidence"]=["deadbeef"];json.dump(d,open("dangling.json","w"))'
lasa report --input dangling.json >/dev/null 2>&1
check "dangling evidence is rejected" test $? -eq 2
head -c 70000000 /dev/zero | tr '\0' ' ' > big.json
lasa report --input big.json >/dev/null 2>&1
check "input over 64 MiB is rejected" test $? -eq 2
rm -f big.json

echo "== Oversized scan"
broad=$(find /usr/share /usr/lib -mindepth 1 -maxdepth 1 -type d ! -type l 2>/dev/null | head -120 | paste -sd,)
/usr/bin/time -o broad.time -f '%M' lasa scan --roots "$broad" --max-files 100000 --timeout 3m --format json --output broad.json >/dev/null 2>&1
rc=$?
echo "      exit $rc, $(stat -c %s broad.json 2>/dev/null || echo 0) bytes, peak $(cat broad.time 2>/dev/null) KB"
check "a broad scan writes a report" bash -c "[[ $rc -eq 0 && -s broad.json ]]"
check "the reduced report reads back" bash -c 'lasa report --input broad.json >/dev/null'
if grep -q fit_export broad.json 2>/dev/null; then
  check "the scope reduction is recorded" grep -q 'file metadata entries were omitted' broad.json
  check "peak memory stays below 512 MB" bash -c "[[ \$(cat broad.time) -lt 524288 ]]"
  if command -v systemd-run >/dev/null && systemd-run --user --scope -q true 2>/dev/null; then
    systemd-run --user --scope -q -p MemoryMax=512M -p MemorySwapMax=0 lasa scan --roots "$broad" --max-files 100000 --timeout 3m --format json --output limited.json >/dev/null 2>&1
    check "the broad scan completes under MemoryMax=512M" test $? -eq 0
  else
    skipped "the broad scan completes under MemoryMax=512M" "systemd-run --user unavailable"
  fi
else
  skipped "scope reduction and memory checks" "this host's /usr trees fit in one report"
fi

echo "== Daemon"
state=$work/state
timeout -s TERM 5 lasa daemon --state-dir "$state" --interval 1s --retention 2 --roots "$fx/etc/sudoers.d" 2> daemon1.log
check "the daemon stops cleanly on SIGTERM" test $? -eq 124
check "retention keeps 2 snapshots and logs removals" bash -c "[[ \$(ls '$state' | grep -c '^scan-') -eq 2 ]] && grep -q 'retention removed' daemon1.log"
chmod 644 "$fx/etc/sudoers.d/evil"
timeout -s TERM 3 lasa daemon --state-dir "$state" --interval 1s --retention 2 --roots "$fx/etc/sudoers.d" 2> daemon2.log
check "a restart restores the baseline and logs the resolution" bash -c "grep -q '^baseline scan-' daemon2.log && grep -q 'finding resolved severity=high rule=LASA-009' daemon2.log"
timeout 3 lasa daemon --state-dir "$state" --interval 1s --roots "$fx/etc/sudoers.d" 2>/dev/null &
first=$!
sleep 1
timeout 3 lasa daemon --state-dir "$state" --interval 1s --roots "$fx/etc/sudoers.d" 2> daemon3.log
rc=$?
wait "$first"
check "a second daemon is refused by the lock" bash -c "[[ $rc -eq 2 ]] && grep -q 'another daemon' daemon3.log"

echo "== Custom rules"
printf 'rules: []\n' > noschema.yaml
check "a missing schema says what to write" bash -c 'lasa rules validate noschema.yaml 2>&1 | grep -q "schema: lasa.rules/v1"'
cat > custom.yaml <<'EOF'
schema: lasa.rules/v1
rules:
  - id: LOCAL-001
    version: "1"
    category: exposure
    subject: process
    title: Any potentially exposed listener
    description: Smoke test rule.
    severity: low
    confidence: medium
    unknown: skip
    required_evidence: [network.potential]
    prerequisites: [Network access.]
    remediation: Review.
    when: {all: [{predicate: network.potential, op: eq, value: true}]}
EOF
check "rules validate accepts a valid pack" bash -c 'lasa rules validate custom.yaml | grep -q "valid, 1 custom rules"'
check "rules predicates documents every predicate" bash -c 'lasa rules predicates --format json | python3 -I -c "import json,sys;p=json.load(sys.stdin);sys.exit(0 if p and all(x[\"description\"] for x in p) else 1)"'
sed 's/LOCAL-001/LASA-001/' custom.yaml > override.yaml
check "builtin rule IDs cannot be overridden" bash -c '! lasa rules validate override.yaml'

echo "== Command errors and doctor"
check "flag errors name the flag and its range" bash -c "lasa scan --max-files 0 2>&1 | grep -q -- '--max-files must be between 1 and 100000, got 0'"
check "errors carry a hint and no generic impact" bash -c "lasa scan --fail-on bogus 2>&1 | grep -q '^  hint:' && ! lasa scan --fail-on bogus 2>&1 | grep -q 'impact:'"
check "the deep profile refusal is explained" bash -c "lasa scan --profile deep 2>&1 | grep -q 'only when a host-wide scan is authorized'"
check "--color is validated" bash -c "lasa scan --color purple 2>&1 | grep -q 'auto, always or never'"
lasa doctor > doctor.txt 2>&1
check "doctor checks openat2 and the environment" bash -c "grep -q '^openat2 ' doctor.txt && grep -q '^environment ' doctor.txt"
check "doctor has no generic evidence impact text" bash -c "! grep -q 'dependent rules cannot confirm' doctor.txt"

echo "== Package contents"
if [[ $(command -v lasa) == /usr/bin/lasa && -d /usr/share/doc/lasa ]]; then
  check "the manual page is installed and current" bash -c "zcat /usr/share/man/man1/lasa.1.gz | grep -q 'fail\\\\-on\\\\-new'"
  check "bash completion is installed" test -s /usr/share/bash-completion/completions/lasa
  check "packaged documentation has no broken relative links" bash -c "! grep -rq '](\\.\\./' /usr/share/doc/lasa"
  check "the custom rules guide is packaged" test -s /usr/share/doc/lasa/custom-rules.md
else
  skipped "package contents" "lasa is not installed from the DEB package"
fi

echo
echo "RESULT: $pass passed, $fail failed, $skip skipped"
[[ $fail -eq 0 ]]
