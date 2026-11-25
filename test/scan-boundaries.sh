#!/usr/bin/env bash
# Trace an installed scanner while it visits a regular file in its declared
# scope. The fixture contains synthetic data and the scan needs no privileges.
set -euo pipefail
umask 077
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/etc/sudoers.d"
fixture="$work/etc/sudoers.d/metadata-only"
printf 'Synthetic fixture contents\n' > "$fixture"
chmod 0666 "$fixture"
lasa=$(command -v lasa)

strace -f -yy -s 256 -o "$work/syscalls" \
  -e 'trace=%network,execve,execveat,io_uring_setup,io_uring_enter,io_uring_register,read,readv,pread64,preadv,preadv2,mmap,splice,sendfile,copy_file_range' \
  "$lasa" scan --roots "$work/etc/sudoers.d" --format json --output "$work/report.json"

python3 -I - "$work" "$fixture" <<'PY'
import json
import pathlib
import re
import sys

work, fixture = map(pathlib.Path, sys.argv[1:])
report = json.loads((work / 'report.json').read_text())
subjects = {node['id']: node['label'] for node in report['graph']['nodes']}
if not any(finding['rule_id'] == 'LASA-009' and subjects.get(finding['subject']) == str(fixture)
           for finding in report['findings']):
    sys.exit('The scanner did not inspect the fixture metadata')

forbidden = {
    'socket', 'socketpair', 'bind', 'listen', 'accept', 'accept4', 'connect', 'shutdown',
    'getsockname', 'getpeername', 'getsockopt', 'setsockopt', 'recv', 'recvfrom', 'recvmsg',
    'recvmmsg', 'send', 'sendto', 'sendmsg', 'sendmmsg', 'socketcall',
    'io_uring_setup', 'io_uring_enter', 'io_uring_register',
}
executions = 0
for line in (work / 'syscalls').read_text(errors='replace').splitlines():
    match = re.match(r'^\s*\d+\s+(\w+)\(', line)
    if not match:
        continue
    call = match[1]
    if call in forbidden:
        # Go's interface inventory uses read-only routing queries to the local
        # Linux kernel. Internet, Unix-domain and other sockets are forbidden.
        args = line[match.end():]
        netlink_fd = re.match(r'\d+<NETLINK:\[', args)
        kernel = 'sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000' in args
        allowed = (
            call == 'socket' and args.startswith('AF_NETLINK, SOCK_RAW') and ', NETLINK_ROUTE)' in args
            or netlink_fd and call in {'recvfrom', 'getsockname'}
            or netlink_fd and call == 'bind' and kernel
            or netlink_fd and call == 'sendto' and kernel
            and ('nlmsg_type=RTM_GETLINK,' in args or 'nlmsg_type=RTM_GETADDR,' in args)
        )
        if not allowed:
            sys.exit(f'Unexpected syscall: {line[:320]}')
    if call in {'execve', 'execveat'}:
        executions += 1
    elif f'<{fixture}>' in line:
        sys.exit(f'Unexpected access to fixture contents: {line}')
if executions != 1:
    sys.exit(f'Expected only the initial LASA exec, saw {executions}')
print('PASS: scan only queried kernel network metadata and made no external connections, subprocess calls or fixture reads')
PY
