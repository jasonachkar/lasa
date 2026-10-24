"""Timeout cleanup and refusal to mistake crashes for signature rejection."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RejectionTests(unittest.TestCase):
    def invoke(self, command):
        return subprocess.run(['sh', str(ROOT / 'test/assert-package-rejection.sh'), 'gpg|signature',
                               'sh', '-c', command], capture_output=True, text=True, timeout=5)

    def test_crypto_rejection_passes_but_success_or_unrelated_error_does_not(self):
        self.assertEqual(self.invoke('echo "gpg: BAD signature"; exit 1').returncode, 0)
        self.assertNotEqual(self.invoke('echo "signature verified"; exit 0').returncode, 0)
        result = self.invoke('echo "missing file"; exit 1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('without the expected', result.stderr)

    def test_signal_or_qemu_crash_is_never_a_valid_security_rejection(self):
        for command in ('echo "gpg signature helper"; exit 139',
                        'echo "gpg: QEMU internal SIGSEGV {code=MAPERR, addr=0x20}"; exit 1'):
            with self.subTest(command=command):
                result = self.invoke(command)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('not evidence of signature enforcement', result.stderr)


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        binary = self.root / 'docker'
        binary.write_text('''#!/bin/sh
set -eu
if [ "$1" = rm ]; then echo "$*" >> "$FIXTURE_CLEANUP"; exit 0; fi
if [ "$1" = create ]; then printf '%064d\\n' 1; exit 0; fi
test "$1" = start
case "$FIXTURE_MODE" in
  crash) exit 139;;
  hang) exec sleep 30;;
  success) exit 0;;
esac
''')
        binary.chmod(0o755)

    def invoke(self, mode):
        environment = {**os.environ, 'PATH': str(self.root) + ':' + os.environ['PATH'],
                       'FIXTURE_MODE': mode, 'FIXTURE_CLEANUP': str(self.root / 'cleanup')}
        return subprocess.run(['bash', str(ROOT / 'scripts/run-package-container.sh'), '1',
                               'Fedora signature rejection fixture', '--platform', 'linux/amd64', 'fixture-image'],
                              env=environment, capture_output=True, text=True, timeout=5)

    def test_hang_has_a_deadline_and_removes_only_the_recorded_container(self):
        start = time.monotonic()
        result = self.invoke('hang')
        self.assertEqual(result.returncode, 124)
        self.assertLess(time.monotonic() - start, 5)
        self.assertIn('timed out: Fedora signature rejection fixture', result.stderr)
        self.assertEqual((self.root / 'cleanup').read_text(), 'rm --force ' + '0' * 63 + '1\n')

    def test_crash_and_success_are_distinguished_and_both_cleanup(self):
        result = self.invoke('crash')
        self.assertEqual(result.returncode, 139)
        self.assertIn('crashed:', result.stderr)
        self.assertIn('not a successful security rejection', result.stderr)
        self.assertEqual(self.invoke('success').returncode, 0)
        self.assertEqual(len((self.root / 'cleanup').read_text().splitlines()), 2)


if __name__ == '__main__':
    unittest.main()
