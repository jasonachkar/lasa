"""Repo-add compatibility and generated signature metadata contract."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/build-arch-database.sh'

# This protocol fixture models option differences; native tools are also exercised
# by test/distribution.sh. Signature bytes here test metadata, not cryptography.
REPO_ADD = r'''#!/usr/bin/env python3
import base64, hashlib, io, os, pathlib, sys, tarfile
major = os.environ['TEST_REPO_MAJOR']
if sys.argv[1:] == ['--version']:
    print('repo-add (pacman) ' + major + '.0.2')
    raise SystemExit(0)
assert '--prevent-downgrade' in sys.argv
assert ('--include-sigs' in sys.argv) == (major == '7')
package = pathlib.Path(sys.argv[-1])
mode = os.environ.get('TEST_REPO_MODE', '')
signature = base64.b64encode(pathlib.Path(str(package) + '.sig').read_bytes()).decode()
fields = {'NAME': 'lasa', 'VERSION': '1.2.3-1', 'FILENAME': package.name,
          'SHA256SUM': hashlib.sha256(package.read_bytes()).hexdigest(), 'PGPSIG': signature}
if mode == 'missing': del fields['PGPSIG']
if mode == 'wrong-signature': fields['PGPSIG'] = base64.b64encode(b'wrong').decode()
if mode == 'bad-base64': fields['PGPSIG'] = '?invalid'
if mode == 'wrong-hash': fields['SHA256SUM'] = '0' * 64
if mode == 'wrong-version': fields['VERSION'] = '9.0.0-1'
for name in ('lasa.db.tar.gz', 'lasa.files.tar.gz'):
    data = ''.join('%' + key + '%\n' + value + '\n\n' for key, value in fields.items()).encode()
    if mode == 'files-only' and name == 'lasa.files.tar.gz':
        data = data.replace(signature.encode(), b'')
    with tarfile.open(name, 'w:gz') as archive:
        entry = tarfile.TarInfo('lasa-1.2.3-1/desc')
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
'''


class ArchDatabaseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        tool = self.bin / 'repo-add'
        tool.write_text(REPO_ADD)
        tool.chmod(0o755)
        self.package = self.root / 'lasa-1.2.3-1-x86_64.pkg.tar.zst'
        self.package.write_bytes(b'fixture package bytes')
        self.signature = Path(str(self.package) + '.sig')
        self.signature.write_bytes(b'fixture signature bytes')

    def invoke(self, major='6', mode=''):
        return subprocess.run(['bash', str(SCRIPT), str(self.root), self.package.name],
                              env={**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                                   'TEST_REPO_MAJOR': major, 'TEST_REPO_MODE': mode},
                              text=True, capture_output=True)

    def test_pacman6_default_and_pacman7_explicit_signature_options(self):
        for major in ('6', '7'):
            with self.subTest(major=major):
                result = self.invoke(major)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_both_indexes_require_matching_signature_and_package_metadata(self):
        for mode in ('missing', 'wrong-signature', 'bad-base64', 'wrong-hash', 'wrong-version', 'files-only'):
            with self.subTest(mode=mode):
                result = self.invoke('7', mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Arch repository validation failed:', result.stderr)

    def test_unknown_tool_versions_fail_before_database_changes(self):
        result = self.invoke('8')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('supported repo-add', result.stderr)
        self.assertFalse((self.root / 'lasa.db.tar.gz').exists())

    def test_missing_signature_fails_before_database_changes(self):
        self.signature.unlink()
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('detached signature are required', result.stderr)
        self.assertFalse((self.root / 'lasa.db.tar.gz').exists())


if __name__ == '__main__':
    unittest.main()
