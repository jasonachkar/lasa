"""Exercise architecture/cache/registry failures through the real shell helpers."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/package-containers.sh'

DOCKER = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ['CONTAINER_FIXTURE'])
args = sys.argv[1:]
with (root / 'commands').open('a') as log: log.write(json.dumps(args) + '\n')
state = root / 'images.json'
images = json.loads(state.read_text())
if args == ['info']: raise SystemExit(int(os.environ.get('FAIL_DAEMON', '0')))
if args[:2] == ['image', 'inspect']:
    if args[-1] not in images: raise SystemExit(1)
    print(images[args[-1]]); raise SystemExit(0)
if args[0] == 'pull':
    # Models ARM64 default selection and the AMD64-only Arch manifest.
    platform = args[args.index('--platform') + 1] if '--platform' in args else os.environ['DOCKER_DEFAULT_PLATFORM']
    if os.environ.get('FAIL_PULL') == '1' or ('archlinux:' in args[-1] and platform != 'linux/amd64'):
        print('no matching manifest', file=sys.stderr); raise SystemExit(1)
    images[args[-1]] = os.environ.get('PULL_RESULT', platform)
    state.write_text(json.dumps(images)); raise SystemExit(0)
if args[0] == 'run':
    assert '--platform' in args, 'implicit run architecture'
    platform = args[args.index('--platform') + 1]
    image = next(item for item in args if '@sha256:' in item)
    assert images.get(image) == platform, 'cached architecture differs'
    assert ('aarch64' if platform == 'linux/arm64' else 'x86_64') in args
    raise SystemExit(int(os.environ.get('FAIL_RUN', '0')))
raise SystemExit('unsupported fixture command')
'''


class PackageContainerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.environment = {**os.environ, 'PATH': str(self.bin) + ':' + os.environ['PATH'],
                            'CONTAINER_FIXTURE': str(self.root), 'DOCKER_DEFAULT_PLATFORM': 'linux/arm64'}
        self.images = self.root / 'images.json'
        self.images.write_text('{}')
        for name, content in (
            ('docker', DOCKER),
            ('uname', '#!/bin/sh\nprintf "%s\\n" "${FIXTURE_MACHINE:-x86_64}"\n'),
            ('grep', '#!/bin/sh\nexit "${FAIL_BINFMT:-0}"\n'),
        ):
            path = self.bin / name
            path.write_text(content)
            path.chmod(0o755)

    def invoke(self, **environment):
        return subprocess.run(['bash', str(SCRIPT)], env={**self.environment, **environment},
                              capture_output=True, text=True, timeout=15)

    def commands(self):
        return [json.loads(line) for line in (self.root / 'commands').read_text().splitlines()]

    def test_amd64_pulls_ignore_an_arm64_docker_default(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        pulls = [args for args in self.commands() if args[0] == 'pull']
        self.assertEqual(len(pulls), 4)
        self.assertTrue(all(args[1:3] == ['--platform', 'linux/amd64'] for args in pulls))

    def test_arm64_host_probes_native_tools_and_emulated_clients(self):
        result = self.invoke(FIXTURE_MACHINE='aarch64', LASA_TEST_EMULATED_AMD64='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = [args for args in self.commands() if args[0] == 'run']
        self.assertEqual([args[args.index('--platform') + 1] for args in runs], ['linux/arm64'] + ['linux/amd64'] * 4)
        native_image = next(arg for arg in runs[0] if '@sha256:' in arg)
        client_image = next(arg for arg in runs[-1] if '@sha256:' in arg)
        self.assertNotEqual(native_image, client_image, 'Alpine platforms must not share an index-digest cache entry')
        self.assertIn('does not establish native ARM64', result.stdout)

    def test_wrong_cached_architecture_is_replaced_and_matching_cache_is_reused(self):
        self.assertEqual(self.invoke().returncode, 0)
        self.images.write_text(json.dumps({name: 'linux/arm64' for name in json.loads(self.images.read_text())}))
        (self.root / 'commands').unlink()
        self.assertEqual(self.invoke().returncode, 0)
        self.assertEqual(sum(args[0] == 'pull' for args in self.commands()), 4)
        (self.root / 'commands').unlink()
        self.assertEqual(self.invoke().returncode, 0)
        self.assertFalse(any(args[0] == 'pull' for args in self.commands()))

    def test_wrong_pull_result_and_registry_failure_stop_before_execution(self):
        for extra, expected in (({'PULL_RESULT': 'linux/arm64'}, 'resolved to linux/arm64'),
                                ({'FAIL_PULL': '1'}, 'Cannot fetch package container')):
            with self.subTest(extra=extra):
                self.images.write_text('{}')
                (self.root / 'commands').unlink(missing_ok=True)
                result = self.invoke(**extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
                self.assertIn('linux/amd64', result.stderr)
                self.assertFalse(any(args[0] == 'run' for args in self.commands()))

    def test_missing_arm64_emulation_or_handler_stops_before_pulls(self):
        for extra in ({'LASA_TEST_EMULATED_AMD64': '0'}, {'LASA_TEST_EMULATED_AMD64': '1', 'FAIL_BINFMT': '1'}):
            with self.subTest(extra=extra):
                (self.root / 'commands').unlink(missing_ok=True)
                result = self.invoke(FIXTURE_MACHINE='aarch64', **extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('fix-binary (F)', result.stderr)
                self.assertEqual(self.commands(), [['info']])

    def test_runtime_and_daemon_errors_identify_the_failed_boundary(self):
        result = self.invoke(FAIL_DAEMON='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Docker daemon is unavailable', result.stderr)
        (self.root / 'commands').unlink()
        result = self.invoke(FAIL_RUN='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Package container execution failed:', result.stderr)
        self.assertEqual(sum(args[0] == 'run' for args in self.commands()), 1)


if __name__ == '__main__':
    unittest.main()
