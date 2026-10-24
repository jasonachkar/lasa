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
if args[0] == 'build':
    if os.environ.get('FAIL_BUILD') == '1': raise SystemExit(1)
    images[args[args.index('-t') + 1]] = args[args.index('--platform') + 1]
    state.write_text(json.dumps(images)); raise SystemExit(0)
if args[0] == 'pull':
    # Models ARM64 default selection and the AMD64-only Arch manifest.
    platform = args[args.index('--platform') + 1] if '--platform' in args else os.environ['DOCKER_DEFAULT_PLATFORM']
    if os.environ.get('FAIL_PULL') == '1' or ('archlinux:' in args[-1] and platform != 'linux/amd64'):
        print('no matching manifest', file=sys.stderr); raise SystemExit(1)
    images[args[-1]] = os.environ.get('PULL_RESULT', platform)
    state.write_text(json.dumps(images)); raise SystemExit(0)
if args[0] == 'create':
    assert '--platform' in args, 'implicit container architecture'
    platform = args[args.index('--platform') + 1]
    image = next(item for item in args if item in images)
    assert images.get(image) == platform, 'cached architecture differs'
    assert ('aarch64' if platform == 'linux/arm64' else 'x86_64') in args
    print('0' * 63 + '1'); raise SystemExit(0)
if args[0] == 'start': raise SystemExit(int(os.environ.get('FAIL_RUN', '0')))
if args[0] == 'rm': raise SystemExit(0)
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

    def test_arm64_host_uses_only_native_clients_and_builds_pacman_fixture(self):
        result = self.invoke(FIXTURE_MACHINE='aarch64', LASA_TEST_EMULATED_AMD64='0')
        self.assertEqual(result.returncode, 0, result.stderr)
        runs = [args for args in self.commands() if args[0] == 'create']
        self.assertEqual([args[args.index('--platform') + 1] for args in runs], ['linux/arm64'] * 4)
        self.assertTrue(any('lasa-pacman-fixture:arm64-' in arg for arg in runs[-1]))
        self.assertFalse(any('archlinux:' in arg for args in self.commands() for arg in args))
        self.assertIn('native ARM64', result.stdout)
        self.assertEqual(sum(args[0] == 'build' for args in self.commands()), 1)
        (self.root / 'commands').unlink()
        self.assertEqual(self.invoke(FIXTURE_MACHINE='aarch64').returncode, 0)
        self.assertFalse(any(args[0] == 'build' for args in self.commands()))

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
                self.assertFalse(any(args[0] == 'create' for args in self.commands()))

    def test_native_pacman_build_failure_stops_before_client_execution(self):
        result = self.invoke(FIXTURE_MACHINE='aarch64', FAIL_BUILD='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Native Pacman fixture setup failed', result.stderr)
        self.assertFalse(any(args[0] == 'create' for args in self.commands()))

    def test_runtime_and_daemon_errors_identify_the_failed_boundary(self):
        result = self.invoke(FAIL_DAEMON='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Docker daemon is unavailable', result.stderr)
        (self.root / 'commands').unlink()
        result = self.invoke(FAIL_RUN='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Package container execution failed:', result.stderr)
        self.assertEqual(sum(args[0] == 'create' for args in self.commands()), 1)


if __name__ == '__main__':
    unittest.main()
