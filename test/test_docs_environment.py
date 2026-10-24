"""Real venv/pip permission regressions; all wheels are local fixtures, no network."""
import base64
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def fixture_wheel(directory):
    """A tiny public package exercises pip's real file and console-script modes."""
    files = {
        "lasa_docs_probe.py": b'def main():\n    print("fixture documentation CLI")\n',
        "mkdocs.py": b'__version__ = "fixture"\n',
        "mike.py": b'__version__ = "fixture"\n',
        "yaml.py": b'__version__ = "fixture"\n',
        "lasa_docs_probe-1.0.0.dist-info/METADATA": b'Metadata-Version: 2.1\nName: lasa-docs-probe\nVersion: 1.0.0\n',
        "lasa_docs_probe-1.0.0.dist-info/WHEEL": b'Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        "lasa_docs_probe-1.0.0.dist-info/entry_points.txt": b'[console_scripts]\nmkdocs = lasa_docs_probe:main\nmike = lasa_docs_probe:main\n',
    }
    records = []
    for name, content in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
        records.append(f"{name},sha256={digest},{len(content)}\n")
    record = "lasa_docs_probe-1.0.0.dist-info/RECORD"
    files[record] = ("".join(records) + record + ",,\n").encode()
    wheel = directory / "lasa_docs_probe-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return wheel


class DocsEnvironmentTests(unittest.TestCase):
    def test_private_caller_umask_yields_readable_public_tools_without_system_python(self):
        with tempfile.TemporaryDirectory(prefix="lasa docs env ") as directory:
            root = Path(directory)
            wheel = fixture_wheel(root)
            requirements = root / "requirements.txt"
            requirements.write_text(wheel.as_uri() + "\n")
            poison = root / "poison"
            poison.mkdir()
            (poison / "python").write_text('#!/bin/sh\necho "unversioned system Python must not be used" >&2\nexit 97\n')
            (poison / "python").chmod(0o755)
            environment = dict(os.environ, PATH=str(poison) + ":" + os.environ["PATH"], PIP_NO_INDEX="1", PIP_CONFIG_FILE=os.devnull)
            target = root / "public-venv"
            result = subprocess.run(["bash", "-c", 'set -euo pipefail; umask 077; bash "$1" "$2" "$3"; test "$(umask)" = 0077',
                                     "fixture", str(ROOT / "scripts/install-public-docs-venv.sh"), str(target), str(requirements)],
                                    env=environment, text=True, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            for folder in (target, target / "bin", target / "lib"):
                self.assertEqual(stat.S_IMODE(folder.stat().st_mode) & 0o055, 0o055)
            for module in target.glob("lib/python*/site-packages/lasa_docs_probe.py"):
                self.assertTrue(module.stat().st_mode & stat.S_IROTH)
            result = subprocess.run(["bash", str(ROOT / "scripts/check-docs-environment.sh"), str(target / "bin/python3")],
                                    env=environment, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("fixture documentation CLI", result.stdout)

    def test_existing_private_directory_is_never_repermissioned(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "private-state"
            target.mkdir(mode=0o700)
            key = target / "saved-key"
            key.write_text("private fixture key")
            key.chmod(0o600)
            result = subprocess.run(["bash", str(ROOT / "scripts/install-public-docs-venv.sh"), str(target), "unused-requirements"],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already exists", result.stderr)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            self.assertEqual(key.read_text(), "private fixture key")

    def test_missing_interpreter_is_identified_before_build_work(self):
        result = subprocess.run(["bash", str(ROOT / "scripts/check-docs-environment.sh"), "/nonexistent/lasa-venv/bin/python3"],
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing or inaccessible", result.stderr)

    def test_missing_dependencies_are_identified_without_system_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "empty-venv"
            subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(target)], check=True, timeout=20)
            result = subprocess.run(["bash", str(ROOT / "scripts/check-docs-environment.sh"), str(target / "bin/python3")],
                                    text=True, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot import MkDocs, Mike or PyYAML", result.stderr)


if __name__ == "__main__":
    unittest.main()
