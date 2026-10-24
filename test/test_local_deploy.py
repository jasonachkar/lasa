"""Local publisher boundaries: verification, credential lifetime, retries and provider ownership."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


launcher = load("local_deploy", "deploy-local.py")
worker = load("local_release", "local-release.py")


def credentials():
    return {"schema": "lasa.local-credentials/v1", "source_revision": "a" * 40,
            "source_branch": "feature/lasa", "distribution_branch": "main", "GH_TOKEN": "PRIVATE_GITHUB_TOKEN",
            "APT_SIGNING_KEY": "PRIVATE_OPENPGP_KEY", "APK_SIGNING_KEY": "PRIVATE_APK_KEY",
            "DISTRIBUTION_DEPLOY_KEY": "PRIVATE_DEPLOY_KEY", "APT_SIGNING_FINGERPRINT": "B" * 40,
            "APK_PUBLIC_KEY_SHA256": "c" * 64}


class CredentialTests(unittest.TestCase):
    def test_private_credentials_are_consumed_and_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            launcher.write_private(path, credentials())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(worker.read_credentials(path), credentials())
            self.assertFalse(path.exists())

    def test_unrecognized_private_input_is_preserved_without_echo(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            launcher.write_private(path, {"schema": "wrong", "GH_TOKEN": "PRIVATE_GITHUB_TOKEN"})
            with self.assertRaisesRegex(ValueError, "schema") as error:
                worker.read_credentials(path)
            self.assertNotIn("PRIVATE", str(error.exception))
            self.assertTrue(path.exists())
            path.write_text("-----BEGIN PRIVATE KEY-----\nPRIVATE_KEY\n")
            with self.assertRaises(ValueError):
                worker.read_credentials(path)
            self.assertTrue(path.exists())

    def test_publicly_readable_or_symlinked_credentials_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            launcher.write_private(path, credentials())
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "private"):
                worker.read_credentials(path)
            path.chmod(0o600)
            alias = Path(directory) / "alias.json"
            alias.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "regular file"):
                worker.read_credentials(alias)
            self.assertTrue(path.exists())

    def test_unverified_revision_never_starts_publishing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".build").mkdir()
            (root / ".build/local-verification.json").write_text(json.dumps({"schema": "lasa.local-verification/v1", "verified": True, "source_revision": "d" * 40}))
            path = root / "credentials.json"
            launcher.write_private(path, credentials())
            with patch.object(worker, "ROOT", root), patch.object(worker.subprocess, "check_output", return_value="a" * 40), patch.object(worker.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "verification record"):
                    worker.publish(path)
            run.assert_not_called()
            self.assertFalse(path.exists())

    def test_verified_worker_sets_only_fixed_publication_destinations_and_no_secret_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".build").mkdir()
            (root / ".build/local-verification.json").write_text(json.dumps({"schema": "lasa.local-verification/v1", "verified": True, "source_revision": "a" * 40}))
            path = root / "credentials.json"
            launcher.write_private(path, credentials())
            with patch.object(worker, "ROOT", root), patch.object(worker.subprocess, "check_output", return_value="a" * 40), patch.object(worker.subprocess, "run") as run:
                worker.publish(path)
            publication = run.call_args
            self.assertEqual(publication.args[0], ["bash", "scripts/release.sh"])
            environment = publication.kwargs["env"]
            self.assertEqual(environment["LASA_RELEASE_PROVIDER"], "local")
            self.assertEqual(environment["LASA_RELEASE_BRANCH"], "feature/lasa")
            self.assertEqual(environment["GITHUB_REPOSITORY"], "jasonachkar/lasa")
            self.assertEqual(environment["GH_TOKEN"], "PRIVATE_GITHUB_TOKEN")
            self.assertNotIn("PRIVATE", repr(publication.args))
            self.assertFalse(path.exists())


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        with patch.object(launcher.Path, "home", return_value=self.home), patch.dict(os.environ, {"LASA_GITHUB_TOKEN": "PRIVATE_GITHUB_TOKEN", "AZURE_DEVOPS_EXT_PAT": "PRIVATE_AZURE_TOKEN", "APT_SIGNING_KEY": "PRIVATE_SIGNING_KEY"}):
            self.deployment = launcher.Deployment(argparse.Namespace(cpus=2, memory="4G", disk="40G"))
        self.deployment.state.mkdir(parents=True)
        self.deployment.branch = "feature/lasa"
        self.deployment.commit = "a" * 40
        self.deployment.distribution_branch = "main"

    def test_vm_and_tool_environment_omits_owner_tokens(self):
        for key in ("GH_TOKEN", "GITHUB_TOKEN", "LASA_GITHUB_TOKEN", "AZURE_DEVOPS_EXT_PAT", "APT_SIGNING_KEY"):
            self.assertNotIn(key, self.deployment.environment)
        self.assertEqual(self.deployment.github_environment["GH_TOKEN"], "PRIVATE_GITHUB_TOKEN")

    def test_recovery_removes_only_its_journaled_vm(self):
        launcher.write_private(self.deployment.journal, {"schema": launcher.JOURNAL_SCHEMA, "vm": "lasa-local-0123456789ab"})
        with patch.object(self.deployment, "existing_vms", return_value={"lasa-local-0123456789ab", "unrelated-vm"}), patch.object(launcher, "run") as run, patch("builtins.print"):
            self.deployment.recover()
        run.assert_called_once_with(["multipass", "delete", "--purge", "lasa-local-0123456789ab"], env=self.deployment.environment, timeout=180)
        self.assertFalse(self.deployment.journal.exists())

    def test_forged_recovery_name_cannot_delete_unrelated_vm(self):
        launcher.write_private(self.deployment.journal, {"schema": launcher.JOURNAL_SCHEMA, "vm": "important-vm"})
        with patch.object(launcher, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "no VM was removed"):
                self.deployment.recover()
        run.assert_not_called()

    def test_failed_vm_deletion_preserves_recovery_journal(self):
        launcher.write_private(self.deployment.journal, {"schema": launcher.JOURNAL_SCHEMA, "vm": "lasa-local-0123456789ab"})
        with patch.object(self.deployment, "existing_vms", return_value={"lasa-local-0123456789ab"}), patch.object(launcher, "run", side_effect=RuntimeError("service unavailable")), patch("builtins.print"):
            with self.assertRaises(RuntimeError):
                self.deployment.recover()
        self.assertTrue(self.deployment.journal.exists())

    def test_verification_failure_cleans_vm_before_any_secret_export_or_transfer(self):
        calls = []
        def run(args, **kwargs):
            calls.append(args)
            if args[:3] == ["git", "rev-parse", "--is-shallow-repository"]:
                return "false"
            if args[:3] == ["git", "rev-parse", "FETCH_HEAD"]:
                return "a" * 40
            return ""
        def guest(*args, **kwargs):
            if args[-1] == "verify":
                raise RuntimeError("fixture verification failed")
            return ""
        def vms():
            return {self.deployment.vm} if self.deployment.vm else set()
        # Before the launch the generated name is intentionally absent; afterwards present.
        with patch.object(launcher, "run", side_effect=run), patch.object(self.deployment, "guest", side_effect=guest), patch.object(self.deployment, "existing_vms", side_effect=[set(), {"fixture"}]), patch("builtins.print"):
            # Cleanup list must contain the dynamically chosen VM, not a fixture constant.
            with patch.object(self.deployment, "existing_vms", side_effect=lambda: set() if not any(a[:2] == ["multipass", "launch"] for a in calls) else vms()):
                with self.assertRaisesRegex(RuntimeError, "verification failed"):
                    self.deployment._deploy()
        self.assertFalse(any(args[0] == "gpg" for args in calls))
        self.assertFalse(any(args[:2] == ["gh", "variable"] for args in calls))
        self.assertFalse(any(any("credentials.json" in argument for argument in args) for args in calls))
        self.assertTrue(any(args[:3] == ["multipass", "delete", "--purge"] for args in calls))
        self.assertFalse(self.deployment.journal.exists())

    def test_command_failures_withhold_credential_bearing_stderr(self):
        result = subprocess.CompletedProcess(["gh"], 1, stdout="PRIVATE_RESPONSE", stderr="HTTP 403 PRIVATE_GITHUB_TOKEN")
        with patch.object(launcher.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "HTTP 403") as error:
                launcher.run(["gh", "api", "repos/example"], capture=True)
        self.assertNotIn("PRIVATE", str(error.exception))


class ProviderTests(unittest.TestCase):
    def test_publisher_guard_defaults_only_missing_provider_to_github(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "gh"
            binary.write_text('#!/bin/sh\ncase "$FIXTURE_PROVIDER" in missing) echo "HTTP 404" >&2; exit 1;; denied) echo "HTTP 403 PRIVATE_RESPONSE" >&2; exit 1;; *) printf "%s\\n" "$FIXTURE_PROVIDER";; esac\n')
            binary.chmod(0o700)
            for provider, expected, succeeds in (("local", "local", True), ("local", "azure", False), ("missing", "github", True), ("denied", "github", False)):
                with self.subTest(provider=provider, expected=expected):
                    env = dict(os.environ, PATH=directory + ":" + os.environ["PATH"], FIXTURE_PROVIDER=provider)
                    result = subprocess.run(["bash", str(ROOT / "scripts/check-publisher.sh"), expected], env=env, capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode == 0, succeeds)
                    self.assertNotIn("PRIVATE", result.stderr)


if __name__ == "__main__":
    unittest.main()
