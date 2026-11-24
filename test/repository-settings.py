#!/usr/bin/env python3
"""Exercise the GitHub settings guards without writing remote configuration."""

import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "repository_settings",
    Path(__file__).resolve().parents[1] / "scripts/security/repository-settings.py",
)
settings = importlib.util.module_from_spec(spec)
spec.loader.exec_module(settings)


class RepositorySettingsTest(unittest.TestCase):
    def test_public_repository_rejects_writes(self):
        with patch.object(settings, "api", return_value={
            "full_name": settings.REPO, "visibility": "public", "private": False,
        }) as api:
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(settings.SettingsError):
                    settings.Changes("apply").require(False, "PATCH", settings.ROOT)
            api.assert_called_once_with(settings.ROOT)

    def test_dry_run_has_no_writes(self):
        with patch.object(settings, "api") as api, contextlib.redirect_stdout(io.StringIO()) as stdout:
            settings.Changes("plan").require(False, "PUT", "example", {"enabled": True})
            api.assert_not_called()
            self.assertIn('PUT example {"enabled": true}', stdout.getvalue())

    def test_apply_requires_readback(self):
        with patch.object(settings, "repository"), patch.object(settings, "api") as api:
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(settings.SettingsError, "read-back"):
                    settings.Changes("apply").require(False, "PUT", "example", verified=lambda: False)
            api.assert_called_once_with("example", "PUT", None)

    def test_governance_rejects_unknown_fork_and_skipped_gate(self):
        sha = "f" * 40
        run = {
            "id": 42, "head_sha": sha, "conclusion": "success", "event": "pull_request",
            "head_repository": {"full_name": settings.REPO}, "path": ".github/workflows/ci.yml",
        }
        for result, repo, expected in [
            ("skipped", settings.REPO, False),
            ("success", "example/fork", False),
            ("success", settings.REPO, True),
        ]:
            with self.subTest(result=result, repo=repo), patch.object(settings, "api", side_effect=[
                {"workflow_runs": [{**run, "head_repository": {"full_name": repo}}]},
                {"jobs": [{"name": settings.GATE, "conclusion": result}]},
            ]):
                self.assertEqual(settings.successful_gate(sha), expected)


if __name__ == "__main__":
    unittest.main()
