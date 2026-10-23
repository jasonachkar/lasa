"""Owner-local PAT recovery, credential isolation and failure-boundary tests."""
from base64 import b64encode
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("configure_azure_pat", ROOT / "scripts/configure-azure.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PATTests(unittest.TestCase):
    organization = "https://dev.azure.com/example"
    secret = "fixture-PAT-never-persist"

    def state(self, directory):
        home = Path(directory)
        state = home / "Library/Application Support/lasa-distribution/jasonachkar_lasa"
        (state / "gnupg").mkdir(parents=True)
        for name, content in {"deploy-key": "fixture-deploy-key", "signing-fingerprint": "A" * 40,
                              "apk-signing-key.pem": "fixture-apk-key", "apk-public-key.sha256": "B" * 64}.items():
            (state / name).write_text(content)
        return home, state

    def test_pat_is_basic_auth_and_api_error_names_pat_recovery(self):
        api = module.Azure(self.organization, self.secret, pat=True)
        with patch.object(module, "build_opener") as opener:
            opener.return_value.open.side_effect = HTTPError(api.base, 403, "private", {}, io.BytesIO(b"private-server-body"))
            with self.assertRaisesRegex(module.AzureHTTPError, "PAT's expiry") as result:
                api.request("POST", "_apis/build/definitions", {"secret": "private-payload"})
        headers = {key.lower(): value for key, value in opener.return_value.open.call_args.args[0].header_items()}
        self.assertEqual(headers["authorization"], "Basic " + b64encode((":" + self.secret).encode()).decode())
        self.assertEqual(headers["x-tfs-fedauthredirect"], "Suppress")
        for secret in (self.secret, "private-server-body", "private-payload"):
            self.assertNotIn(secret, str(result.exception))

    def test_pat_preflight_skips_cli_and_ignores_cli_tenant_selection(self):
        with patch.object(module, "azure_token") as token, patch.object(module, "azure_login") as login, patch.object(module.Azure, "request", return_value={"visibility": "private"}), patch("builtins.print"):
            api = module.authenticated_azure(self.organization, "LASA", tenant="irrelevant/CLI/context", personal_access_token=self.secret)
        self.assertTrue(api.pat)
        token.assert_not_called()
        login.assert_not_called()

    def test_pat_denial_never_attempts_tenant_retry_or_mutations(self):
        denied = module.AzureHTTPError("GET", "_apis/projects/LASA", 401,
                                       "12345678-1234-1234-1234-123456789abc", "TF400813", pat=True)
        with patch.object(module, "azure_token") as token, patch.object(module, "azure_login") as login, patch.object(module.Azure, "request", side_effect=denied) as request, patch.object(module.subprocess, "run") as mutation:
            with self.assertRaisesRegex(RuntimeError, "PAT access could not be verified") as result:
                module.authenticated_azure(self.organization, "LASA", personal_access_token=self.secret)
        self.assertIn("No publishing keys", str(result.exception))
        self.assertNotIn("--reauth", str(result.exception))
        self.assertNotIn(self.secret, str(result.exception))
        self.assertEqual([call.args[0] for call in request.call_args_list], ["GET", "GET"])
        token.assert_not_called()
        login.assert_not_called()
        mutation.assert_not_called()

    def test_pat_project_scope_denial_is_distinguished_from_org_denial(self):
        denied = module.AzureHTTPError("GET", "_apis/projects/LASA", 403, pat=True)
        with patch.object(module.Azure, "request", side_effect=[denied, {"authenticatedUser": {"id": "owner"}}]):
            with self.assertRaisesRegex(RuntimeError, "PAT's project scopes") as result:
                module.authenticated_azure(self.organization, "LASA", personal_access_token=self.secret)
        self.assertIn("cannot grant access its owner lacks", str(result.exception))

    def test_pat_missing_project_still_requires_authenticated_org(self):
        with patch.object(module.Azure, "request", side_effect=[None, {"authenticatedUser": {"id": "00000000-0000-0000-0000-000000000000"}}]) as request:
            with self.assertRaisesRegex(RuntimeError, "PAT access could not be verified"):
                module.authenticated_azure(self.organization, "LASA", personal_access_token=self.secret)
        self.assertEqual([call.args[0] for call in request.call_args_list], ["GET", "GET"])

    def test_bad_destination_and_conflicting_modes_fail_before_auth(self):
        with patch.object(module.getpass, "getpass") as prompt, patch.object(module.subprocess, "run") as browser, patch.object(module, "azure_login") as login:
            with self.assertRaises(ValueError):
                module.read_devops_pat("https://evil.test/organization")
            with self.assertRaises(ValueError):
                module.authenticated_azure(self.organization, "LASA", reauthenticate=True, personal_access_token=self.secret)
        prompt.assert_not_called()
        browser.assert_not_called()
        login.assert_not_called()

    def test_existing_pat_needs_no_browser_or_prompt(self):
        with patch.object(module.getpass, "getpass") as prompt, patch.object(module.subprocess, "run") as browser:
            self.assertEqual(module.read_devops_pat(self.organization, self.secret), self.secret)
        prompt.assert_not_called()
        browser.assert_not_called()

    def test_noninteractive_input_cannot_fall_back_to_visible_read(self):
        with patch.object(module.sys.stdin, "isatty", return_value=False), patch.object(module.getpass, "getpass") as prompt, patch.object(module.subprocess, "run") as browser:
            with self.assertRaisesRegex(RuntimeError, "interactive terminal with hidden input"):
                module.read_devops_pat(self.organization)
        prompt.assert_not_called()
        browser.assert_not_called()

    def test_failed_hidden_prompt_never_falls_back_to_echo(self):
        def unavailable(*_):
            module.warnings.warn("cannot control echo", module.getpass.GetPassWarning)
            raise AssertionError("unsafe fallback must not be reached")
        with patch.object(module.sys.stdin, "isatty", return_value=True), patch.object(module.getpass, "getpass", side_effect=unavailable), patch.object(module.subprocess, "run"), patch("builtins.print"):
            with self.assertRaisesRegex(RuntimeError, "hidden terminal input unavailable"):
                module.read_devops_pat(self.organization)

    def test_browser_unavailable_keeps_hidden_prompt_usable(self):
        with patch.object(module.sys.stdin, "isatty", return_value=True), patch.object(module.subprocess, "run", side_effect=OSError("no opener")), patch.object(module.getpass, "getpass", return_value=self.secret), patch("builtins.print") as output:
            self.assertEqual(module.read_devops_pat(self.organization), self.secret)
        self.assertNotIn(self.secret, str(output.call_args_list))

    def test_cancelled_prompt_stops_safely(self):
        for error in (EOFError, KeyboardInterrupt, OSError):
            with self.subTest(error=error), patch.object(module.sys.stdin, "isatty", return_value=True), patch.object(module.subprocess, "run"), patch.object(module.getpass, "getpass", side_effect=error), patch("builtins.print"):
                with self.assertRaisesRegex(RuntimeError, "PAT input cancelled"):
                    module.read_devops_pat(self.organization)

    def test_malformed_pat_is_rejected_without_echoing_value(self):
        for token in ("fixture secret", "fixture\nsecret", "fixture\x00secret", "é-secret", "X" * 4097):
            with self.subTest(length=len(token)), self.assertRaisesRegex(ValueError, "value withheld") as result:
                module.read_devops_pat(self.organization, token)
            self.assertNotIn(token, str(result.exception))

    def test_denied_main_removes_env_pat_and_never_exports_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            home, state = self.state(directory)
            before = {item.name: item.read_bytes() for item in state.iterdir() if item.is_file()}
            def denied(*args, **kwargs):
                self.assertNotIn("AZURE_DEVOPS_EXT_PAT", os.environ)
                self.assertEqual(kwargs, {"personal_access_token": self.secret})
                raise RuntimeError("PAT HTTP 401")
            with patch.object(module.Path, "home", return_value=home), patch.dict(os.environ, {"LASA_AZURE_DEVOPS_PAT": "1", "LASA_AZURE_REAUTH": "0", "AZURE_DEVOPS_EXT_PAT": self.secret}), patch.object(module, "authenticated_azure", side_effect=denied), patch.object(module, "command") as command, patch.object(module.subprocess, "run") as mutation:
                with self.assertRaisesRegex(RuntimeError, "PAT HTTP 401"):
                    module.main()
            command.assert_not_called()
            mutation.assert_not_called()
            self.assertEqual(before, {item.name: item.read_bytes() for item in state.iterdir() if item.is_file()})

    def test_successful_main_never_copies_pat_to_provider_payloads_or_children(self):
        with tempfile.TemporaryDirectory() as directory:
            home, state = self.state(directory)
            api = object()
            def child(*args, **kwargs):
                self.assertNotIn("AZURE_DEVOPS_EXT_PAT", os.environ)
                self.assertNotIn(self.secret, repr((args, kwargs)))
                return "fixture-non-PAT-value"
            def payload(*args):
                self.assertNotIn(self.secret, repr(args))
                self.assertEqual(set(args[2]), {"GH_TOKEN", "APT_SIGNING_KEY", "DISTRIBUTION_DEPLOY_KEY", "APK_SIGNING_KEY"})
            with patch.object(module.Path, "home", return_value=home), patch.dict(os.environ, {"LASA_AZURE_DEVOPS_PAT": "1", "LASA_AZURE_REAUTH": "0", "AZURE_DEVOPS_EXT_PAT": self.secret, "LASA_GITHUB_TOKEN": "separate-github-fixture"}), patch.object(module, "authenticated_azure", return_value=api), patch.object(module, "command", side_effect=child), patch.object(module.subprocess, "run", side_effect=child), patch.object(module, "configure", side_effect=payload) as configure:
                module.main()
            configure.assert_called_once()
            self.assertTrue(all(self.secret not in item.read_text() for item in state.iterdir() if item.is_file()))

    def test_real_pat_client_never_follows_redirect_or_forwards_basic_auth(self):
        observed = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                observed.append((self.path.split("?")[0], self.headers.get("Authorization")))
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/destination?session=SECRET")
                self.end_headers()
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            api = module.Azure(self.organization, self.secret, pat=True)
            # The test alone redirects the validated client base to a loopback fixture.
            api.base = f"http://127.0.0.1:{server.server_port}"
            with self.assertRaises(module.AzureRedirectError) as result:
                api.request("GET", "original")
            self.assertNotIn("SECRET", str(result.exception))
            self.assertNotIn(self.secret, str(result.exception))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
        self.assertEqual(observed, [("/original", "Basic " + b64encode((":" + self.secret).encode()).decode())])

    def test_shell_flags_reject_conflicting_auth_modes_before_setup(self):
        result = subprocess.run(["bash", str(ROOT / "scripts/bootstrap-azure.sh"), "--reauth", "--devops-pat"],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not both", result.stderr)
        help_result = subprocess.run(["bash", str(ROOT / "scripts/bootstrap-azure.sh"), "--help"],
                                     capture_output=True, text=True, timeout=5, check=True)
        self.assertIn("--devops-pat", help_result.stdout)

    def test_real_wrapper_keeps_environment_pat_out_of_tool_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            script = root / "scripts/bootstrap-azure.sh"
            script.write_text((ROOT / "scripts/bootstrap-azure.sh").read_text())
            binary = root / "bin"
            binary.mkdir()
            log = root / "observed.jsonl"
            helper = "#!" + sys.executable + "\n" + '''import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
with open(os.environ["FIXTURE_LOG"], "a") as output:
    output.write(json.dumps({"name": name, "args": sys.argv[1:], "pat_present": bool(os.environ.get("AZURE_DEVOPS_EXT_PAT"))}) + "\\n")
if name == "git" and sys.argv[1:] == ["branch", "--show-current"]:
    print("fixture-branch")
elif name == "git" and sys.argv[1] == "rev-parse":
    print("fixture-commit")
elif name == "brew" and sys.argv[1] == "--prefix":
    print(os.environ["FIXTURE_ROOT"])
elif name == "gh" and sys.argv[1:] == ["auth", "token"]:
    print("fixture-github-token")
'''
            for name in ("git", "brew", "gh", "gpg", "python3.12"):
                path = binary / name
                path.write_text(helper)
                path.chmod(0o700)
            environment = dict(os.environ, AZURE_DEVOPS_EXT_PAT=self.secret, FIXTURE_ROOT=directory,
                               FIXTURE_LOG=str(log), PATH=str(binary) + ":/usr/bin:/bin")
            subprocess.run(["/bin/bash", str(script), "--devops-pat", "--configure-only"],
                           env=environment, text=True, capture_output=True, check=True, timeout=10)
            observed = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertTrue(any(item["name"] == "python3.12" and item["pat_present"] for item in observed))
            self.assertTrue(all(not item["pat_present"] for item in observed if item["name"] != "python3.12"))
            self.assertFalse(any("azure-cli" in item["args"] for item in observed))
            self.assertNotIn(self.secret, log.read_text())


if __name__ == "__main__":
    unittest.main()
