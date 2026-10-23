"""HTTP regression checks against Microsoft's documented SDK endpoint contracts.

The fixture is not an Azure service emulator or a live authorization check. It
enforces API revisions/auth headers that the earlier orchestration mocks omitted.
"""
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
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

from test_azure import FakeAzure
import test_azure_pat

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("azure_contract", ROOT / "scripts/configure-azure.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class HTTPContractTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.backend = FakeAzure()
        self.reject = None
        self.missing_project = False
        self.payload = None
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.handle_request()
            def do_POST(self):
                self.handle_request()
            def do_PATCH(self):
                self.handle_request()
            def do_PUT(self):
                self.handle_request()
            def log_message(self, *_):
                pass
            def handle_request(self):
                parsed = urlsplit(self.path)
                path = parsed.path.lstrip("/")
                query = parse_qs(parsed.query)
                version = query.pop("api-version", [""])[0]
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                payload = json.loads(body) if body else None
                fixture.calls.append((self.command, path, version, dict(self.headers), payload))
                expected = "7.1"
                if "serviceendpoint/" in path:
                    expected = "7.1-preview.4"
                elif path == "_apis/connectionData" or "distributedtask/" in path or "pipelines/pipelinepermissions/" in path:
                    expected = "7.1-preview.1"
                status = 200
                if self.headers.get("X-VSS-ForceMsaPassThrough") != "true":
                    status, result = 401, {"message": "TF400813 fixture MSA passthrough missing"}
                elif version != expected:
                    status, result = 400, {"message": "fixture endpoint requires preview API revision"}
                elif fixture.reject and fixture.reject[0] in path:
                    status, result = fixture.reject[1], {"message": "PRIVATE_DIAGNOSTIC_BODY"}
                elif fixture.payload is not None:
                    result = fixture.payload
                elif path == "_apis/connectionData":
                    result = {"authenticatedUser": {"id": "fixture-owner", "isActive": True}}
                elif fixture.missing_project and path == "_apis/projects/LASA":
                    status, result = 404, {}
                else:
                    routed = path
                    if "type" in query:
                        routed += "?type=" + query["type"][0]
                    elif "name" in query:
                        routed += "?name=" + query["name"][0]
                    result = fixture.backend.request(self.command, routed, payload)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def client(self, *, pat=False):
        api = module.Azure("https://dev.azure.com/example", "fixture-only-token", pat=pat)
        # Only test code substitutes a local HTTP fixture after destination validation.
        api.base = f"http://127.0.0.1:{self.server.server_port}"
        return api

    def test_actual_http_configuration_uses_sdk_headers_and_endpoint_revisions(self):
        for pat in (False, True):
            with self.subTest(pat=pat), patch.object(module.subprocess, "run") as github, patch("builtins.print"):
                self.calls.clear()
                module.configure(self.client(pat=pat), "LASA", {"GH_TOKEN": "fixture-github-token"}, {}, "refs/heads/feature/lasa", True)
                github.assert_called_once()
                self.assertTrue(any(method == "POST" for method, *_ in self.calls))
                for _, _, _, headers, payload in self.calls:
                    self.assertTrue(headers["Authorization"].startswith("Basic " if pat else "Bearer "))
                    self.assertEqual(headers["X-Tfs-Fedauthredirect"], "Suppress")
                    self.assertNotIn("fixture-only-token", repr(payload))

    def test_org_preflight_uses_preview_connection_contract_before_project_creation(self):
        self.missing_project = True
        api = self.client()
        with patch.object(module, "Azure", return_value=api), patch.object(module, "azure_token", return_value="fixture-only-token"):
            self.assertIs(module.authenticated_azure("https://dev.azure.com/example", "LASA"), api)
        self.assertEqual([(method, path, version) for method, path, version, *_ in self.calls],
                         [("GET", "_apis/projects/LASA", "7.1"), ("GET", "_apis/connectionData", "7.1-preview.1")])

    def test_old_version_reproduces_contract_failure_with_actionable_diagnostic(self):
        with self.assertRaisesRegex(module.AzureHTTPError, "API version: 7.1") as result:
            self.client().request("GET", "_apis/connectionData", version="7.1")
        self.assertEqual(result.exception.status, 400)
        self.assertIn("API contract failure", str(result.exception))
        self.assertNotIn("fixture endpoint", str(result.exception))

    def test_read_only_check_stops_at_rejected_resource_with_api_context(self):
        self.reject = ("serviceendpoint/", 403)
        with patch("builtins.print"), self.assertRaisesRegex(module.AzureHTTPError, "serviceendpoint/endpoints returned HTTP 403") as result:
            module.check_configuration(self.client(pat=True), "LASA")
        self.assertIn("7.1-preview.4", str(result.exception))
        self.assertNotIn("PRIVATE_DIAGNOSTIC_BODY", str(result.exception))
        self.assertTrue(all(method == "GET" for method, *_ in self.calls))

    def test_non_object_json_is_reported_without_an_attribute_traceback(self):
        self.payload = ["PRIVATE_RESPONSE_VALUE"]
        with self.assertRaisesRegex(RuntimeError, "unexpected JSON shape") as result:
            self.client().request("GET", "_apis/projects/LASA")
        self.assertNotIn("PRIVATE_RESPONSE_VALUE", str(result.exception))


class EntryPointTests(unittest.TestCase):
    def test_missing_and_denied_api_responses_close_http_streams(self):
        for status in (404, 403):
            with self.subTest(status=status):
                body = io.BytesIO(b'{"message":"PRIVATE_ERROR_BODY"}')
                error = HTTPError("https://dev.azure.com/example", status, "private", {}, body)
                with patch.object(module, "build_opener") as opener:
                    opener.return_value.open.side_effect = error
                    api = module.Azure("https://dev.azure.com/example", "fixture-token")
                    if status == 404:
                        self.assertIsNone(api.request("GET", "_apis/projects/LASA", missing=True))
                    else:
                        with self.assertRaises(module.AzureHTTPError):
                            api.request("GET", "_apis/projects/LASA")
                self.assertTrue(body.closed)

    def test_blocked_redirect_closes_original_response_stream(self):
        body = io.BytesIO(b"fixture redirect response")
        with self.assertRaises(module.AzureRedirectError):
            module.NoRedirect().redirect_request(Request("https://dev.azure.com/example"), body, 302,
                                                "Found", {}, "https://login.microsoftonline.com/signin")
        self.assertTrue(body.closed)

    def test_python_entrypoint_accepts_pat_and_check_without_wrapper(self):
        with patch.dict(os.environ, {}, clear=True):
            module.cli_options(["--devops-pat", "--check"])
            self.assertEqual(os.environ["LASA_AZURE_DEVOPS_PAT"], "1")
            self.assertEqual(os.environ["LASA_AZURE_CHECK"], "1")
            self.assertEqual(os.environ["LASA_AZURE_REAUTH"], "0")
        result = subprocess.run([sys.executable, str(ROOT / "scripts/configure-azure.py"), "--help"],
                                text=True, capture_output=True, check=True, timeout=5)
        self.assertIn("--devops-pat", result.stdout)
        self.assertIn("--check", result.stdout)

    def test_python_rejects_conflicting_auth_and_operation_flags(self):
        for arguments in (["--devops-pat", "--reauth"], ["--check", "--configure-only"]):
            with self.subTest(arguments=arguments), patch.dict(os.environ, {}, clear=True), patch("sys.stderr", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as result:
                    module.cli_options(arguments)
                self.assertEqual(result.exception.code, 2)

    def test_check_mode_requires_no_keys_github_or_remote_mutations(self):
        api = FakeAzure()
        with patch.dict(os.environ, {"LASA_AZURE_CHECK": "1", "LASA_AZURE_DEVOPS_PAT": "0", "LASA_AZURE_REAUTH": "0"}), patch.object(module, "authenticated_azure", return_value=api), patch.object(module.Path, "home", side_effect=AssertionError("keys must not be inspected")), patch.object(module, "github_token") as token, patch.object(module.subprocess, "run") as mutation, patch("builtins.print"):
            module.main()
        token.assert_not_called()
        mutation.assert_not_called()
        self.assertTrue(all(method == "GET" for method, *_ in api.calls))

    def test_direct_python_loads_github_token_from_cli_without_printing_it(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(module, "command", return_value="fixture-GH-token") as command:
            self.assertEqual(module.github_token(), "fixture-GH-token")
        command.assert_called_once_with("gh", "auth", "token", "--hostname", "github.com", stderr=subprocess.DEVNULL)

    def test_missing_github_credentials_stop_before_key_preparation_or_export(self):
        with tempfile.TemporaryDirectory() as directory:
            home, _ = test_azure_pat.PATTests().state(directory)
            with patch.dict(os.environ, {"LASA_AZURE_CHECK": "0", "LASA_AZURE_DEVOPS_PAT": "0", "LASA_GITHUB_TOKEN": ""}), patch.object(module.Path, "home", return_value=home), patch.object(module, "authenticated_azure", return_value=object()), patch.object(module, "command", side_effect=subprocess.CalledProcessError(1, ["gh"])) as command, patch.object(module.subprocess, "run") as mutation:
                with self.assertRaisesRegex(RuntimeError, "GitHub credentials are unavailable"):
                    module.main()
            self.assertEqual(command.call_count, 1)
            mutation.assert_not_called()

    def test_resource_tenant_header_is_accepted_only_as_a_guid(self):
        tenant = "12345678-1234-1234-1234-123456789ABC"
        self.assertEqual(module.tenant_challenge({"X-VSS-ResourceTenant": tenant}), tenant.lower())
        for value in ("https://evil.test/" + tenant, "SECRET_HEADER_VALUE", tenant + ";token=SECRET"):
            self.assertIsNone(module.tenant_challenge({"X-VSS-ResourceTenant": value}))


if __name__ == "__main__":
    unittest.main()
