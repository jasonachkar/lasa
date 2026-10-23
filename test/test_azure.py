"""Azure orchestration contract tests; no network access or real secrets."""
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request

spec = importlib.util.spec_from_file_location("configure_azure", Path(__file__).resolve().parents[1] / "scripts/configure-azure.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeAzure:
    base = "https://dev.azure.com/example"

    def __init__(self, existing=False, active=False, hosted=True):
        self.calls = []
        self.existing, self.active, self.hosted = existing, active, hosted
        self.definition = {"id": 9, "revision": 2, "repository": {"name": "jasonachkar/lasa"},
                           "process": {"yamlFilename": "azure-pipelines.yml"}}

    def request(self, method, path, data=None, **kwargs):
        self.calls.append((method, path, data))
        if "_apis/projects/" in path:
            return {"id": "project-id", "visibility": "private", "state": "wellFormed"}
        if "serviceendpoint/endpoints" in path:
            if method == "GET":
                return {"value": [{"id": "endpoint-id", "name": "LASA-GitHub", "description": "Owner-configured LASA publishing connection"}] if self.existing else []}
            return {"id": "endpoint-id"}
        if "distributedtask/queues" in path:
            return {"value": [{"id": 4, "name": "Azure Pipelines", "pool": {"isHosted": True}}] if self.hosted else []}
        if "build/definitions" in path:
            if method == "GET":
                return self.definition.copy() if path.endswith("/9") else {"value": [{"id": 9}] if self.existing else []}
            return dict(data, id=9)
        if "pipelinepermissions" in path:
            return {}
        if "build/builds" in path:
            return {"value": [{"id": 12}] if self.active else []} if method == "GET" else {"_links": {"web": {"href": "https://dev.azure.com/example/run"}}}
        raise AssertionError((method, path))


class ConfigureTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(module.subprocess, "run")
        self.run_command = patcher.start()
        self.addCleanup(patcher.stop)

    def run_configure(self, api, configure_only=False):
        with patch("builtins.print"):
            module.configure(api, "LASA", {"GH_TOKEN": "test-token", "APT_SIGNING_KEY": "test-key"},
                             {"DOCS_SITE_URL": "https://lasa.secureobs.com/"}, "refs/heads/feature/lasa", configure_only)
            return self.run_command

    def test_new_pipeline_encrypts_secrets_and_authorizes_only_itself(self):
        api = FakeAzure()
        self.run_configure(api)
        definition = next(data for method, path, data in api.calls if method == "POST" and path.endswith("build/definitions"))
        self.assertTrue(definition["variables"]["GH_TOKEN"]["isSecret"])
        self.assertFalse(definition["variables"]["DOCS_SITE_URL"]["isSecret"])
        permission = next(data for method, path, data in api.calls if method == "PATCH")
        self.assertEqual(permission, {"pipelines": [{"id": 9, "authorized": True}]})
        self.assertTrue(any(method == "POST" and path.endswith("build/builds") for method, path, _ in api.calls))

    def test_retry_reuses_connection_definition_and_existing_run(self):
        api = FakeAzure(existing=True, active=True)
        self.run_configure(api)
        self.assertFalse(any(method == "POST" for method, _, _ in api.calls))
        self.assertTrue(any(method == "PUT" and path.endswith("build/definitions/9") for method, path, _ in api.calls))

    def test_configure_only_does_not_queue(self):
        api = FakeAzure()
        self.run_configure(api, True)
        self.assertFalse(any("build/builds" in path for _, path, _ in api.calls))

    def test_unavailable_hosted_pool_does_not_switch_provider(self):
        api = FakeAzure(hosted=False)
        with self.assertRaisesRegex(ValueError, "hosted"):
            self.run_configure(api)
        self.run_command.assert_not_called()
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_refuses_to_overwrite_unrelated_pipeline(self):
        api = FakeAzure(existing=True)
        api.definition["repository"]["name"] = "other/repo"
        with self.assertRaisesRegex(ValueError, "another repository"):
            self.run_configure(api)
        self.assertTrue(all(method == "GET" for method, _, _ in api.calls))

    def test_api_errors_suppress_secret_response_bodies(self):
        api = module.Azure("https://dev.azure.com/example", "private-token")
        with patch.object(module, "build_opener") as opener:
            opener.return_value.open.side_effect = HTTPError("https://dev.azure.com/example", 403, "private-response", {}, None)
            with self.assertRaisesRegex(RuntimeError, "HTTP 403") as result:
                api.request("POST", "_apis/example", {"secret": "private-payload"})
            self.assertNotIn("private", str(result.exception))

    def test_endpoint_failure_does_not_switch_provider_or_create_pipeline(self):
        api = FakeAzure()
        original = api.request
        def failing(method, path, data=None, **kwargs):
            if method == "POST" and "serviceendpoint" in path:
                raise RuntimeError("HTTP 403")
            return original(method, path, data, **kwargs)
        api.request = failing
        with self.assertRaisesRegex(RuntimeError, "403"):
            self.run_configure(api)
        self.run_command.assert_not_called()
        self.assertFalse(any(method != "GET" and "build/definitions" in path for method, path, _ in api.calls))

    def test_rejects_non_azure_credential_destinations(self):
        for url in ("http://dev.azure.com/example", "https://evil.test/example", "https://dev.azure.com/example/extra"):
            with self.assertRaises(ValueError):
                module.Azure(url, "test-token")


class AuthenticationTests(unittest.TestCase):
    tenant = "12345678-1234-1234-1234-123456789abc"

    def test_read_only_project_preflight_does_not_change_anything(self):
        with patch.object(module, "azure_token", return_value="private-token"), patch.object(module.Azure, "request", return_value={"visibility": "private"}) as request, patch.object(module, "azure_login") as login, patch.object(module.subprocess, "run") as mutation, patch("builtins.print"):
            api = module.authenticated_azure("https://dev.azure.com/example", "LASA")
        self.assertEqual(api.token, "private-token")
        request.assert_called_once_with("GET", "_apis/projects/LASA", missing=True)
        mutation.assert_not_called()
        login.assert_not_called()

    def test_explicit_reauthentication_uses_requested_tenant_without_logging_out(self):
        with patch.object(module.subprocess, "run") as run, patch("builtins.print"):
            module.azure_login(self.tenant)
        run.assert_called_once_with(["az", "login", "--allow-no-subscriptions", "--output", "none", "--tenant", self.tenant], check=True)

    def test_org_authentication_but_project_denial_identifies_permissions(self):
        denied = module.AzureHTTPError("GET", "_apis/projects/LASA", 403)
        with patch.object(module, "azure_token", return_value="never-display-token"), patch.object(module.Azure, "request", side_effect=[denied, {"authenticatedUser": {"id": "owner-id", "isActive": True}}]), patch.object(module.subprocess, "run") as mutation:
            with self.assertRaisesRegex(RuntimeError, "project membership and permissions") as result:
                module.authenticated_azure("https://dev.azure.com/example", "LASA")
        self.assertNotIn("never-display-token", str(result.exception))
        self.assertIn("No publishing keys", str(result.exception))
        mutation.assert_not_called()

    def test_denied_organization_has_actionable_sign_in_recovery(self):
        denied = module.AzureHTTPError("GET", "_apis/projects/LASA", 403)
        with patch.object(module, "azure_token", return_value="secret-token"), patch.object(module.Azure, "request", side_effect=denied), patch.object(module.subprocess, "run") as mutation:
            with self.assertRaisesRegex(RuntimeError, "Organization settings > Users") as result:
                module.authenticated_azure("https://dev.azure.com/example", "LASA")
        self.assertIn("--reauth", str(result.exception))
        self.assertNotIn("secret-token", str(result.exception))
        mutation.assert_not_called()

    def test_authenticated_missing_project_can_proceed_to_configuration(self):
        with patch.object(module, "azure_token", return_value="secret-token"), patch.object(module.Azure, "request", side_effect=[None, {"authenticatedUser": {"id": "owner-id"}}]) as request:
            module.authenticated_azure("https://dev.azure.com/example", "LASA")
        self.assertEqual([c.args[0] for c in request.call_args_list], ["GET", "GET"])

    def test_missing_project_without_organization_auth_cannot_be_created(self):
        with patch.object(module, "azure_token", return_value="secret-token"), patch.object(module.Azure, "request", side_effect=[None, {"authenticatedUser": {"id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}}]):
            with self.assertRaisesRegex(RuntimeError, "organization access could not be verified"):
                module.authenticated_azure("https://dev.azure.com/example", "LASA")

    def test_trusted_tenant_challenge_retries_cached_tenant_once(self):
        denied = module.AzureHTTPError("GET", "_apis/projects/LASA", 403, self.tenant)
        with patch.object(module, "azure_token", side_effect=["wrong-tenant-token", "organization-token"]) as token, patch.object(module.Azure, "request", side_effect=[denied, denied, {"visibility": "private"}]), patch("builtins.print"):
            api = module.authenticated_azure("https://dev.azure.com/example", "LASA")
        self.assertEqual(api.token, "organization-token")
        self.assertEqual([c.args for c in token.call_args_list], [(None,), (self.tenant,)])

    def test_no_cached_organization_tenant_gives_exact_local_recovery(self):
        denied = module.AzureHTTPError("GET", "_apis/projects/LASA", 403, self.tenant)
        with patch.object(module, "azure_token", side_effect=["cached-token", subprocess.CalledProcessError(1, ["az"])]), patch.object(module.Azure, "request", side_effect=denied), patch("builtins.print"):
            with self.assertRaisesRegex(RuntimeError, "LASA_AZURE_TENANT=" + self.tenant):
                module.authenticated_azure("https://dev.azure.com/example", "LASA")

    def test_explicit_tenant_is_not_silently_replaced(self):
        denied = module.AzureHTTPError("GET", "_apis/projects/LASA", 403, self.tenant)
        with patch.object(module, "azure_token", return_value="cached-token") as token, patch.object(module.Azure, "request", side_effect=denied):
            with self.assertRaises(RuntimeError):
                module.authenticated_azure("https://dev.azure.com/example", "LASA", "explicit.onmicrosoft.com")
        token.assert_called_once_with("explicit.onmicrosoft.com")

    def test_non_auth_failure_does_not_prompt_for_another_login(self):
        with patch.object(module, "azure_token", return_value="cached-token"), patch.object(module.Azure, "request", side_effect=module.AzureHTTPError("GET", "_apis/projects/LASA", 429)), patch.object(module, "azure_login") as login:
            with self.assertRaisesRegex(RuntimeError, "429"):
                module.authenticated_azure("https://dev.azure.com/example", "LASA")
        login.assert_not_called()

    def test_reauth_runs_before_access_check(self):
        calls = []
        with patch.object(module, "azure_login", side_effect=lambda _: calls.append("login")), patch.object(module, "azure_token", side_effect=lambda _: calls.append("token") or "token"), patch.object(module.Azure, "request", return_value={"visibility": "private"}), patch("builtins.print"):
            module.authenticated_azure("https://dev.azure.com/example", "LASA", reauthenticate=True)
        self.assertEqual(calls, ["login", "token"])

    def test_api_retains_only_trusted_tenant_guid_from_authentication_header(self):
        headers = {"WWW-Authenticate": 'Bearer authorization_uri="https://login.windows.net/' + self.tenant + '", private="never-display"'}
        api = module.Azure("https://dev.azure.com/example", "secret-token")
        with patch.object(module, "build_opener") as opener:
            opener.return_value.open.side_effect = HTTPError(api.base, 403, "private", headers, io.BytesIO(b"private secret response"))
            with self.assertRaises(module.AzureHTTPError) as result:
                api.request("GET", "_apis/projects/LASA")
        self.assertEqual(result.exception.tenant, self.tenant)
        self.assertNotIn("private", str(result.exception))
        self.assertNotIn("secret-token", str(result.exception))
        self.assertIsNone(module.tenant_challenge({"WWW-Authenticate": "https://evil.test/" + self.tenant}))

    def test_preflight_validates_target_and_tenant_before_authentication(self):
        with patch.object(module, "azure_token") as token, patch.object(module, "azure_login") as login:
            for organization, tenant in [("https://evil.test/org", None), ("https://dev.azure.com/example", "--bad"), ("https://dev.azure.com/example", "https://evil.test")]:
                with self.assertRaises(ValueError):
                    module.authenticated_azure(organization, "LASA", tenant, True)
        token.assert_not_called()
        login.assert_not_called()

    def test_missing_cli_session_opens_login_then_verifies_access(self):
        with patch.object(module, "azure_token", side_effect=[subprocess.CalledProcessError(1, ["az"]), "fresh-token"]), patch.object(module, "azure_login") as login, patch.object(module.Azure, "request", return_value={"visibility": "private"}), patch("builtins.print"):
            api = module.authenticated_azure("https://dev.azure.com/example", "LASA")
        self.assertEqual(api.token, "fresh-token")
        login.assert_called_once_with(None)

    def test_denied_main_preflight_never_prepares_or_exports_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            state = home / "Library/Application Support/lasa-distribution/jasonachkar_lasa"
            (state / "gnupg").mkdir(parents=True)
            (state / "deploy-key").write_text("private fixture; must not be read")
            (state / "signing-fingerprint").write_text("A" * 40)
            with patch.object(module.Path, "home", return_value=home), patch.dict(os.environ, {"LASA_AZURE_PROJECT": "LASA"}), patch.object(module, "authenticated_azure", side_effect=RuntimeError("HTTP 403")), patch.object(module, "command") as command, patch.object(module.subprocess, "run") as mutation:
                with self.assertRaisesRegex(RuntimeError, "403"):
                    module.main()
            command.assert_not_called()
            mutation.assert_not_called()
            self.assertFalse((state / "apk-signing-key.pem").exists())

    def test_changing_authentication_hints_cannot_cause_unbounded_retry(self):
        first = module.AzureHTTPError("GET", "project", 403, self.tenant)
        second = module.AzureHTTPError("GET", "project", 403, "87654321-4321-4321-4321-cba987654321")
        with patch.object(module, "azure_token", side_effect=["initial", "retried"]) as token, patch.object(module.Azure, "request", side_effect=[first, first, second, second]), patch("builtins.print"):
            with self.assertRaisesRegex(RuntimeError, "organization access could not be verified"):
                module.authenticated_azure("https://dev.azure.com/example", "LASA")
        self.assertEqual(token.call_count, 2)


class RedirectTests(unittest.TestCase):
    def test_api_suppresses_federated_login_redirects_and_requests_json(self):
        api = module.Azure("https://dev.azure.com/example", "secret-token")
        with patch.object(module, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'{"visibility":"private"}'
            self.assertEqual(api.request("GET", "_apis/projects/LASA"), {"visibility": "private"})
        request = opener.return_value.open.call_args.args[0]
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(headers["x-tfs-fedauthredirect"], "Suppress")
        self.assertEqual(headers["accept"], "application/json")
        self.assertEqual(headers["authorization"], "Bearer secret-token")

    def test_microsoft_redirect_is_classified_without_disclosing_session_url(self):
        request = Request("https://dev.azure.com/example/_apis/projects/LASA?api-version=7.1")
        request.add_header("Authorization", "Bearer token-must-not-forward")
        with self.assertRaises(module.AzureRedirectError) as result:
            module.NoRedirect().redirect_request(request, None, 302, "Found", {},
                                                "https://app.vssps.visualstudio.com/_signin?realm=SECRET_REALM&session=SECRET_SESSION")
        self.assertTrue(module.access_denial(result.exception))
        self.assertIn("Microsoft sign-in redirect", str(result.exception))
        for secret in ("SECRET_REALM", "SECRET_SESSION", "token-must-not-forward", "_signin?"):
            self.assertNotIn(secret, str(result.exception))

    def test_unexpected_redirect_does_not_become_an_authentication_retry(self):
        error = module.AzureRedirectError("GET", "_apis/projects/LASA", 307, "https://evil.test/secret-path?access_token=SECRET")
        self.assertFalse(module.access_denial(error))
        self.assertNotIn("secret-path", str(error))
        self.assertNotIn("SECRET", str(error))
        self.assertIn("evil.test", str(error))

    def test_sign_in_redirect_is_not_treated_as_a_missing_project(self):
        denied = module.AzureRedirectError("GET", "_apis/projects/LASA", 302, "https://app.vssps.visualstudio.com/_signin?secret=value")
        with patch.object(module, "azure_token", return_value="token"), patch.object(module.Azure, "request", side_effect=denied) as request, patch.object(module.subprocess, "run") as mutation:
            with self.assertRaisesRegex(RuntimeError, "profile/organization sign-in"):
                module.authenticated_azure("https://dev.azure.com/example", "LASA")
        self.assertEqual([c.args[0] for c in request.call_args_list], ["GET", "GET"])
        mutation.assert_not_called()

    def test_known_first_sign_in_code_is_retained_without_private_error_body(self):
        api = module.Azure("https://dev.azure.com/example", "private-token")
        body = b'{"message":"TF401444: Please sign in as private-user@example.test, token=PRIVATE_SECRET"}'
        with patch.object(module, "build_opener") as opener:
            opener.return_value.open.side_effect = HTTPError(api.base, 401, "private", {}, io.BytesIO(body))
            with self.assertRaises(module.AzureHTTPError) as result:
                api.request("GET", "_apis/projects/LASA")
        self.assertEqual(result.exception.service_code, "TF401444")
        self.assertIn("first browser sign-in", str(result.exception))
        for secret in ("private-user", "PRIVATE_SECRET", "private-token"):
            self.assertNotIn(secret, str(result.exception))

    def test_html_response_is_explained_without_returning_html_secrets(self):
        with patch.object(module, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'<html>sign-in PRIVATE_SESSION</html>'
            with self.assertRaisesRegex(RuntimeError, "non-JSON response") as result:
                module.Azure("https://dev.azure.com/example", "token").request("GET", "_apis/projects/LASA")
        self.assertNotIn("PRIVATE_SESSION", str(result.exception))

    def test_oversized_response_has_a_bounded_actionable_failure(self):
        with patch.object(module, "build_opener") as opener:
            opener.return_value.open.return_value.__enter__.return_value.read.return_value = b'x' * ((8 << 20) + 1)
            with self.assertRaisesRegex(RuntimeError, "8MiB response budget"):
                module.Azure("https://dev.azure.com/example", "token").request("GET", "_apis/projects/LASA")
            opener.return_value.open.return_value.__enter__.return_value.read.assert_called_once_with((8 << 20) + 1)

    def test_real_http_client_never_requests_redirect_destination(self):
        observed = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                observed.append(self.path)
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/destination?session=PRIVATE_SESSION")
                self.end_headers()
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            request = Request(f"http://127.0.0.1:{server.server_port}/original", headers={"Authorization": "Bearer fixture-only"})
            with self.assertRaises(module.AzureRedirectError):
                module.build_opener(module.NoRedirect).open(request, timeout=5)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
        self.assertEqual(observed, ["/original"])


if __name__ == "__main__":
    unittest.main()
