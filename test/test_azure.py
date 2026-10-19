"""Azure orchestration contract tests; no network access or real secrets."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

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
        with self.assertRaisesRegex(ValueError, "hosted"):
            self.run_configure(FakeAzure(hosted=False))
        self.run_command.assert_not_called()

    def test_refuses_to_overwrite_unrelated_pipeline(self):
        api = FakeAzure(existing=True)
        api.definition["repository"]["name"] = "other/repo"
        with self.assertRaisesRegex(ValueError, "another repository"):
            self.run_configure(api)
        self.assertFalse(any(method == "PUT" and "build/definitions" in path for method, path, _ in api.calls))

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
        self.assertFalse(any("build/definitions" in path for _, path, _ in api.calls))

    def test_rejects_non_azure_credential_destinations(self):
        for url in ("http://dev.azure.com/example", "https://evil.test/example", "https://dev.azure.com/example/extra"):
            with self.assertRaises(ValueError):
                module.Azure(url, "test-token")


if __name__ == "__main__":
    unittest.main()
