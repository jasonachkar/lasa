#!/usr/bin/env python3
"""Owner-local Azure bootstrap. Tokens stay in memory; API error bodies are redacted."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


def command(*args, **kwargs):
    # Never print subprocess stdout: it can contain credentials or private keys.
    return subprocess.check_output(args, text=True, **kwargs).strip()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("Azure API redirected the authenticated request; check the organization URL and sign-in tenant")


class Azure:
    def __init__(self, organization, token):
        if not re.fullmatch(r"https://dev\.azure\.com/[A-Za-z0-9][A-Za-z0-9-]*/?", organization):
            raise ValueError("Organization must be an HTTPS dev.azure.com organization URL")
        self.base = organization.rstrip("/")
        self.token = token

    def request(self, method, path, data=None, *, missing=False, version="7.1"):
        url = self.base + "/" + path.lstrip("/")
        url += ("&" if "?" in url else "?") + "api-version=" + version
        request = Request(url, data=None if data is None else json.dumps(data).encode(), method=method,
                          headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with build_opener(NoRedirect).open(request, timeout=60) as response:
                content = response.read()
                return json.loads(content) if content else {}
        except HTTPError as error:
            if missing and error.code == 404:
                return None
            raise RuntimeError(f"Azure {method} {path.split('?')[0]} returned HTTP {error.code}. "
                               "Check organization membership, project administration and token/tenant access. "
                               "The response body is suppressed to protect secrets.") from None
        except (URLError, TimeoutError) as error:
            raise RuntimeError(f"Azure {method} request failed ({type(error).__name__}); check connectivity and retry.") from None


def configure(api, project_name, secrets, public, branch, configure_only):
    project_path = quote(project_name, safe="")
    project = api.request("GET", f"_apis/projects/{project_path}", missing=True)
    if project is None:
        print(f"Creating private Azure project {project_name}", flush=True)
        api.request("POST", "_apis/projects", {
            "name": project_name, "visibility": "private",
            "description": "LASA verification and signed distribution automation",
            "capabilities": {"versioncontrol": {"sourceControlType": "Git"},
                             "processTemplate": {"templateTypeId": "6b724908-ef14-45cf-84f8-768b5384da45"}}})
        for _ in range(120):
            project = api.request("GET", f"_apis/projects/{project_path}", missing=True)
            if project and project.get("state", "").lower() == "wellformed":
                break
            time.sleep(2)
        else:
            raise RuntimeError("Azure project creation did not finish in four minutes; rerun to reuse it.")
    if project.get("visibility") != "private":
        raise ValueError("The existing LASA project is not private; choose a private project with LASA_AZURE_PROJECT")
    prefix = quote(project["id"], safe="") + "/_apis/"
    endpoints = api.request("GET", prefix + "serviceendpoint/endpoints?type=github")["value"]
    matches = [item for item in endpoints if item["name"] == "LASA-GitHub"]
    if len(matches) > 1:
        raise ValueError("Multiple LASA-GitHub connections exist; refusing an ambiguous update")
    endpoint = {"name": "LASA-GitHub", "type": "github", "url": "https://github.com",
                "authorization": {"scheme": "PersonalAccessToken", "parameters": {"accessToken": secrets["GH_TOKEN"]}},
                "isShared": False, "isReady": True,
                "description": "Owner-configured LASA publishing connection",
                "serviceEndpointProjectReferences": [{"projectReference": {"id": project["id"], "name": project_name},
                                                      "name": "LASA-GitHub"}]}
    if matches:
        if matches[0].get("description") != "Owner-configured LASA publishing connection":
            raise ValueError("The existing LASA-GitHub connection was not created by this bootstrap; refusing to replace its credentials")
        endpoint["id"] = matches[0]["id"]
        endpoint = api.request("PUT", "_apis/serviceendpoint/endpoints/" + endpoint["id"], endpoint)
    else:
        endpoint = api.request("POST", "_apis/serviceendpoint/endpoints", endpoint)
    queues = api.request("GET", prefix + "distributedtask/queues")["value"]
    queues = [queue for queue in queues if queue.get("pool", {}).get("isHosted") and queue["name"] == "Azure Pipelines"]
    if len(queues) != 1:
        raise ValueError("The project has no unique Microsoft-hosted 'Azure Pipelines' queue. "
                         "Enable Azure Pipelines/hosted-agent access for this organization, then rerun.")
    definitions = api.request("GET", prefix + "build/definitions?name=LASA")["value"]
    if len(definitions) > 1:
        raise ValueError("Multiple LASA build definitions exist; refusing an ambiguous update")
    definition = {}
    if definitions:
        definition = api.request("GET", prefix + "build/definitions/" + str(definitions[0]["id"]))
        if (definition.get("repository", {}).get("name") != "jasonachkar/lasa"
                or definition.get("process", {}).get("yamlFilename") != "azure-pipelines.yml"):
            raise ValueError("Existing LASA pipeline belongs to another repository or YAML path; refusing to overwrite")
    variables = {name: {"value": value, "isSecret": False} for name, value in public.items()}
    variables.update({name: {"value": value, "isSecret": True} for name, value in secrets.items()})
    definition.update({"name": "LASA", "type": "build", "queueStatus": "enabled",
                       "queue": {"id": queues[0]["id"]}, "process": {"type": 2, "yamlFilename": "azure-pipelines.yml"},
                       "variables": variables,
                       "repository": {"id": "jasonachkar/lasa", "name": "jasonachkar/lasa", "type": "GitHub",
                                      "url": "https://github.com/jasonachkar/lasa.git", "defaultBranch": branch,
                                      "clean": "true", "properties": {"connectedServiceId": endpoint["id"],
                                      "reportBuildStatus": "true", "fetchDepth": "0"}}})
    definition = api.request("PUT" if definitions else "POST", prefix + "build/definitions" +
                             ("/" + str(definition["id"]) if definitions else ""), definition)
    pipeline_id = definition["id"]
    api.request("PATCH", prefix + "pipelines/pipelinepermissions/endpoint/" + endpoint["id"],
                {"pipelines": [{"id": pipeline_id, "authorized": True}]}, version="7.1-preview.1")
    api.request("PATCH", prefix + "pipelines/pipelinepermissions/queue/" + str(queues[0]["id"]),
                {"pipelines": [{"id": pipeline_id, "authorized": True}]}, version="7.1-preview.1")
    # Switch publishers only after Azure configuration and resource authorization succeed.
    subprocess.run(["gh", "variable", "set", "PUBLISHING_PROVIDER", "--repo", "jasonachkar/lasa", "--body", "azure"], check=True)
    url = api.base + "/" + project_path + "/_build?definitionId=" + str(pipeline_id)
    print("Azure pipeline configured: " + url, flush=True)
    if not configure_only:
        active = api.request("GET", prefix + "build/builds?" + urlencode({"definitions": pipeline_id, "statusFilter": "inProgress,notStarted"}))["value"]
        if active:
            print("An existing LASA run is queued/running; no duplicate run was created.")
        else:
            build = api.request("POST", prefix + "build/builds", {"definition": {"id": pipeline_id}, "sourceBranch": branch})
            print("Queued run: " + build.get("_links", {}).get("web", {}).get("href", url))
    print("Trusted branch runs publish customer docs and verify code. Stable releases publish automatically on main.")


def main():
    organization = os.environ.get("LASA_AZURE_ORGANIZATION", "https://dev.azure.com/jasonachkardiab")
    project = os.environ.get("LASA_AZURE_PROJECT", "LASA")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]{0,63}", project):
        raise ValueError("Invalid LASA_AZURE_PROJECT name")
    state = Path.home() / "Library/Application Support/lasa-distribution/jasonachkar_lasa"
    for path in (state / "deploy-key", state / "signing-fingerprint", state / "gnupg"):
        if not path.exists():
            raise ValueError(f"Restore existing publishing state: {path}. Keys will not be regenerated.")
    fingerprint = (state / "signing-fingerprint").read_text().strip()
    if not re.fullmatch(r"[A-F0-9]{40}", fingerprint):
        raise ValueError("Invalid local signing fingerprint")
    # Short alias avoids macOS GnuPG Unix socket length limits.
    with tempfile.TemporaryDirectory(prefix="lasa-gpg-", dir="/tmp") as temp:
        alias = Path(temp) / "home"
        alias.symlink_to(state / "gnupg", target_is_directory=True)
        try:
            key = command("gpg", "--homedir", str(alias), "--batch", "--armor", "--export-secret-keys", fingerprint)
        finally:
            subprocess.run(["gpgconf", "--homedir", str(alias), "--kill", "gpg-agent"],
                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not key:
        raise ValueError("Local signing key could not be exported; restore your private state backup")
    secrets = {"GH_TOKEN": os.environ["LASA_GITHUB_TOKEN"], "APT_SIGNING_KEY": key,
               "DISTRIBUTION_DEPLOY_KEY": (state / "deploy-key").read_text()}
    public = {"APT_SIGNING_FINGERPRINT": fingerprint, "DISTRIBUTION_REPOSITORY": "jasonachkar/homebrew-lasa",
              "DISTRIBUTION_BRANCH": command("gh", "api", "repos/jasonachkar/homebrew-lasa", "--jq", ".default_branch"),
              "APT_REPOSITORY_URL": "https://lasa.secureobs.com/apt", "DOCS_SITE_URL": "https://lasa.secureobs.com/"}
    branch = "refs/heads/" + command("git", "branch", "--show-current")
    token = command("az", "account", "get-access-token", "--resource", "499b84ac-1321-427f-aa17-267ca6975798", "--query", "accessToken", "--output", "tsv")
    configure(Azure(organization, token), project, secrets, public, branch,
              os.environ.get("LASA_AZURE_CONFIGURE_ONLY") == "1")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, KeyError, OSError, subprocess.CalledProcessError) as error:
        # CalledProcessError stores arguments; credential-bearing commands never use args for values.
        print(f"Azure bootstrap stopped: {error}", file=sys.stderr)
        sys.exit(1)
