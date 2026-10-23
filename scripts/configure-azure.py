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
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


def command(*args, **kwargs):
    # Never print subprocess stdout: it can contain credentials or private keys.
    return subprocess.check_output(args, text=True, **kwargs).strip()


class AzureHTTPError(RuntimeError):
    def __init__(self, method, path, status, tenant=None, service_code=None):
        self.status = status
        self.tenant = tenant
        self.service_code = service_code
        detail = ""
        if service_code == "TF401444":
            detail = " Azure DevOps requires this account to complete its first browser sign-in to the organization."
        elif service_code in ("TF400813", "VS30063"):
            detail = " Azure DevOps did not authorize this account for the requested resource."
        super().__init__(f"Azure {method} {path.split('?')[0]} returned HTTP {status}. "
                         + (f"Service code: {service_code}." if service_code else "") + detail + " "
                         "Check organization membership, project administration and token/tenant access. "
                         "The response body is suppressed to protect secrets.")


class AzureRedirectError(AzureHTTPError):
    def __init__(self, method, path, status, target, tenant=None):
        super().__init__(method, path, status, tenant)
        try:
            destination = urlsplit(target)
            host = destination.hostname or ""
            login_host = (host in ("login.microsoftonline.com", "login.windows.net", "login.live.com", "aex.dev.azure.com")
                          or host.endswith(".vssps.visualstudio.com"))
            self.authentication = destination.scheme == "https" and login_host
            safe_host = host if re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) else "unrecognized host"
        except ValueError:
            self.authentication, safe_host = False, "unrecognized host"
        kind = "Microsoft sign-in redirect" if self.authentication else "unexpected redirect"
        self.args = (f"Azure {method} {path.split('?')[0]} returned HTTP {status}: {kind} to {safe_host}. "
                     "The redirect was not followed and no token was forwarded. Redirect paths, query strings and response bodies are withheld. "
                     + ("Open the organization in your browser with the selected Microsoft account and complete any required "
                        "Azure DevOps profile/organization sign-in before retrying." if self.authentication else
                        "Check the organization URL and network/proxy configuration."),)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # A login URL can contain session values. Classify it; never follow or print it.
        path = urlsplit(req.full_url).path
        raise AzureRedirectError(req.get_method(), path, code, newurl, tenant_challenge(headers))


def access_denial(error):
    return error.status in (401, 403) or isinstance(error, AzureRedirectError) and error.authentication


def azure_service_code(error):
    # Extract only a closed set of actionable service codes, never arbitrary error text.
    if error.fp is None:
        return None
    try:
        body = error.read(65536).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None  # Optional error details must not hide the original HTTP status.
    for code in ("TF401444", "TF400813", "VS30063"):
        if re.search(r"\b" + code + r"\b", body):
            return code
    return None


def tenant_challenge(headers):
    # Retain only a tenant GUID from Microsoft's fixed authentication authorities.
    # Never display the complete authentication header or arbitrary server text.
    challenge = headers.get("WWW-Authenticate", "") if headers else ""
    match = re.search(r"https://(?:login\.windows\.net|login\.microsoftonline\.com)/"
                      r"([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})(?:[/\"\s]|$)", challenge)
    return match.group(1).lower() if match else None


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
                          headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json",
                                   "Accept": "application/json", "X-TFS-FedAuthRedirect": "Suppress"})
        try:
            with build_opener(NoRedirect).open(request, timeout=60) as response:
                content = response.read((8 << 20) + 1)
                if len(content) > 8 << 20:
                    raise RuntimeError(f"Azure {method} {path.split('?')[0]} exceeded the 8MiB response budget; response withheld.")
                try:
                    return json.loads(content) if content else {}
                except (ValueError, UnicodeError):
                    raise RuntimeError(f"Azure {method} {path.split('?')[0]} returned a non-JSON response. "
                                       "Check organization browser sign-in and network/proxy access; response body withheld.") from None
        except HTTPError as error:
            if missing and error.code == 404:
                return None
            raise AzureHTTPError(method, path, error.code, tenant_challenge(error.headers), azure_service_code(error)) from None
        except (URLError, TimeoutError) as error:
            raise RuntimeError(f"Azure {method} request failed ({type(error).__name__}); check connectivity and retry.") from None


def azure_login(tenant):
    args = ["az", "login", "--allow-no-subscriptions", "--output", "none"]
    if tenant:
        args.extend(["--tenant", tenant])
    print("Sign in with the Microsoft account that opens the selected Azure DevOps organization in your browser.", flush=True)
    subprocess.run(args, check=True)


def azure_token(tenant):
    args = ["az", "account", "get-access-token", "--resource", "499b84ac-1321-427f-aa17-267ca6975798",
            "--query", "accessToken", "--output", "tsv"]
    if tenant:
        args.extend(["--tenant", tenant])
    token = command(*args, stderr=subprocess.DEVNULL)
    if not token:
        raise RuntimeError("Azure CLI returned no Azure DevOps access token; rerun bootstrap with --reauth.")
    return token


def authenticated_azure(organization, project_name, tenant=None, reauthenticate=False):
    # Read-only preflight precedes key preparation/export and all remote writes.
    Azure(organization, "")  # Validate credential destination before invoking sign-in.
    if tenant and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", tenant):
        raise ValueError("LASA_AZURE_TENANT must be a tenant ID or tenant domain, not a URL")
    if reauthenticate:
        azure_login(tenant)
    try:
        token = azure_token(tenant)
    except subprocess.CalledProcessError:
        if reauthenticate:
            raise RuntimeError("Azure CLI could not obtain an Azure DevOps token after sign-in. "
                               "Check the selected account, tenant and organization sign-in policy.") from None
        azure_login(tenant)
        try:
            token = azure_token(tenant)
        except subprocess.CalledProcessError:
            raise RuntimeError("Azure CLI could not obtain an Azure DevOps token. "
                               "Use LASA_AZURE_TENANT for the organization tenant and rerun --reauth.") from None
    attempted = set()
    while True:
        api = Azure(organization, token)
        project_error = None
        try:
            project = api.request("GET", "_apis/projects/" + quote(project_name, safe=""), missing=True)
            if project is not None:
                if project.get("visibility") != "private":
                    raise ValueError("The selected Azure project is not private; choose a private LASA_AZURE_PROJECT")
                print("Azure project access verified: " + api.base + "/" + quote(project_name, safe=""), flush=True)
                return api
        except AzureHTTPError as error:
            if not access_denial(error):
                raise
            project_error = error
        try:
            connection = api.request("GET", "_apis/connectionData")
            identity = connection.get("authenticatedUser", {})
            organization_access = bool(identity.get("id") and identity["id"] not in (
                "00000000-0000-0000-0000-000000000000", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
                                       and identity.get("isActive") is not False)
        except AzureHTTPError as error:
            if not access_denial(error):
                raise
            organization_access = False
            organization_error = error
        else:
            organization_error = None
        if organization_access:
            if project_error is None:
                return api  # Authenticated organization; configure can create the missing private project.
            raise RuntimeError(f"{project_error} The organization authenticated this login, but access to project "
                               f"'{project_name}' was denied. Sign in with its owner account or ask an organization/project "
                               "administrator to check project membership and permissions. Setup needs project, service-connection "
                               "and pipeline administration; it cannot grant itself access. "
                               "Rerun bash scripts/bootstrap-azure.sh --reauth if the cached account is wrong. "
                               "No publishing keys or pipeline configuration were changed by this preflight.") from None
        hint = (organization_error.tenant if organization_error else None) or (project_error.tenant if project_error else None)
        if hint and not tenant and not attempted:
            attempted.add(hint)
            print("Azure identified its organization tenant; checking that tenant's owner session.", flush=True)
            try:
                token = azure_token(hint)
            except subprocess.CalledProcessError:
                if not reauthenticate:
                    raise RuntimeError(f"Azure requires tenant {hint}. Rerun with "
                                       f"LASA_AZURE_TENANT={hint} bash scripts/bootstrap-azure.sh --reauth. "
                                       "Existing signing keys were not changed.") from None
                azure_login(hint)
                try:
                    token = azure_token(hint)
                except subprocess.CalledProcessError:
                    raise RuntimeError("Azure CLI could not obtain the organization-tenant token after sign-in. "
                                       "Check account membership and tenant sign-in policy.") from None
            continue
        status = project_error.status if project_error else (organization_error.status if organization_error else "unknown")
        reason = str(organization_error or project_error) if organization_error or project_error else "The organization returned no authenticated identity."
        raise RuntimeError(f"Azure organization access could not be verified (HTTP {status}): {api.base}. "
                           f"Observed response: {reason} "
                           "A cached Azure CLI token does not establish Azure DevOps membership. "
                           "Open this organization in your browser and use that same Microsoft account with "
                           "bash scripts/bootstrap-azure.sh --reauth. If access is still denied, its administrator must check "
                           "Organization settings > Users and the organization's tenant/sign-in policies. "
                           "Set LASA_AZURE_TENANT if a specific tenant is required. "
                           "No publishing keys or pipeline configuration were changed by this preflight.") from None


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
    api = authenticated_azure(organization, project, os.environ.get("LASA_AZURE_TENANT"),
                              os.environ.get("LASA_AZURE_REAUTH") == "1")
    subprocess.run(["bash", str(Path(__file__).resolve().parent / "prepare-apk-key.sh"), str(state), "jasonachkar/lasa"], check=True)
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
               "DISTRIBUTION_DEPLOY_KEY": (state / "deploy-key").read_text(),
               "APK_SIGNING_KEY": (state / "apk-signing-key.pem").read_text()}
    public = {"APT_SIGNING_FINGERPRINT": fingerprint, "APK_PUBLIC_KEY_SHA256": (state / "apk-public-key.sha256").read_text().strip(), "DISTRIBUTION_REPOSITORY": "jasonachkar/homebrew-lasa",
              "DISTRIBUTION_BRANCH": command("gh", "api", "repos/jasonachkar/homebrew-lasa", "--jq", ".default_branch"),
              "APT_REPOSITORY_URL": "https://lasa.secureobs.com/apt", "DOCS_SITE_URL": "https://lasa.secureobs.com/"}
    branch = "refs/heads/" + command("git", "branch", "--show-current")
    configure(api, project, secrets, public, branch,
              os.environ.get("LASA_AZURE_CONFIGURE_ONLY") == "1")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, KeyError, OSError, subprocess.CalledProcessError) as error:
        # CalledProcessError stores arguments; credential-bearing commands never use args for values.
        print(f"Azure bootstrap stopped: {error}", file=sys.stderr)
        sys.exit(1)
