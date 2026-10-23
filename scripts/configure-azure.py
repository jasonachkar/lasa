#!/usr/bin/env python3
"""Owner-local Azure bootstrap. Tokens stay in memory; API error bodies are redacted."""
import argparse
from base64 import b64encode
import getpass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import warnings
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


def api_version(path):
    # Match Microsoft's v7_1 SDK bindings for endpoints that require preview revisions.
    # Core/build APIs have published 7.1 contracts; each other family is versioned separately.
    resource = path.split("?", 1)[0].split("_apis/", 1)[-1].lower()
    if resource == "connectiondata" or resource.startswith(("distributedtask/", "pipelines/pipelinepermissions/")):
        return "7.1-preview.1"
    if resource.startswith("serviceendpoint/"):
        return "7.1-preview.4"
    return "7.1"


def command(*args, **kwargs):
    # Never print subprocess stdout: it can contain credentials or private keys.
    return subprocess.check_output(args, text=True, **kwargs).strip()


def cli_options(argv=None):
    parser = argparse.ArgumentParser(description="Configure LASA Azure publishing, or check access without publishing changes.")
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--check", action="store_true", default=os.environ.get("LASA_AZURE_CHECK") == "1",
                           help="read-only Azure diagnostics; no publishing state or GitHub credentials required")
    operation.add_argument("--configure-only", action="store_true", default=os.environ.get("LASA_AZURE_CONFIGURE_ONLY") == "1",
                           help="configure the pipeline without queuing a run")
    authentication = parser.add_mutually_exclusive_group()
    authentication.add_argument("--reauth", action="store_true", default=os.environ.get("LASA_AZURE_REAUTH") == "1",
                                help="open a fresh Azure CLI browser sign-in")
    authentication.add_argument("--devops-pat", action="store_true", default=os.environ.get("LASA_AZURE_DEVOPS_PAT") == "1",
                                help="use the organization owner's short-lived PAT, entered in a hidden prompt")
    options = parser.parse_args(argv)
    if options.reauth and options.devops_pat:
        parser.error("choose --reauth or --devops-pat, not both")
    if options.check and options.configure_only:
        parser.error("choose --check or --configure-only, not both")
    for name in ("check", "configure_only", "reauth", "devops_pat"):
        os.environ["LASA_AZURE_" + name.upper()] = "1" if getattr(options, name) else "0"


def github_token():
    token = os.environ.get("LASA_GITHUB_TOKEN")
    if not token:
        try:
            token = command("gh", "auth", "token", "--hostname", "github.com", stderr=subprocess.DEVNULL)
        except (OSError, subprocess.CalledProcessError):
            raise RuntimeError("GitHub credentials are unavailable. Run gh auth login --hostname github.com, "
                               "then rerun setup. No publishing keys or pipeline configuration were changed.") from None
    if not token:
        raise RuntimeError("GitHub CLI returned an empty token; authenticate with gh before setup. No publishing keys were changed.")
    return token


def verify_github_source(token, branch):
    # Verify the same credential Azure will receive, rather than a different gh session.
    environment = dict(os.environ, GH_TOKEN=token)
    path = "repos/jasonachkar/lasa/contents/azure-pipelines.yml?" + urlencode({"ref": branch})
    try:
        kind = command("gh", "api", "--hostname", "github.com", path, "--jq", ".type",
                       env=environment, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        raise RuntimeError("The GitHub credential being copied to Azure cannot read azure-pipelines.yml on the selected LASA branch. "
                           "Check that the branch is pushed and LASA_GITHUB_TOKEN (or the gh session token) has repository contents access. "
                           "No publishing keys or pipeline configuration were changed by this check.") from None
    if kind != "file":
        raise RuntimeError("GitHub did not return azure-pipelines.yml as a regular file on the selected branch. "
                           "No publishing keys or pipeline configuration were changed by this check.")


class AzureHTTPError(RuntimeError):
    def __init__(self, method, path, status, tenant=None, service_code=None, *, pat=False, version=None, validation=()):
        self.status = status
        self.tenant = tenant
        self.service_code = service_code
        self.validation = validation
        detail = ""
        if service_code == "TF401444":
            detail = " Azure DevOps requires this account to complete its first browser sign-in to the organization."
        elif service_code in ("TF400813", "VS30063"):
            detail = " Azure DevOps did not authorize this account for the requested resource."
        recovery = ("Check the Azure DevOps PAT's expiry, organization and scopes, and its owner's organization/project permissions. "
                    "Required bootstrap scopes are listed in docs/maintainer/azure.md#use-an-azure-devops-pat. " if pat else
                    "Check organization membership, project administration and token/tenant access. ")
        if status == 400:
            recovery = "Azure rejected this request during validation; check repository metadata, YAML and resource authorization. "
        elif status == 429:
            recovery = "Azure throttled this request; wait before retrying setup. "
        elif status >= 500:
            recovery = "Azure reported a service failure; check Azure DevOps service status and retry. "
        super().__init__(f"Azure {method} {path.split('?')[0]} returned HTTP {status}. "
                         + (f"API version: {version}. " if version else "")
                         + (f"Service code: {service_code}." if service_code else "") + detail + " "
                         + recovery + ("Safe validation details: " + " ".join(validation) + " " if validation else "")
                         + "The response body is suppressed to protect secrets.")


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
        if fp is not None:
            fp.close()
        raise AzureRedirectError(req.get_method(), path, code, newurl, tenant_challenge(headers))


def access_denial(error):
    return error.status in (401, 403) or isinstance(error, AzureRedirectError) and error.authentication


def azure_error_body(error):
    # Read once, with a fixed limit; helpers emit only closed classifications below.
    if error.fp is None:
        return ""
    try:
        return error.read(65536).decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return ""  # Optional error details must not hide the original HTTP status.


def azure_service_code(body):
    for code in ("TF401444", "TF400813", "VS30063"):
        if re.search(r"\b" + code + r"\b", body):
            return code
    return None


def azure_validation_details(body):
    # Never echo arbitrary server messages, quoted YAML values or exception names:
    # Azure can include request variables/keys in validation responses.
    details = []
    rules = (
        (r"\b(?:PipelineValidationException|BuildDefinitionValidationException|DefinitionValidationException)\b",
         "Azure pipeline validation failed."),
        (r"\bVssInvalidPreviewVersionException\b", "Azure requires the endpoint's preview API revision."),
        (r"\bArgumentNullException\b", "Azure reports a missing required argument."),
        (r"\bapiUrl\b", "Check repository.properties.apiUrl (the GitHub REST repository URL)."),
        (r"\bdefaultBranch\b", "Check repository.defaultBranch and repository.properties.defaultBranch."),
        (r"\bconnectedServiceId\b", "Check repository.properties.connectedServiceId (the GitHub connection ID)."),
        (r"\byamlFilename\b", "Check process.yamlFilename (azure-pipelines.yml)."),
        (r"could not (?:find|retrieve|read|load)[^\r\n]{0,200}(?:yaml|azure-pipelines)",
         "Azure could not load the pipeline YAML from the configured GitHub branch."),
        (r"(?:service connection|service endpoint)[^\r\n]{0,200}(?:not found|does not exist|not authorized|disabled)",
         "Azure could not use the GitHub service connection; check its credentials and project authorization."),
        (r"(?:not authorized|access denied|do not have permission|does not have permission)",
         "Azure reported an authorization failure during validation; check pipeline, GitHub connection and agent-queue permissions."),
        (r"(?:no hosted parallelism|parallelism[^\r\n]{0,80}(?:not been|not available|not enabled))",
         "Azure reports unavailable hosted-job capacity."),
    )
    for pattern, explanation in rules:
        if re.search(pattern, body, re.IGNORECASE):
            details.append(explanation)
    locations = re.finditer(r"azure-pipelines\.yml[^\r\n]{0,12}\(Line:\s*([0-9]{1,6}),\s*Col:\s*([0-9]{1,6})\)", body)
    for location in locations:
        point = f"YAML location: azure-pipelines.yml line {int(location[1])}, column {int(location[2])}."
        if point not in details:
            details.append(point)
        if len(details) >= 12:
            break
    return tuple(details)


def tenant_challenge(headers):
    # Retain only a tenant GUID from Microsoft's fixed authentication authorities.
    # Never display the complete authentication header or arbitrary server text.
    if headers:
        tenant = headers.get("X-VSS-ResourceTenant", "").strip()
        if re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", tenant):
            return tenant.lower()
    challenge = headers.get("WWW-Authenticate", "") if headers else ""
    match = re.search(r"https://(?:login\.windows\.net|login\.microsoftonline\.com)/"
                      r"([0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})(?:[/\"\s]|$)", challenge)
    return match.group(1).lower() if match else None


class Azure:
    def __init__(self, organization, token, *, pat=False):
        if not re.fullmatch(r"https://dev\.azure\.com/[A-Za-z0-9][A-Za-z0-9-]*/?", organization):
            raise ValueError("Organization must be an HTTPS dev.azure.com organization URL")
        self.base = organization.rstrip("/")
        self.token = token
        self.pat = pat

    def request(self, method, path, data=None, *, missing=False, version=None):
        version = version or api_version(path)
        url = self.base + "/" + path.lstrip("/")
        url += ("&" if "?" in url else "?") + "api-version=" + version
        authorization = ("Basic " + b64encode((":" + self.token).encode("ascii")).decode("ascii")
                         if self.pat else "Bearer " + self.token)
        request = Request(url, data=None if data is None else json.dumps(data).encode(), method=method,
                          headers={"Authorization": authorization, "Content-Type": "application/json",
                                   "Accept": "application/json", "X-TFS-FedAuthRedirect": "Suppress",
                                   "X-VSS-ForceMsaPassThrough": "true"})
        try:
            with build_opener(NoRedirect).open(request, timeout=60) as response:
                content = response.read((8 << 20) + 1)
                if len(content) > 8 << 20:
                    raise RuntimeError(f"Azure {method} {path.split('?')[0]} exceeded the 8MiB response budget; response withheld.")
                try:
                    result = json.loads(content) if content else {}
                except (ValueError, UnicodeError):
                    raise RuntimeError(f"Azure {method} {path.split('?')[0]} returned a non-JSON response. "
                                       "Check organization browser sign-in and network/proxy access; response body withheld.") from None
                if not isinstance(result, dict):
                    raise RuntimeError(f"Azure {method} {path.split('?')[0]} returned an unexpected JSON shape; "
                                       "expected an API object. Response body withheld.")
                return result
        except HTTPError as error:
            try:
                if missing and error.code == 404:
                    return None
                body = azure_error_body(error)
                safe_error = AzureHTTPError(method, path, error.code, tenant_challenge(error.headers), azure_service_code(body),
                                            pat=self.pat, version=version, validation=azure_validation_details(body))
            finally:
                error.close()
            raise safe_error from None
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


def read_devops_pat(organization, existing=None):
    Azure(organization, "")  # Validate before opening a browser or prompting for a secret.
    if existing:
        token = existing
    else:
        if not sys.stdin.isatty():
            raise RuntimeError("PAT mode requires an interactive terminal with hidden input, or a pre-existing "
                               "AZURE_DEVOPS_EXT_PAT from your local secret manager. Never put a PAT in command arguments or chat.")
        url = organization.rstrip("/") + "/_usersSettings/tokens"
        print("Create a short-lived PAT using the browser account that administers this organization: " + url, flush=True)
        print("Choose this organization; scopes: Project and Team (read/write/manage), Build (read/execute), "
              "Service Connections (read/query/manage), Agent Pools (read), Pipeline Resources (use/manage). "
              "The PAT is used only for this setup; revoke it afterwards. Paste it only into the hidden terminal prompt.", flush=True)
        try:
            subprocess.run(["open", url], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass  # The public URL above remains usable when no macOS browser opener is available.
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", getpass.GetPassWarning)
                token = getpass.getpass("Azure DevOps bootstrap PAT (hidden): ")
        except (EOFError, KeyboardInterrupt, OSError, getpass.GetPassWarning):
            raise RuntimeError("PAT input cancelled or hidden terminal input unavailable; no credential was saved. "
                               "Run from an interactive terminal or use your local secret manager.") from None
    if not re.fullmatch(r"[!-~]{1,4096}", token):
        raise ValueError("Invalid Azure DevOps PAT input: expected a nonempty ASCII token without spaces or control characters; value withheld.")
    return token


def authenticated_azure(organization, project_name, tenant=None, reauthenticate=False, *, personal_access_token=None):
    # Read-only preflight precedes key preparation/export and all remote writes.
    Azure(organization, "")  # Validate credential destination before invoking sign-in.
    pat_mode = personal_access_token is not None
    if pat_mode and reauthenticate:
        raise ValueError("Choose Azure CLI reauthentication or Azure DevOps PAT mode, not both")
    if not pat_mode and tenant and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", tenant):
        raise ValueError("LASA_AZURE_TENANT must be a tenant ID or tenant domain, not a URL")
    if reauthenticate:
        azure_login(tenant)
    if pat_mode:
        token = personal_access_token
    else:
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
        api = Azure(organization, token, pat=pat_mode)
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
            recovery = ("Check the PAT's project scopes and the browser owner's project permissions; "
                        "a PAT cannot grant access its owner lacks. " if pat_mode else
                        "Rerun bash scripts/bootstrap-azure.sh --reauth if the cached account is wrong. ")
            raise RuntimeError(f"{project_error} The organization authenticated this login, but access to project "
                               f"'{project_name}' was denied. Sign in with its owner account or ask an organization/project "
                               "administrator to check project membership and permissions. Setup needs project, service-connection "
                               "and pipeline administration; it cannot grant itself access. "
                               + recovery + "No publishing keys or pipeline configuration were changed by this preflight.") from None
        if pat_mode:
            reason = str(organization_error or project_error) if organization_error or project_error else "No authenticated organization identity was returned."
            raise RuntimeError(f"Azure DevOps PAT access could not be verified: {api.base}. Observed response: {reason} "
                               "Check that this short-lived PAT is unexpired, scoped to this organization and created by the browser "
                               "account that administers it, with the documented bootstrap scopes. Organization policies may restrict PATs. "
                               "A PAT cannot add membership or permissions; its owner must already have access. "
                               "Azure CLI tenant selection is not used in PAT mode. "
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
                           "If repeated CLI sign-in still fails but the browser owner has access, use --devops-pat "
                           "with that owner's short-lived Azure DevOps PAT (entered privately on this Mac). "
                           "No publishing keys or pipeline configuration were changed by this preflight.") from None


GITHUB_CONNECTION_DESCRIPTION = "Owner-configured LASA publishing connection"
GITHUB_CONNECTION_MARKER = "lasaBootstrapRepository"
GITHUB_CONNECTION_NAMES = ("LASA-GitHub", "LASA-GitHub-bootstrap")


def bootstrap_owns_connection(endpoint, project_id):
    # Markers establish operational provenance, not a permission grant. Never
    # overwrite shared, differently scoped or non-GitHub connections.
    kind, url = endpoint.get("type"), endpoint.get("url")
    if (not isinstance(kind, str) or kind.lower() != "github" or not isinstance(url, str) or url.rstrip("/") != "https://github.com"
            or endpoint.get("isShared") is not False):
        return False
    references = endpoint.get("serviceEndpointProjectReferences") or []
    if not isinstance(references, list):
        return False
    for reference in references:
        if (not isinstance(reference, dict) or not isinstance(reference.get("projectReference"), dict)
                or reference["projectReference"].get("id") != project_id):
            return False
    data = endpoint.get("data") or {}
    if not isinstance(data, dict):
        return False
    marker = data.get(GITHUB_CONNECTION_MARKER)
    if marker is not None and marker != "jasonachkar/lasa":
        return False
    return (marker == "jasonachkar/lasa" or endpoint.get("description") == GITHUB_CONNECTION_DESCRIPTION
            or any(reference.get("description") == GITHUB_CONNECTION_DESCRIPTION for reference in references))


def configure_github_connection(api, project, token):
    prefix = quote(project["id"], safe="") + "/_apis/"
    # Include failed connections and other types so name collisions do not get
    # mistaken for absence. List projections are insufficient for ownership checks.
    endpoints = api.request("GET", prefix + "serviceendpoint/endpoints?includeFailed=true").get("value")
    if not isinstance(endpoints, list) or any(not isinstance(item, dict) for item in endpoints):
        raise RuntimeError("Azure service-connection listing returned an invalid collection; response withheld.")
    candidates = {}
    for name in GITHUB_CONNECTION_NAMES:
        matches = [item for item in endpoints if item.get("name") == name]
        if len(matches) > 1:
            raise ValueError("Multiple connections use reserved name " + name + "; refusing an ambiguous update")
        if matches:
            endpoint_id = matches[0].get("id")
            if not isinstance(endpoint_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", endpoint_id):
                raise RuntimeError("Azure returned an invalid LASA service-connection ID; no credentials were replaced.")
            detail = api.request("GET", prefix + "serviceendpoint/endpoints/" + quote(endpoint_id, safe=""))
            if detail.get("id") != endpoint_id or detail.get("name") != name:
                raise RuntimeError("Azure service-connection details changed during setup; retry before replacing credentials.")
            candidates[name] = detail
    owned = next((item for item in candidates.values() if bootstrap_owns_connection(item, project["id"])), None)
    if owned:
        name = owned["name"]
    else:
        name = next((item for item in GITHUB_CONNECTION_NAMES if item not in candidates), None)
        if name is None:
            raise ValueError("Both reserved LASA GitHub connection names are occupied by connections whose ownership/scope "
                             "cannot be verified. Existing credentials were left unchanged; resolve the reserved-name conflict in this project.")
        if candidates:
            print("Existing connection metadata does not establish exclusive bootstrap ownership; creating separate " + name + ".", flush=True)
    endpoint = {"name": name, "type": "github", "url": "https://github.com",
                "authorization": {"scheme": "PersonalAccessToken", "parameters": {"accessToken": token}},
                "isShared": False, "isReady": True,
                "description": GITHUB_CONNECTION_DESCRIPTION,
                "data": {GITHUB_CONNECTION_MARKER: "jasonachkar/lasa"},
                "serviceEndpointProjectReferences": [{"projectReference": {"id": project["id"], "name": project["name"]},
                                                      "name": name, "description": GITHUB_CONNECTION_DESCRIPTION}]}
    if owned:
        endpoint["id"] = owned["id"]
        endpoint = api.request("PUT", "_apis/serviceendpoint/endpoints/" + quote(owned["id"], safe=""), endpoint)
    else:
        endpoint = api.request("POST", "_apis/serviceendpoint/endpoints", endpoint)
    if not isinstance(endpoint.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", endpoint["id"]):
        raise RuntimeError("Azure did not return a service-connection ID; pipeline creation stopped.")
    if endpoint.get("isReady") is False:
        raise RuntimeError("Azure reports that the selected LASA-GitHub connection is not ready. Check its GitHub credential and project access. "
                           "The pipeline definition was not written and the publishing provider was not switched.")
    return endpoint


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
    # Validate existing resources before creating/updating a credential-bearing connection.
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
    endpoint = configure_github_connection(api, {"id": project["id"], "name": project_name}, secrets["GH_TOKEN"])
    variables = {name: {"value": value, "isSecret": False} for name, value in public.items()}
    variables.update({name: {"value": value, "isSecret": True} for name, value in secrets.items()})
    definition.setdefault("path", "\\")
    # Follow Azure CLI's GitHub provider contract, including both branch fields and apiUrl.
    # Only YAML CI is configured; secret-bearing PR execution remains disabled in YAML.
    definition.setdefault("triggers", [{"settingsSourceType": 2, "triggerType": 2}])
    definition.update({"name": "LASA", "type": "build", "queueStatus": "enabled",
                       "queue": {"id": queues[0]["id"]}, "process": {"type": 2, "yamlFilename": "azure-pipelines.yml"},
                       "variables": variables,
                       "repository": {"id": "jasonachkar/lasa", "name": "jasonachkar/lasa", "type": "GitHub",
                                      "url": "https://github.com/jasonachkar/lasa", "defaultBranch": branch,
                                      "clean": "true", "properties": {"connectedServiceId": endpoint["id"],
                                      "apiUrl": "https://api.github.com/repos/jasonachkar/lasa", "defaultBranch": branch,
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


def check_configuration(api, project_name):
    project = api.request("GET", "_apis/projects/" + quote(project_name, safe=""), missing=True)
    if project is None:
        print("Organization access verified. The private project does not exist; normal setup will create it.", flush=True)
        return
    prefix = quote(project["id"], safe="") + "/_apis/"
    for label, path in (("hosted queues", "distributedtask/queues"),
                        ("GitHub service connections", "serviceendpoint/endpoints?type=github"),
                        ("LASA pipeline definitions", "build/definitions?name=LASA")):
        result = api.request("GET", prefix + path)
        if not isinstance(result.get("value"), list):
            raise RuntimeError("Azure GET " + prefix + path.split("?")[0] + " returned an invalid collection; response body withheld.")
        print("Read access verified: " + label, flush=True)
    print("Azure read-only checks passed. No publishing state was read or changed and no remote configuration was written. "
          "Administrative write permissions and hosted-job capacity are checked only when setup/a run needs them.", flush=True)


def main():
    # Remove injected PAT before any child process (including the browser and gh) starts.
    existing_pat = os.environ.pop("AZURE_DEVOPS_EXT_PAT", None)
    pat_mode = os.environ.get("LASA_AZURE_DEVOPS_PAT") == "1"
    reauthenticate = os.environ.get("LASA_AZURE_REAUTH") == "1"
    if pat_mode and reauthenticate:
        raise ValueError("Choose --reauth or --devops-pat, not both")
    print("Azure authentication mode: " + ("organization-owner PAT" if pat_mode else "Azure CLI"), flush=True)
    organization = os.environ.get("LASA_AZURE_ORGANIZATION", "https://dev.azure.com/jasonachkardiab")
    project = os.environ.get("LASA_AZURE_PROJECT", "LASA")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]{0,63}", project):
        raise ValueError("Invalid LASA_AZURE_PROJECT name")
    if os.environ.get("LASA_AZURE_CHECK") == "1":
        if pat_mode:
            api = authenticated_azure(organization, project, personal_access_token=read_devops_pat(organization, existing_pat))
        else:
            api = authenticated_azure(organization, project, os.environ.get("LASA_AZURE_TENANT"), reauthenticate)
        check_configuration(api, project)
        return
    state = Path.home() / "Library/Application Support/lasa-distribution/jasonachkar_lasa"
    for path in (state / "deploy-key", state / "signing-fingerprint", state / "gnupg"):
        if not path.exists():
            raise ValueError(f"Restore existing publishing state: {path}. Keys will not be regenerated.")
    fingerprint = (state / "signing-fingerprint").read_text().strip()
    if not re.fullmatch(r"[A-F0-9]{40}", fingerprint):
        raise ValueError("Invalid local signing fingerprint")
    if pat_mode:
        api = authenticated_azure(organization, project, personal_access_token=read_devops_pat(organization, existing_pat))
    else:
        api = authenticated_azure(organization, project, os.environ.get("LASA_AZURE_TENANT"), reauthenticate)
    token = github_token()  # Direct Python invocation must work without wrapper-only environment setup.
    branch = "refs/heads/" + command("git", "branch", "--show-current")
    verify_github_source(token, branch)
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
    secrets = {"GH_TOKEN": token, "APT_SIGNING_KEY": key,
               "DISTRIBUTION_DEPLOY_KEY": (state / "deploy-key").read_text(),
               "APK_SIGNING_KEY": (state / "apk-signing-key.pem").read_text()}
    public = {"APT_SIGNING_FINGERPRINT": fingerprint, "APK_PUBLIC_KEY_SHA256": (state / "apk-public-key.sha256").read_text().strip(), "DISTRIBUTION_REPOSITORY": "jasonachkar/homebrew-lasa",
              "DISTRIBUTION_BRANCH": command("gh", "api", "repos/jasonachkar/homebrew-lasa", "--jq", ".default_branch"),
              "APT_REPOSITORY_URL": "https://lasa.secureobs.com/apt", "DOCS_SITE_URL": "https://lasa.secureobs.com/"}
    configure(api, project, secrets, public, branch,
              os.environ.get("LASA_AZURE_CONFIGURE_ONLY") == "1")


if __name__ == "__main__":
    try:
        cli_options()
        main()
    except (ValueError, RuntimeError, KeyError, OSError, subprocess.CalledProcessError) as error:
        # CalledProcessError stores arguments; credential-bearing commands never use args for values.
        print(f"Azure bootstrap stopped: {error}", file=sys.stderr)
        sys.exit(1)
