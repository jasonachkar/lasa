# Azure publishing and recovery

[Maintainer index](README.md) · [Existing GitHub bootstrap](publishing.md)

## Start from the Mac

For a complete release without Azure or GitHub Actions build runners, use [local deployment](local-deployment.md). The steps below describe the optional Azure provider.

From a clean, pushed checkout containing these files:

```bash
bash scripts/bootstrap-azure.sh
```

The defaults are organization `https://dev.azure.com/jasonachkardiab`, private project `LASA`, pipeline `LASA`, source `jasonachkar/lasa`, and public distribution `jasonachkar/homebrew-lasa`. The command installs missing Azure CLI, GitHub CLI, GnuPG and Python tools through the existing Homebrew installation. It opens account sign-in when required, creates/reuses the project and GitHub service connection, installs encrypted pipeline secrets, authorizes only this pipeline to use its connection, switches the publishing provider, and queues the current branch. It does not merge a feature branch. Pushes to `main` subsequently trigger verification and releases automatically.

The wrapper prints the checked-out bootstrap revision and the Python script prints its selected authentication mode. `--reauth` is spelled with two hyphens and `reauth` in that order. A mismatch with the remote branch asks you to pull remote changes or push your intended commit before setup.

The preferred GitHub service connection is `LASA-GitHub`. When an existing connection with that name cannot be safely identified as bootstrap-owned, setup creates an independent `LASA-GitHub-bootstrap` connection and uses its ID in the LASA pipeline. See [connection retry recovery](#recover-from-a-service-connection-ownership-error).

Use `--configure-only` to avoid queuing and `--reauth` to open a fresh Azure sign-in without logging out other cached accounts. Those flags can be combined. Alternatively, use [`--devops-pat`](#use-an-azure-devops-pat) when the browser owner can access DevOps but CLI sign-in repeatedly fails; this mode skips Azure CLI and tenant selection. It can be combined with `--configure-only`, but not `--reauth`. `LASA_AZURE_ORGANIZATION` and `LASA_AZURE_PROJECT` override the organization/project; `LASA_AZURE_TENANT` selects its tenant ID/domain in CLI mode only. Azure project/organization access is checked before preparing, registering or exporting publishing keys. The source, distribution and domain are intentionally fixed to this deployment. The bootstrap checks the checkout matches its remote branch before configuring anything. Existing keys are reused from `~/Library/Application Support/lasa-distribution/jasonachkar_lasa`; a missing state backup stops setup rather than rotating keys and breaking installations. It does not change DNS, nameservers, or the unrelated `cybersecurity-writeups` repository or `docs.jasonachkardiab.com` domain.

## Publish the website immediately without a build runner

```bash
bash scripts/publish-docs-local.sh
```

This first runs the owner-local [HTTPS repair](publishing.md#repair-an-http-only-documentation-site), then builds and pushes the customer MkDocs site from the Mac using the saved distribution deploy key. It uses no source-repository Actions minutes, Go compiler, Linux host, Docker or Azure agent. GitHub Pages still needs to build/serve the public distribution branch, and its HTTPS certificate must be valid. The command checks the served version index and build identity over verified HTTPS; a push followed by a certificate/deployment timeout is reported as incomplete. Rerun after resolving the reported Pages issue; no key reset is needed. The default page opens the maintained **Current documentation** channel. Documentation-only updates refresh `latest` immediately; numbered release versions remain available. The publisher migrates the former channel and retains bookmarked URLs as redirects.

## Pipeline behavior

`azure-pipelines.yml` uses an Ubuntu 24.04 Microsoft-hosted agent and pinned Go 1.27.2/Python 3.12. It first validates and publishes public documentation, independently of scanner builds. It then runs Go formatting, vet, unit/race checks, static analysis, dependency policy, the live official vulnerability check, fuzz smoke tests, reproducibility checks, SBOM/package generation, real signed APT integration, bootstrap/version/domain tests and shell linting. The ARM64 binary is cross-compiled; this pipeline does not run ARM64 binaries or privileged eBPF attachment. Dedicated kernel validation remains a separate requirement.

Only `main` runs `release-from-azure.sh`. Trusted branch runs publish current product documentation and verify code. There is no automatic Azure PR trigger: secret-bearing YAML must only run for trusted owner-reviewed branches. Restrict pipeline edit/queue permissions and review changes to YAML/scripts before merging. Microsoft-hosted agents are ephemeral; the pipeline does not install a persistent agent on the Mac.

Stable versions come from the highest reachable `vMAJOR.MINOR.PATCH` tag and conventional commits: first `0.1.0`, `feat:` increments minor, `BREAKING CHANGE:` or `type!:` increments major, other changes increment patch. Versions are injected into binaries without committing generated version files. Tags are never moved. A queued older commit fails if `main` has advanced. Main pushes are batched, and the publishing stage uses `lockBehavior: sequential` to serialize publishing runs, including manual queues, using Azure's stage lock. The bootstrap does not queue a duplicate active run. The package publisher also rejects conflicting immutable artifacts and non-fast-forward branch pushes. Keep other providers and local package publishers stopped during release publication.

Successful verification builds Linux AMD64 and ARM64 binaries, DEBs, archives, licenses and SBOMs. A draft release may be repaired after an interruption; published assets are reused rather than overwritten. The checksum manifest is signed by the existing APT key. Matching stable docs publish before APT indexing, so an indexing failure does not withhold them. The distribution publisher verifies provenance and hashes, updates signed APT indexes and the Linux Homebrew formula, pushes the existing public branch, and waits for the exact signed index to be served. Mike preserves packages, formula, CNAME and older documentation versions. An older docs release cannot replace a newer stable alias.

## Credentials and permissions

The bootstrap uses Azure CLI's owner login with the Azure DevOps audience, or an explicitly selected owner PAT, over TLS, to administer the selected organization/project. It uses the owner's existing local GitHub CLI session for setup. By default it copies that session's GitHub token into the encrypted Azure GitHub connection and encrypted `GH_TOKEN` pipeline variable. That token retains its existing account scopes; it is not automatically restricted to LASA. For least privilege, set `LASA_GITHUB_TOKEN` locally to a dedicated token authorized for source checkout, tags, releases and build statuses for this repository, including organization SSO where required. Never put it in a command committed to Git or paste it into chat. The owner CLI session still sets the repository publishing-provider variable. Expired/revoked tokens require rerunning bootstrap with a usable session/token.

Encrypted Azure pipeline variables are `GH_TOKEN`, `APT_SIGNING_KEY`, `APK_SIGNING_KEY` and `DISTRIBUTION_DEPLOY_KEY`. Signing/deploy material is copied from local private state. Public variables contain the fingerprint, destination branch and APT/docs URLs. No GoDaddy credentials are copied into Azure. Anyone able to run arbitrary code with these secrets could sign packages and publish the distribution; limit project/pipeline administration accordingly. The script sends secret JSON directly from memory over HTTPS, suppresses API error bodies, and does not write credential payload files. Azure log masking is supplementary protection, not permission to print secrets.

Azure releases have an OpenPGP-signed `SHA256SUMS.asc`, not GitHub Actions OIDC attestations. The public key included in the release is a convenience; consumers must authenticate its fingerprint independently. GitHub-origin releases continue to require GitHub attestation verification. The retry path detects an existing GitHub-origin release without a detached signature and requires GitHub attestation verification instead. A present detached signature must verify against the configured fingerprint; verification failures never fall back to another policy.

## Use an Azure DevOps PAT

Use this path for a persistent CLI `TF400813`/HTTP 401 or 403 when the organization opens successfully under its actual owner in the browser. A personal Microsoft account and a work account can share the same displayed email while representing different identities. Repeating sign-in with an unauthorized CLI identity does not change its DevOps permissions.

From anywhere inside the clean, pushed checkout on the Mac:

```bash
git pull --ff-only
bash "$(git rev-parse --show-toplevel)/scripts/bootstrap-azure.sh" --devops-pat
```

The script opens the organization's [Personal access tokens page](https://dev.azure.com/jasonachkardiab/_usersSettings/tokens). Sign in with the account that administers this organization. Create an organization-specific bootstrap token, choose a short expiration, and select **Custom defined** scopes (expand **Show all scopes** where necessary):

| Scope | Access needed | Bootstrap use |
| --- | --- | --- |
| Project and Team | Read, write & manage (`vso.project_manage`) | Read the private project or create it if missing |
| Build | Read & execute (`vso.build_execute`) | Read/create/update the YAML pipeline and queue a run |
| Service Connections | Read, query & manage (`vso.serviceendpoint_manage`) | Create/reuse the LASA GitHub connection |
| Agent Pools | Read (`vso.agentpools`) | Locate the existing Microsoft-hosted project queue |
| Pipeline Resources | Use & manage (`vso.pipelineresources_manage`) | Authorize this pipeline's connection and queue |

Paste the newly issued token **only into the hidden local terminal prompt**. No token is needed in chat, a command argument, a committed file or a pipeline variable. Credential issuance requires the authorized browser account; the script cannot mint a PAT using the identity Azure has already rejected. Organization policy may restrict PAT creation, scope availability or lifetime. Such policy and missing membership/roles must be resolved by the organization administrator; a PAT inherits its owner's permissions and cannot grant access.

This mode does not install or invoke Azure CLI and ignores `LASA_AZURE_TENANT`. It uses Basic authentication over verified HTTPS to the validated organization only. Authenticated redirects are blocked. The same read-only project/organization preflight runs before key preparation/export or remote configuration writes. Read access verifies identity/access; later administration operations can still fail if their required scope or owner role is missing, and the diagnostic names the rejected API operation and status.

The PAT stays in bootstrap process memory and is not saved to local state, GitHub secrets, the Azure GitHub service connection or Azure pipeline variables. Those retain the separate GitHub/signing/deploy credentials described above. If supplied by an existing local secret-manager integration, `AZURE_DEVOPS_EXT_PAT` is accepted only in explicit PAT mode; the wrapper withholds it from Git, Homebrew and GitHub CLI and Python removes it from its environment before starting any child process. Interactive input requires a terminal and refuses an echoing fallback. Do not type an environment assignment containing the PAT into shell history.

After successful setup, revoke this bootstrap PAT on the same browser page; the pipeline does not depend on it. Keep the separate GitHub credential valid for source/release access. Interrupted or failed setup can be retried with a valid bootstrap PAT without rotating the saved signing/deploy keys. PAT-denial diagnostics do not loop through CLI sign-in or tenant retries.

## Diagnose access without publishing changes

From anywhere inside the checkout:

```bash
bash "$(git rev-parse --show-toplevel)/scripts/bootstrap-azure.sh" --check --devops-pat
```

For the existing CLI session, omit `--devops-pat`; add `--reauth` only when you want fresh CLI sign-in. `--check` sends only GET requests to Azure: it verifies project/organization access and reads the queue, GitHub connection and LASA build-definition collections. It does not read publishing keys, prepare Alpine keys, authenticate GitHub, create/update resources, queue builds or switch publishing providers. It works without the private publishing state and without a clean/pushed checkout. The wrapper may install missing local Azure/Python tools through Homebrew. Read-only success does not prove write permissions or available hosted parallel jobs. The failed operation, HTTP status and API revision identify where a check stops; response bodies and credentials remain withheld.

Both entrypoints now accept the same flags. With prerequisites already installed, these commands also work directly from `scripts/`:

```bash
python3 configure-azure.py --check --devops-pat
python3 configure-azure.py --devops-pat
```

Direct Python invocation does not install tools or perform the wrapper's Git checkout verification; use a clean, pushed checkout for normal setup. It reads the existing GitHub CLI token when `LASA_GITHUB_TOKEN` is unset, before key preparation/export. A missing GitHub credential gets an explicit authentication diagnostic. Running `python3 configure-azure.py` **without flags** still selects Azure CLI authentication, so it does not exercise PAT recovery.

The HTTP client follows [Microsoft's Python SDK authentication headers](https://github.com/microsoft/azure-devops-python-api/blob/86c9a559fc4ab309df21e674b236a542f9e77f89/azure-devops/azure/devops/client.py), including `X-VSS-ForceMsaPassThrough: true` for personal Microsoft accounts and federated-redirect suppression. It uses the SDK's `7.1-preview.1` connection/agent-queue/pipeline-permission revisions and `7.1-preview.4` service-endpoint revision; published core/build contracts use `7.1`. These API revision names describe Azure's endpoints, not LASA's product status. The client accepts a tenant GUID from Azure's `X-VSS-ResourceTenant` header as well as the trusted Microsoft `WWW-Authenticate` challenge. Explicit tenant choices still take precedence, and PAT mode never retries through CLI tenants.

HTTP 400 identifies request validation, which can include repository metadata, YAML or resource authorization; it does not by itself identify an incorrect API version. HTTP 429 identifies throttling and 5xx a service failure. Invalid JSON shapes produce a bounded, redacted API diagnostic. Missing, rejected and redirected HTTP responses close their underlying streams. Before updating a GitHub service connection, normal setup validates the hosted queue and refuses to overwrite an unrelated existing pipeline.

## Recover from build-definition HTTP 400

An error at `POST PROJECT_ID/_apis/build/definitions` means organization/project authentication and the preceding service-connection request succeeded, but Azure rejected pipeline creation. Keep the same usable bootstrap credential and saved signing state; resetting trust keys does not repair this request.

The GitHub provider metadata follows [Microsoft's Azure CLI pipeline builder](https://github.com/Azure/azure-devops-cli-extension/blob/429a129a69306ae7377684b00660dd3521a126ea/azure-devops/azext_devops/dev/pipelines/pipeline_create.py):

| Definition field | LASA value |
| --- | --- |
| `repository.id` / `repository.name` | `jasonachkar/lasa` |
| `repository.type` | `GitHub` |
| `repository.url` | `https://github.com/jasonachkar/lasa` |
| `repository.defaultBranch` and `repository.properties.defaultBranch` | The same selected `refs/heads/...` branch |
| `repository.properties.apiUrl` | `https://api.github.com/repos/jasonachkar/lasa` |
| `repository.properties.connectedServiceId` | The created/reused LASA-GitHub connection ID |
| `process` | Type `2`, file `azure-pipelines.yml` |
| `path` for a new definition | Root folder `\` |

Earlier bootstrap revisions omitted the provider's `apiUrl` and branch property. Updating this checkout repairs the payload on retry. New definitions explicitly use the YAML CI trigger; the YAML limits it to trusted `main` and disables PR runs. Existing definition revisions, folders and trigger settings are preserved on update. A connection that explicitly reports `isReady: false` stops before a pipeline-definition write/provider switch.

Before preparing/exporting publishing keys, normal setup now verifies that the exact GitHub token being copied to Azure can read `azure-pipelines.yml` on the selected pushed branch, using the explicit `github.com` host. This detects a dedicated `LASA_GITHUB_TOKEN` whose access differs from the owner's default GitHub session. This check establishes repository contents access; Azure's provider authorization and webhook policies can impose additional requirements.

For further validation failures, the error retains fixed classifications and known field names such as `repository.properties.apiUrl`, plus `azure-pipelines.yml` line/column locations when Azure supplies them. It can identify missing arguments, pipeline validation, unavailable YAML, connection authorization and hosted-job capacity. It never prints arbitrary messages, quoted YAML values, token/key material or raw response bodies. Unrecognized details stay suppressed rather than being guessed or echoed. Error reads remain bounded to 64 KiB and do not bypass a failed validation.

## Recover from a service-connection ownership error

Earlier revisions required the top-level `description` in Azure's connection listing to exactly match the bootstrap's description. That was too narrow: list responses can omit metadata, and the API also models the description inside `serviceEndpointProjectReferences`. A retry could therefore stop with “was not created by this bootstrap” after a successful earlier connection creation.

Update the checkout and rerun the same bootstrap command with a valid owner credential. No deletion, credential reset or manual ownership override is needed for the normal retry path:

- Setup lists existing connections, including failed connections and other types, then fetches project-scoped details for the reserved LASA names.
- An update requires the public GitHub URL, GitHub type, explicit non-shared status, compatible project references and a recognized bootstrap marker. It recognizes the legacy top-level description, the matching project's description, or the `data.lasaBootstrapRepository=jasonachkar/lasa` marker. Conflicting repository markers, different project references and shared connections are not updated.
- Newly created/updated connections include the marker and both description locations. A recognized failed connection can receive the owner's current GitHub credential on retry.
- If the existing `LASA-GitHub` connection has missing or unrecognized provenance, it remains untouched. Setup creates a separate `LASA-GitHub-bootstrap` connection, configures the pipeline to use it, and reuses that connection on subsequent retries. It does not keep creating new connections after each failed pipeline-definition request.
- Duplicate reserved names, changing connection details, malformed IDs or both names being occupied by unverifiable connections stop with an explicit diagnostic before replacing credentials. Ownership markers are operational metadata, not an authorization boundary or a substitute for Azure permissions.

The original connection may remain in the project after automatic recovery; the bootstrap does not delete it or change its credentials. Only the selected LASA connection and hosted queue are authorized for this pipeline. Publishing signing/deploy keys retain their existing identities.

## Costs, consent and failure recovery

An Azure DevOps organization does not guarantee free hosted parallel jobs. Microsoft may require a hosted-agent grant or billing; account verification and provider approval cannot be supplied by a Bash script. Project creation and pipeline/service-connection administration require appropriate organization permissions. GitHub OAuth/SSO consent, macOS administrator prompts, Azure browser sign-in and optional PAT issuance remain owner actions; the script automates repository/project configuration and secret copying. No cloud-side deployment is claimed merely because the files or local tests exist.

If Azure reports no hosted parallelism or leaves a run queued, use the local docs command immediately, then enable hosted capacity in the organization. The bootstrap does not buy capacity or bypass policy. If sign-in chooses the wrong tenant, sign in to the organization tenant with Azure CLI and rerun. If service connection or secret permissions fail, the error identifies the operation and HTTP status without dumping credentials. Existing unrelated pipelines/connections are protected against name collisions.

The bootstrap sets source repository variable `PUBLISHING_PROVIDER=azure` only after Azure configuration and endpoint authorization succeed. GitHub automatic release and docs publication jobs then stop publishing, preventing duplicate publishers when Actions minutes reset. GitHub verification jobs remain available. If the first Azure queue fails after the switch, rerun bootstrap or use the local docs command; the switch is intentionally preserved for recovery. To return to GitHub publishing, set that variable to `github` after stopping Azure publication; existing GitHub release-environment secrets remain intact. Avoid switching while a release is running.

Interrupted runs can leave a draft release or an already pushed Pages commit. Rerun the same commit to reuse its version. If a release was published but its package deployment failed, retry the run for that commit while it is still `main`; the publisher downloads and verifies its original bytes. A new main commit gets its own version. Do not reset keys, force-push distribution history, delete published assets or relax TLS verification as a retry strategy. Previously GitHub-built releases retain GitHub provenance verification on retry.

## Validation scope

Repository tests exercise real MkDocs/Mike publishing, current/release alias behavior and preservation of package/domain trees. Azure contract tests mock service boundaries to check encrypted variable payloads, connection/pipeline reuse, restricted endpoint authorization, duplicate-run avoidance and failures before provider switching. Local integration tests exercise OpenPGP signatures and APT verification. Live Azure authentication, hosted-agent allocation, GitHub service hooks and public HTTPS deployment require the owner's account and are not established by mocked tests.

## Website presentation

The site uses MkDocs Material with LASA's own styles in `docs/website/assets/site.css` and header, navigation and footer overrides in `docs/theme/partials/`. `mkdocs.yml` keeps **Start here**, **Use LASA**, and **Trust and scope** together in the left navigation on every page; top-level tabs are disabled. The right rail contains the page outline. Narrow screens use Material's navigation drawer with the same complete navigation tree, rather than drilling into one section at a time. The landing page cards stack into one column. Dark mode is the default; an explicit light-mode choice remains available and is remembered. The header has no version/environment selector. Numbered documentation URLs and automated versioning remain intact. The footer keeps compact previous/next navigation and third-party notices. `docs/theme/main.html` places it inside the article column so it does not span beneath or reduce either sidebar; the desktop navigation rail retains the full viewport height below the header. Search, theme switching and code copying use the pinned theme's components. `docs/website/assets/site.js` adds the Ctrl+K / Command+K search shortcut and synchronizes the navigation control's expanded state. Header controls expose button semantics; the script handles Enter/Space activation once, without duplicating the theme's delegated Enter handler. Sidebar groups use native, keyboard-accessible disclosure elements and start expanded. Fonts, icons, styles and search assets are served locally; the redesign introduces no third-party requests.

The visual reference is the owner's [ModelFence documentation source](https://github.com/jasonachkar/modelFence/tree/features/product-completion/docs-site) at revision `5a070ef930aaeaa4b8ccc29f237c7074faea6234`: its Starlight violet palette, dark surfaces, typography, sidebar tree, landing-page workflow cards and linked topic cards are adapted to MkDocs. The LASA header and all page URLs remain local to LASA. Unlike ModelFence's splash template, the LASA homepage retains the complete sidebar requested for every page. No Astro/Node dependency is added to LASA publishing. Theme changes trigger the GitHub docs workflow through its `docs/theme/**` path filter, and Azure/local publication builds the same configuration. Numbered documentation archives are preserved; the maintained channel is titled **Current documentation**. A current-docs update refreshes the default site even when no new scanner release is being published.


## Additional Linux package repositories

Rerun the updated `bash scripts/bootstrap-azure.sh` from a clean pushed checkout to configure the additional Alpine RSA key and pin without resetting existing OpenPGP/deploy keys. The pipeline builds/signs/indexes DEB, RPM, Pacman and APK packages and retains the Homebrew tap. Native package-client integration runs in isolated containers on the Linux runner; no Linux machine or Docker installation is required on the Mac. See [native distribution design](linux-distribution.md). Stable releases remain restricted to `main`; a feature-branch bootstrap queues verification/current docs only.


## Recover from an Azure project HTTP 403

A successful GitHub `APK_SIGNING_KEY` setup is separate from Azure authorization. Keep the saved keys and state directory. A token issued by Azure CLI can be valid while its cached account/tenant has no access to the DevOps organization or the private LASA project.

From the clean updated checkout on the Mac:

```bash
git pull --ff-only
bash scripts/bootstrap-azure.sh --reauth
```

Choose the same Microsoft account that can open `https://dev.azure.com/jasonachkardiab` in the browser. This opens fresh Azure sign-in without clearing other cached accounts. When the trusted Microsoft authentication challenge identifies a different organization tenant, the preflight checks that tenant's cached session once. With `--reauth` it can open the required tenant sign-in. An explicit `LASA_AZURE_TENANT` is always honored; the script does not replace it silently.

If Azure provides a tenant ID but no usable cached session, the diagnostic prints a local command using that non-secret tenant ID. Do not paste access tokens into chat or put them in command arguments. The preflight sends credentials only to the validated Azure DevOps organization and does not follow authenticated redirects. It retains only a tenant GUID from recognized Microsoft authentication authorities; headers and response bodies stay suppressed.

A persistent denial is an account/authorization boundary:

- If CLI sign-in still reports `TF400813`/401 after choosing the intended tenant, but the browser owner can administer this organization, use [the PAT mode](#use-an-azure-devops-pat). Do not reset publishing keys or repeatedly select subscriptions.
- If the organization cannot authenticate this login, its administrator must check **Organization settings → Users**, the account's membership, linked tenant and sign-in policies. An Azure subscription/account login by itself does not grant DevOps membership.
- If the organization authenticates the login but project access is denied, check the selected **LASA** project membership and permissions. Full bootstrap needs project creation/administration where applicable, service-connection administration, pipeline administration and resource authorization. Project Administrators normally covers project-level setup; organization policies can impose additional restrictions.
- If a different project name is intended, set `LASA_AZURE_PROJECT` to that private project's actual name. A missing project is created only after organization authentication is verified; a forbidden project is never treated as absent.

No automatic membership/role grants or policy changes are attempted. Authentication failure stops before publishing key updates, secret export, pipeline mutation or publisher switching. A later API permission failure still names the rejected operation/status. The tests cover read-only preflight, project/organization denial, missing/anonymous access, explicit sign-in, tenant hints/override, redaction and non-authentication failures. Live authorization must be verified by the owner's account.

### A subscription choice changes 403 into a sign-in redirect

A tenant-level account is sufficient for Azure DevOps; no paid Azure subscription is required. Choosing an Azure subscription selects CLI context, not DevOps organization membership. An organization-named tenant and a changed HTTP response are not proof of authorized project access.

To use a particular tenant without accidentally selecting an unrelated default subscription:

```bash
LASA_AZURE_TENANT=YOUR_ORGANIZATION_TENANT_ID bash scripts/bootstrap-azure.sh --reauth
```

The API client now sends `Accept: application/json` and `X-TFS-FedAuthRedirect: Suppress`. This asks Azure for a machine-readable authentication failure instead of a browser sign-in redirect. Redirects are still blocked: tokens are never forwarded to the destination. The error classifies known Microsoft sign-in hosts without displaying redirect paths, query strings, session values or response bodies. Unexpected redirects remain fatal and do not trigger authentication retries.

If Azure ignores suppression, a Microsoft sign-in redirect is handled as an authentication failure during the read-only preflight, never as a missing project. Open the organization URL once in the browser using the intended Microsoft identity and complete any required DevOps profile/organization sign-in. A personal and a work account can share a displayed email address; use the identity that actually opens the organization. Provider profile/terms acceptance cannot be supplied by a script.

Known API codes are retained through a closed allowlist: `TF401444` identifies the required initial browser sign-in; `TF400813` and `VS30063` indicate authorization failure. Other body text stays withheld. HTML/sign-in responses and oversized responses get explicit diagnostics instead of raw JSON parser failures. If access still fails after browser sign-in, check the organization's linked tenant, account membership and sign-in/API policies with its administrator. Existing signing keys remain unchanged on every failed preflight.
