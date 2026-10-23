# Azure publishing and recovery

[Maintainer index](README.md) · [Existing GitHub bootstrap](publishing.md)

## Start from the Mac

From a clean, pushed checkout containing these files:

```bash
bash scripts/bootstrap-azure.sh
```

The defaults are organization `https://dev.azure.com/jasonachkardiab`, private project `LASA`, pipeline `LASA`, source `jasonachkar/lasa`, and public distribution `jasonachkar/homebrew-lasa`. The command installs missing Azure CLI, GitHub CLI, GnuPG and Python tools through the existing Homebrew installation. It opens account sign-in when required, creates/reuses the project and GitHub service connection, installs encrypted pipeline secrets, authorizes only this pipeline to use its connection, switches the publishing provider, and queues the current branch. It does not merge a feature branch. Pushes to `main` subsequently trigger verification and releases automatically.

Use `--configure-only` to avoid queuing and `--reauth` to open a fresh Azure sign-in without logging out other cached accounts. The flags can be combined. `LASA_AZURE_ORGANIZATION` and `LASA_AZURE_PROJECT` override the organization/project; `LASA_AZURE_TENANT` selects its tenant ID/domain when required. Azure project/organization access is checked before preparing, registering or exporting publishing keys. The source, distribution and domain are intentionally fixed to this deployment. The bootstrap checks the checkout matches its remote branch before configuring anything. Existing keys are reused from `~/Library/Application Support/lasa-distribution/jasonachkar_lasa`; a missing state backup stops setup rather than rotating keys and breaking installations. It does not change DNS, nameservers, or the unrelated `cybersecurity-writeups` repository or `docs.jasonachkardiab.com` domain.

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

The bootstrap uses Azure CLI's owner login with the Azure DevOps audience, over TLS, to administer the selected organization/project. It uses the owner's existing local GitHub CLI session for setup. By default it copies that session's GitHub token into the encrypted Azure GitHub connection and encrypted `GH_TOKEN` pipeline variable. That token retains its existing account scopes; it is not automatically restricted to LASA. For least privilege, set `LASA_GITHUB_TOKEN` locally to a dedicated token authorized for source checkout, tags, releases and build statuses for this repository, including organization SSO where required. Never put it in a command committed to Git or paste it into chat. The owner CLI session still sets the repository publishing-provider variable. Expired/revoked tokens require rerunning bootstrap with a usable session/token.

Encrypted Azure pipeline variables are `GH_TOKEN`, `APT_SIGNING_KEY`, `APK_SIGNING_KEY` and `DISTRIBUTION_DEPLOY_KEY`. Signing/deploy material is copied from local private state. Public variables contain the fingerprint, destination branch and APT/docs URLs. No GoDaddy credentials are copied into Azure. Anyone able to run arbitrary code with these secrets could sign packages and publish the distribution; limit project/pipeline administration accordingly. The script sends secret JSON directly from memory over HTTPS, suppresses API error bodies, and does not write credential payload files. Azure log masking is supplementary protection, not permission to print secrets.

Azure releases have an OpenPGP-signed `SHA256SUMS.asc`, not GitHub Actions OIDC attestations. The public key included in the release is a convenience; consumers must authenticate its fingerprint independently. GitHub-origin releases continue to require GitHub attestation verification. The retry path detects an existing GitHub-origin release without a detached signature and requires GitHub attestation verification instead. A present detached signature must verify against the configured fingerprint; verification failures never fall back to another policy.

## Costs, consent and failure recovery

An Azure DevOps organization does not guarantee free hosted parallel jobs. Microsoft may require a hosted-agent grant or billing; account verification and provider approval cannot be supplied by a Bash script. Project creation and pipeline/service-connection administration require appropriate organization permissions. GitHub OAuth/SSO consent, macOS administrator prompts and Azure browser sign-in remain owner actions. These are the only intended interactive boundaries; the script automates repository/project configuration and secret copying. No cloud-side deployment is claimed merely because the files or local tests exist.

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
