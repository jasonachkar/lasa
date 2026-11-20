#!/usr/bin/env python3
"""Plan and verify LASA's private GitHub settings through the active gh login."""

import argparse
import json
import os
import re
import subprocess
import sys


REPO = "jasonachkar/lasa"
ROOT = f"repos/{REPO}"
GATE = "LASA verification gate"
PIN_ROLES = [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]
ENV_POLICY = {"protected_branches": False, "custom_branch_policies": True}


class SettingsError(Exception):
    pass


class APIError(SettingsError):
    def __init__(self, path, status, detail):
        super().__init__(f"{path}: HTTP {status or 'unknown'}")
        self.status = status
        self.detail = detail


def api(endpoint, method="GET", body=None):
    command = ["gh", "api", "--hostname", "github.com", "--method", method, endpoint]
    if body is not None:
        command += ["--input", "-"]
    result = subprocess.run(
        command, input=json.dumps(body) if body is not None else None,
        capture_output=True, text=True, check=False,
        env={**os.environ, "GH_PROMPT_DISABLED": "1"},
    )
    if result.returncode:
        match = re.search(r"\(HTTP (\d{3})\)", result.stderr)
        raise APIError(endpoint, int(match[1]) if match else None, result.stderr)
    return json.loads(result.stdout) if result.stdout.strip() else None


def repository():
    repo = api(ROOT)
    if repo["full_name"] != REPO or repo["visibility"] != "private" or not repo["private"]:
        raise SettingsError("expected the private jasonachkar/lasa repository")
    if repo["default_branch"] != "main" or not repo["permissions"]["admin"]:
        raise SettingsError("expected main and the repository administrator's login")
    return repo


class Changes:
    def __init__(self, mode):
        self.mode = mode
        self.pending = 0

    def require(self, matches, method, path, body=None, verified=None):
        if matches:
            return
        self.pending += 1
        if self.mode == "verify":
            print(f"DRIFT: {path}")
            return
        payload = "" if body is None else " " + json.dumps(body, sort_keys=True)
        print(f"{method} {path}{payload}", flush=True)
        if self.mode == "apply":
            repository()
            api(path, method, body)
            if not verified():
                raise SettingsError(f"read-back check failed for {path}")


def alert_enabled():
    try:
        api(f"{ROOT}/vulnerability-alerts")
    except APIError as error:
        if error.status == 404 and "Vulnerability alerts are disabled" in error.detail:
            return False
        raise
    return True


def ruleset_spec(name, target, include, rules, actors=()):
    return dict(name=name, target=target, enforcement="active", bypass_actors=list(actors),
                conditions={"ref_name": {"include": [include], "exclude": []}},
                rules=rules)


def ruleset(changes, desired, *, replace_id=None):
    endpoint = f"{ROOT}/rulesets"
    entries = [entry for entry in api(endpoint + "?includes_parents=false")
               if (entry["id"] == replace_id if replace_id is not None
                   else entry["name"] == desired["name"])]
    if len(entries) > 1:
        raise SettingsError(f"ambiguous repository ruleset: {desired['name']}")

    def matches(actual):
        return all(actual.get(key) == value for key, value in desired.items() if key != "rules") and (
            {r["type"]: r.get("parameters") for r in actual["rules"]}
            == {r["type"]: r.get("parameters") for r in desired["rules"]})

    if entries:
        entry_path = f"{endpoint}/{entries[0]['id']}"
        actual = api(entry_path)
        if not matches(actual) and replace_id is None:
            raise SettingsError(f"review drifted ruleset before replacing it: {desired['name']}")
        changes.require(matches(actual), "PUT", entry_path, desired, lambda: matches(api(entry_path)))
    elif replace_id is not None:
        raise SettingsError("expected existing legacy ruleset")
    else:
        def check_created():
            updated = [entry for entry in api(endpoint + "?includes_parents=false")
                       if entry["name"] == desired["name"]]
            return len(updated) == 1 and matches(api(f"{endpoint}/{updated[0]['id']}"))

        changes.require(False, "POST", endpoint, desired, check_created)


def baseline(changes):
    repo = repository()
    for workflow in ("version.yml", "privileged.yml"):
        path = f"{ROOT}/actions/workflows/{workflow}"
        # GitHub retains deleted workflows as inventory entries.
        state = api(path)["state"]
        changes.require(state in {"disabled_manually", "deleted"}, "PUT", path + "/disable",
                        verified=lambda: api(path)["state"] == "disabled_manually")

    path = f"{ROOT}/actions/permissions"
    actual = api(path)
    if not actual["enabled"]:
        raise SettingsError("Actions are disabled; inspect before enabling")
    desired = {"enabled": True, "allowed_actions": actual["allowed_actions"], "sha_pinning_required": True}
    changes.require(actual.get("sha_pinning_required") is True, "PUT", path, desired,
                    lambda: all(api(path).get(k) == v for k, v in desired.items()))

    path = f"{ROOT}/actions/permissions/workflow"
    desired = {"default_workflow_permissions": "read", "can_approve_pull_request_reviews": False}
    changes.require(api(path) == desired, "PUT", path, desired, lambda: api(path) == desired)
    fork_policy = api(f"{ROOT}/actions/permissions/fork-pr-workflows-private-repos")
    if any(fork_policy[k] for k in ("run_workflows_from_fork_pull_requests", "send_secrets_and_variables",
                                   "send_write_tokens_to_workflows")):
        raise SettingsError("unexpected private fork policy; review before changing")
    if api(f"{ROOT}/actions/permissions/access")["access_level"] != "none":
        raise SettingsError("external Actions access is enabled; review before changing")
    if api(f"{ROOT}/actions/runners")["total_count"]:
        raise SettingsError("registered self-hosted runners require explicit review")

    environment = f"{ROOT}/environments/release"
    def env_matches():
        current = api(environment)
        return current.get("deployment_branch_policy") == ENV_POLICY and not current["can_admins_bypass"]

    current = api(environment)
    if any(rule["type"] != "branch_policy" for rule in current["protection_rules"]):
        raise SettingsError("existing deployment protection rules require review")
    if current.get("deployment_branch_policy") not in (None, ENV_POLICY):
        raise SettingsError("unexpected deployment policy; review before replacing")
    changes.require(env_matches(), "PUT", environment,
                    {"deployment_branch_policy": ENV_POLICY, "can_admins_bypass": False}, env_matches)
    policies = environment + "/deployment-branch-policies"

    def main_only():
        return [(p["name"], p["type"]) for p in api(policies)["branch_policies"]] == [("main", "branch")]

    if api(environment).get("deployment_branch_policy") == ENV_POLICY:
        entries = api(policies)["branch_policies"]
        if any((p["name"], p["type"]) != ("main", "branch") for p in entries):
            raise SettingsError("unexpected deployment branches/tags; review before removing")
        changes.require(main_only(), "POST", policies, {"name": "main", "type": "branch"}, main_only)
    elif changes.mode != "apply":
        changes.require(False, "POST", policies, {"name": "main", "type": "branch"}, main_only)

    target = "refs/tags/v*"
    ruleset(changes, ruleset_spec("LASA release tag integrity", "tag", target,
                                  [{"type": kind} for kind in ("update", "deletion", "non_fast_forward")]))
    ruleset(changes, ruleset_spec("LASA release tag creation", "tag", target,
                                  [{"type": "creation"}], PIN_ROLES))
    path = f"{ROOT}/immutable-releases"
    changes.require(api(path)["enabled"], "PUT", path, verified=lambda: api(path)["enabled"])
    changes.require(alert_enabled(), "PUT", f"{ROOT}/vulnerability-alerts", verified=alert_enabled)
    path = f"{ROOT}/automated-security-fixes"
    changes.require(api(path)["enabled"], "PUT", path, verified=lambda: api(path)["enabled"])
    if repo["allow_auto_merge"]:
        path = ROOT
        changes.require(False, "PATCH", path, {"allow_auto_merge": False},
                        lambda: not repository()["allow_auto_merge"])


def successful_gate(sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise SettingsError("a full passing commit SHA is required for governance")
    checks = api(f"{ROOT}/commits/{sha}/check-runs?check_name=LASA%20verification%20gate&filter=latest")
    return any(check["name"] == GATE and check["conclusion"] == "success"
               and check["head_sha"] == sha and check["app"]["slug"] == "github-actions"
               for check in checks["check_runs"])


def governance(changes, sha):
    if changes.mode == "apply" and not successful_gate(sha):
        raise SettingsError("GitHub must record the successful canonical gate before enforcing it")
    collaborators = api(f"{ROOT}/collaborators?affiliation=all&per_page=100")
    if [entry["login"] for entry in collaborators] != [REPO.split("/")[0]]:
        raise SettingsError("review the single-maintainer policy with the current collaborators")
    if api(f"{ROOT}/invitations"):
        raise SettingsError("pending repository invitations require review")
    pr = {"type": "pull_request", "parameters": {
        "allowed_merge_methods": ["squash"],
        "dismiss_stale_reviews_on_push": True,
        "require_code_owner_review": False,
        "require_extra_approval_for_unattributed_changes": False,
        "require_last_push_approval": False,
        "required_approving_review_count": 0,
        "required_review_thread_resolution": True,
        "required_reviewers": [],
    }}
    check = {"type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": True,
        "do_not_enforce_on_create": False,
        "required_status_checks": [{"context": GATE, "integration_id": 15368}],
    }}
    baseline_rules = [{"type": kind} for kind in ("creation", "deletion", "non_fast_forward")]
    ruleset(changes, ruleset_spec("LASA protected main", "branch", "~DEFAULT_BRANCH",
                                  [*baseline_rules, pr, check]))
    # Keep the original admin-only creation/update policy on non-default refs.
    # Establish the replacement default-branch policy before excluding main.
    legacy = api(f"{ROOT}/rulesets/27697708")
    if (legacy["target"] != "branch" or legacy["enforcement"] != "active"
            or legacy["bypass_actors"] != PIN_ROLES
            or legacy["conditions"]["ref_name"]["include"] != ["~ALL"]
            or legacy["conditions"]["ref_name"]["exclude"] not in ([], ["~DEFAULT_BRANCH"])
            or {r["type"] for r in legacy["rules"]} != {"creation", "update", "deletion",
                                                       "non_fast_forward", "pull_request"}):
        raise SettingsError("legacy ruleset drift requires review")
    desired = {key: legacy[key] for key in ("name", "target", "enforcement", "bypass_actors", "rules")}
    desired["conditions"] = {"ref_name": {"include": ["~ALL"], "exclude": ["~DEFAULT_BRANCH"]}}
    ruleset(changes, desired, replace_id=27697708)
    desired = {"allow_squash_merge": True, "allow_merge_commit": False, "allow_rebase_merge": False}
    changes.require(all(repository()[k] == v for k, v in desired.items()), "PATCH", ROOT,
                    desired, lambda: all(repository()[k] == v for k, v in desired.items()))

    if changes.mode == "apply" or not changes.pending:
        effective = {r["type"]: r for r in api(f"{ROOT}/rules/branches/main")}
        if not {"deletion", "non_fast_forward", "pull_request", "required_status_checks"} <= effective.keys():
            raise SettingsError("effective main rules are incomplete")
        if "update" in effective:
            raise SettingsError("effective main still has the legacy admin-only update rule")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("harden", "verify"))
    parser.add_argument("--stage", choices=("baseline", "governance"), default="baseline")
    parser.add_argument("--sha", help="full SHA with a successful GitHub Actions gate (governance apply)")
    parser.add_argument("--apply", action="store_true", help="perform the planned writes")
    args = parser.parse_args()
    if args.apply and args.command != "harden":
        parser.error("--apply requires harden")
    mode = "verify" if args.command == "verify" else ("apply" if args.apply else "plan")
    changes = Changes(mode)
    try:
        repository()
        if args.stage == "baseline":
            baseline(changes)
        else:
            governance(changes, args.sha or "")
        repository()
    except (SettingsError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"LASA settings stopped: {error}", file=sys.stderr)
        return 1
    if mode == "verify" and changes.pending:
        return 1
    print(f"{args.stage}: {changes.pending} {'changes applied and verified' if args.apply else 'changes needed'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
