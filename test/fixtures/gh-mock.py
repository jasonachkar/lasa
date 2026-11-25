#!/usr/bin/env python3
"""Stateful GitHub CLI stand-in for test/setup-ci-publishing.sh.

Repositories are real local bare Git repositories. Secrets, variables, deploy
keys, rulesets, pull requests and workflow runs live in a JSON state file.
Merging a release PR creates a release run; approving it performs what the
release workflow would: tags the commit and publishes an APT index signed
with the APT_SIGNING_SUBKEY secret the setup script uploaded.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

STATE = Path(os.environ["GH_MOCK_STATE"])
REPOS = Path(os.environ["GH_MOCK_REPOS"])


def load():
    return json.loads(STATE.read_text())


def save(state):
    STATE.write_text(json.dumps(state, indent=1, sort_keys=True))


def log(entry):
    with open(STATE.with_suffix(".log"), "a") as handle:
        handle.write(entry + "\n")


def git(*args, cwd=None, capture=True):
    result = subprocess.run(["git", *args], cwd=cwd, check=True, text=True,
                            capture_output=capture)
    return result.stdout.strip() if capture else ""


def bare(repo):
    return REPOS / (repo.replace("/", "__") + ".git")


def read_file(repo, ref, path):
    return subprocess.run(["git", "--git-dir", str(bare(repo)), "show", f"{ref}:{path}"],
                          check=True, capture_output=True).stdout


def jq(data, expression):
    if expression is None:
        return json.dumps(data) if not isinstance(data, str) else data
    out = subprocess.run(["jq", "-r", expression], input=json.dumps(data), text=True,
                         capture_output=True)
    if out.returncode:
        sys.stderr.write(out.stderr)
        sys.exit(1)
    return out.stdout.rstrip("\n")


def emit(text):
    if text:
        print(text)


def fail(message, code=1):
    sys.stderr.write(message + "\n")
    sys.exit(code)


def option(args, name, default=None):
    if name in args:
        return args[args.index(name) + 1]
    return default


def squash_merge(state, number):
    pr = state["prs"][str(number)]
    if pr["state"] != "OPEN":
        return
    repo = pr["repo"]
    with tempfile.TemporaryDirectory() as work:
        git("clone", "-q", str(bare(repo)), work)
        git("-c", "user.name=Mock", "-c", "user.email=mock@example.invalid",
            "merge", "-q", "--squash", f"origin/{pr['head']}", cwd=work)
        git("-c", "user.name=Mock", "-c", "user.email=mock@example.invalid",
            "commit", "-q", "-m", f"{pr['title']} (#{number})", cwd=work)
        git("push", "-q", "origin", "HEAD:main", cwd=work)
        sha = git("rev-parse", "HEAD", cwd=work)
    pr.update(state="MERGED", merge_sha=sha)
    if pr["title"].startswith("Release "):
        run = str(len(state["runs"]) + 1000)
        state["runs"][run] = {"sha": sha, "head_sha": sha, "status": "waiting", "conclusion": None,
                              "head_repository": {"full_name": repo}, "head_branch": "main",
                              "path": ".github/workflows/release.yml", "event": "push",
                              "version": pr["title"].split()[1]}
    log(f"merged PR {number} as {sha}")


def publish_release(state, run_id):
    """What the release workflow does after approval, with the uploaded secret."""
    run = state["runs"][run_id]
    version, sha = run["version"], run["sha"]
    source = state["vars"]["DISTRIBUTION_REPOSITORY"]
    assert git("--git-dir", str(bare("jasonachkar/lasa")), "rev-parse", f"refs/tags/v{version}^{{commit}}") == sha
    secret = state["secrets"].get("APT_SIGNING_SUBKEY")
    subkey = state["vars"].get("APT_SIGNING_SUBKEY_FINGERPRINT")
    if not secret or not subkey or state["vars"].get("PUBLISHING_PROVIDER") != "github-actions":
        run.update(status="completed", conclusion="failure")
        return
    with tempfile.TemporaryDirectory() as work:
        home = Path(work) / "gnupg"
        home.mkdir(mode=0o700)
        subprocess.run(["gpg", "--homedir", str(home), "--batch", "--import"], input=secret,
                       text=True, check=True, capture_output=True)
        site = Path(work) / "site"
        git("clone", "-q", str(bare(source)), str(site))
        stable = site / "apt/dists/stable"
        (stable / "main/binary-amd64").mkdir(parents=True, exist_ok=True)
        (stable / "main/binary-amd64/Packages").write_text(
            f"Package: lasa\nVersion: {version}\nArchitecture: amd64\n")
        (stable / "Release").write_text(f"Origin: LASA\nSuite: stable\nVersion: {version}\n")
        for args in (["--clearsign", "--output", str(stable / "InRelease")],
                     ["--armor", "--detach-sign", "--output", str(stable / "Release.gpg")]):
            # --pinentry-mode error: fails if the uploaded subkey needs a passphrase.
            subprocess.run(["gpg", "--homedir", str(home), "--batch", "--yes", "--pinentry-mode", "error",
                            "--local-user", subkey + "!", *args, str(stable / "Release")],
                           check=True, capture_output=True)
        git("add", "-A", cwd=site)
        git("-c", "user.name=CI", "-c", "user.email=ci@example.invalid", "commit", "-q", "-m",
            f"Publish v{version}", cwd=site)
        git("push", "-q", "origin", "HEAD:main", cwd=site)
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "all"], capture_output=True)
    run.update(status="completed", conclusion="success")
    log(f"published v{version}")


def api(state, args):
    method = option(args, "--method", "GET")
    expression = option(args, "--jq")
    raw = "-H" in args and "raw" in option(args, "-H", "")
    fields = {}
    for flag in ("-f", "-F"):
        for index, value in enumerate(args):
            if value == flag:
                key, _, val = args[index + 1].partition("=")
                fields.setdefault(key, []).append(val)
    path = next(a for a in args[1:] if not a.startswith("-") and args[args.index(a) - 1] not in
                ("--method", "--jq", "-H", "-f", "-F", "--input"))
    path, _, query = path.partition("?")
    ref = dict(p.split("=", 1) for p in query.split("&") if "=" in p).get("ref", "main")

    if path == "user":
        return emit(jq({"login": state["login"], "id": 1}, expression))
    match = re.fullmatch(r"repos/([^/]+/[^/]+)", path)
    if match:
        return emit(jq({"owner": {"login": "jasonachkar"}, "full_name": match[1]}, expression))
    if path == "repos/jasonachkar/lasa/environments/release":
        return emit(jq(state["environment"], expression))
    if path == "repos/jasonachkar/lasa/environments/release/deployment-branch-policies":
        return emit(jq({"branch_policies": state["deployment_branches"]}, expression))
    match = re.fullmatch(r"repos/([^/]+/[^/]+)/contents/(.+)", path)
    if match:
        try:
            data = read_file(match[1], ref, match[2])
        except subprocess.CalledProcessError:
            fail("HTTP 404: Not Found")
        assert raw, "contents must be requested raw"
        sys.stdout.buffer.write(data)
        return
    match = re.fullmatch(r"repos/([^/]+/[^/]+)/git/matching-refs/tags/(.*)", path)
    if match:
        tags = git("--git-dir", str(bare(match[1])), "tag", "-l").split()
        refs = [{"ref": f"refs/tags/{t}"} for t in tags if t.startswith(match[2])]
        return emit(jq(refs, expression))
    match = re.fullmatch(r"repos/([^/]+/[^/]+)/commits/refs/tags/(v[\d.]+)", path)
    if match:
        sha = git("--git-dir", str(bare(match[1])), "rev-parse", f"refs/tags/{match[2]}^{{commit}}")
        return emit(jq({"sha": sha}, expression))
    if path == "repos/jasonachkar/lasa/git/refs" and method == "POST":
        assert state["login"] == "jasonachkar"
        tag = fields["ref"][0].removeprefix("refs/tags/")
        sha = fields["sha"][0]
        git("--git-dir", str(bare("jasonachkar/lasa")), "tag", tag, sha)
        log(f"owner created tag {tag}")
        return emit(jq({"ref": f"refs/tags/{tag}"}, expression))
    match = re.fullmatch(r"repos/([^/]+/[^/]+)/keys(?:/(\d+))?", path)
    if match:
        keys = state["deploy_keys"]
        if method == "DELETE":
            state["deploy_keys"] = [k for k in keys if str(k["id"]) != match[2]]
            log(f"deleted deploy key {match[2]}")
            return
        if method == "POST":
            key = {"id": len(keys) + 100 + len(state["log_keys"]), "title": fields["title"][0],
                   "key": fields["key"][0], "read_only": fields["read_only"][0] == "true"}
            state["log_keys"].append(key["id"])
            keys.append(key)
            log(f"added deploy key {key['id']} read_only={key['read_only']}")
            return emit(jq(key, expression))
        return emit(jq([keys] if "--slurp" in args else keys, expression))
    match = re.fullmatch(r"repos/([^/]+/[^/]+)/rulesets(?:/(\d+))?", path)
    if match:
        rulesets = state["rulesets"][match[1]]
        if match[2] is None:
            return emit(jq([{"id": r["id"], "name": r["name"]} for r in rulesets], expression))
        ruleset = next(r for r in rulesets if str(r["id"]) == match[2])
        if method == "PUT":
            assert match[1] == "jasonachkar/homebrew-lasa", "source rulesets must not be changed by setup"
            body = json.loads(sys.stdin.read())
            assert set(body) == {"name", "target", "enforcement", "conditions", "rules", "bypass_actors"}, body
            ruleset.update(body)
            log(f"updated ruleset {ruleset['name']}")
        return emit(jq(ruleset, expression))
    match = re.fullmatch(r"repos/([^/]+/[^/]+)/actions/runs/(\d+)(/pending_deployments|/jobs)?", path)
    if match:
        run = state["runs"][match[2]]
        if match[3] == "/jobs":
            return emit(jq({"jobs": [{"name": "build", "id": 1, "conclusion": "success"}]}, expression))
        if match[3] == "/pending_deployments":
            if method == "POST":
                assert fields["state"] == ["approved"] and fields["environment_ids[]"] == ["7"]
                log(f"approved run {match[2]}")
                run["status"] = "in_progress"
                publish_release(state, match[2])
                return emit(jq([{}], expression))
            pending = ([{"environment": {"id": 7, "name": "release"}, "current_user_can_approve": True}]
                       if run["status"] == "waiting" else [])
            return emit(jq(pending, expression))
        return emit(jq(run, expression))
    fail(f"unexpected gh api call: {args}", 90)


def main():
    args = sys.argv[1:]
    state = load()
    log("gh " + " ".join(args))
    command = args[:2]
    if command == ["auth", "status"]:
        pass
    elif args[0] == "api":
        api(state, args)
    elif command == ["variable", "get"]:
        value = state["vars"].get(args[2])
        if value is None:
            fail(f"variable {args[2]} was not found")
        print(value)
    elif command == ["variable", "set"]:
        state["vars"][args[2]] = option(args, "--body")
    elif command == ["secret", "list"]:
        assert option(args, "--env") == "release"
        emit(jq([{"name": n} for n in state["secrets"]], option(args, "--jq")))
    elif command == ["secret", "set"]:
        assert option(args, "--env") == "release"
        state["secrets"][args[2]] = sys.stdin.read()
        state["secret_writes"] += 1
    elif command == ["repo", "edit"]:
        state["auto_merge"] = "--enable-auto-merge" in args
    elif command == ["repo", "clone"]:
        rest = args[args.index("--") + 1:] if "--" in args else []
        git("clone", *rest, str(bare(args[2])), args[3], capture=False)
    elif command == ["pr", "list"]:
        head, wanted = option(args, "--head"), option(args, "--state")
        prs = [{"number": int(n), "state": p["state"]} for n, p in state["prs"].items()
               if p["head"] == head and (wanted == "all" or p["state"].lower() == wanted)]
        emit(jq(prs, option(args, "--jq")))
    elif command == ["pr", "create"]:
        number = str(len(state["prs"]) + 40)
        state["prs"][number] = {"repo": option(args, "--repo"), "head": option(args, "--head"),
                                "title": option(args, "--title"), "state": "OPEN"}
        print(f"https://github.com/{option(args, '--repo')}/pull/{number}")
    elif command == ["pr", "merge"]:
        assert "--auto" in args and "--squash" in args and state["auto_merge"]
        squash_merge(state, args[2])
    elif command == ["pr", "view"]:
        pr = state["prs"][args[2]]
        emit(jq({"state": pr["state"], "mergeCommit": {"oid": pr.get("merge_sha")}}, option(args, "--jq")))
    elif command == ["run", "list"]:
        sha = option(args, "--commit")
        runs = [{"databaseId": int(i)} for i, r in state["runs"].items() if r["sha"] == sha]
        emit(jq(runs, option(args, "--jq")))
    elif command == ["run", "rerun"]:
        state["runs"][args[2]].update(status="waiting", conclusion=None)
    else:
        fail(f"unexpected gh command: {args}", 90)
    save(state)


main()
