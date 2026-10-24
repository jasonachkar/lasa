#!/usr/bin/env python3
"""Owner-local orchestration; credentials enter the disposable guest after verification."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import uuid

SOURCE = "jasonachkar/lasa"
DISTRIBUTION = "jasonachkar/homebrew-lasa"
ROOT = Path(__file__).resolve().parents[1]
GUEST = "/home/ubuntu/lasa"
JOURNAL_SCHEMA = "lasa.local-deployment/v1"


def run(args, *, capture=False, env=None, timeout=7200, input_text=None):
    try:
        result = subprocess.run(args, cwd=ROOT, env=env, text=True, check=False, timeout=timeout, input=input_text,
                                stdout=subprocess.PIPE if capture else None,
                                stderr=subprocess.PIPE if capture else None)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("Local deployment could not complete " + args[0] + "; check tool availability/connectivity and retry.") from None
    if result.returncode:
        status = re.search(r"HTTP [0-9]{3}", result.stderr or "") if capture else None
        operation = " ".join(args[:2])
        raise RuntimeError(f"{operation} failed (exit {result.returncode}" + (", " + status[0] if status else "")
                           + "). Credential-bearing output is withheld; check the current deployment stage.")
    return result.stdout.strip() if capture else ""


def write_private(path, data):
    descriptor, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w") as output:
            json.dump(data, output)
            output.write("\n")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_json(value, label):
    try:
        return json.loads(value)
    except ValueError:
        raise RuntimeError(label + " returned invalid JSON; response withheld.") from None


class Deployment:
    @property
    def stage(self):
        return self._stage

    @stage.setter
    def stage(self, value):
        self._stage = value
        print("Local deployment: " + value, flush=True)

    def __init__(self, options):
        self.options = options
        self.state = Path.home() / "Library/Application Support/lasa-distribution/jasonachkar_lasa"
        self.environment = dict(os.environ)
        for name in ("AZURE_DEVOPS_EXT_PAT", "LASA_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN",
                     "APT_SIGNING_KEY", "APK_SIGNING_KEY", "DISTRIBUTION_DEPLOY_KEY", "GODADDY_API_KEY", "GODADDY_API_SECRET"):
            self.environment.pop(name, None)
        self.token = os.environ.get("LASA_GITHUB_TOKEN") or run(["gh", "auth", "token", "--hostname", "github.com"], capture=True)
        if not self.token or not re.fullmatch(r"[!-~]{1,4096}", self.token):
            raise RuntimeError("A valid GitHub token is required; value withheld.")
        self.github_environment = dict(self.environment, GH_TOKEN=self.token, GH_HOST="github.com")
        self.vm = None
        self.stage = "preflight"
        self.journal = self.state / "local-deploy-active.json"

    def api(self, path):
        try:
            value = run(["gh", "api", "--hostname", "github.com", path], capture=True, env=self.github_environment, timeout=120)
        except RuntimeError as error:
            raise RuntimeError("GitHub GET " + path.split("?", 1)[0] + ": " + str(error)) from None
        return parse_json(value, "GitHub " + path.split("?", 1)[0])

    def guest(self, *args, capture=False):
        return run(["multipass", "exec", self.vm, "--", *args], capture=capture, env=self.environment)

    def preflight(self):
        if run(["git", "status", "--porcelain"], capture=True):
            raise RuntimeError("Commit the intended source changes before deployment; a clean checkout is required.")
        self.branch = run(["git", "branch", "--show-current"], capture=True)
        if not self.branch:
            raise RuntimeError("A named, pushed branch is required; this checkout has a detached HEAD.")
        run(["git", "check-ref-format", "--branch", self.branch], capture=True)
        self.commit = run(["git", "rev-parse", "HEAD"], capture=True)
        from urllib.parse import quote
        remote = self.api("repos/" + SOURCE + "/git/ref/heads/" + quote(self.branch, safe=""))
        if not isinstance(remote, dict) or not isinstance(remote.get("object"), dict) or remote["object"].get("sha") != self.commit:
            raise RuntimeError("The checked-out commit differs from its remote branch. Pull or push the intended reviewed source first.")
        state_info = self.state.lstat()
        if not stat.S_ISDIR(state_info.st_mode) or state_info.st_uid != os.getuid() or stat.S_IMODE(state_info.st_mode) & 0o077:
            raise RuntimeError("The saved publishing-state directory must be private (0700), owned by this user and not a symlink.")
        for name in ("deploy-key", "signing-fingerprint", "apk-signing-key.pem", "apk-public-key.sha256"):
            path = self.state / name
            if not path.is_file() or path.stat().st_size == 0:
                raise RuntimeError("Restore existing private publishing state: " + str(path) + ". No keys will be regenerated.")
        if not (self.state / "gnupg").is_dir():
            raise RuntimeError("Restore the existing GnuPG publishing state; no trust key will be regenerated.")
        self.fingerprint = (self.state / "signing-fingerprint").read_text().strip()
        self.apk_pin = (self.state / "apk-public-key.sha256").read_text().strip()
        if not re.fullmatch(r"[A-F0-9]{40}", self.fingerprint) or not re.fullmatch(r"[a-f0-9]{64}", self.apk_pin):
            raise RuntimeError("Saved public signing fingerprint/pin is malformed.")
        public = run(["openssl", "pkey", "-in", str(self.state / "apk-signing-key.pem"), "-pubout"], capture=True)
        # subprocess strips one final newline; PEM pinning includes it.
        if hashlib.sha256((public + "\n").encode()).hexdigest() != self.apk_pin:
            raise RuntimeError("Saved Alpine private key differs from its public-key pin. Restore the matching state.")
        metadata = self.api("repos/" + DISTRIBUTION)
        if not isinstance(metadata, dict) or metadata.get("visibility") != "public":
            raise RuntimeError("The existing distribution repository must be public; its visibility was not changed.")
        self.distribution_branch = metadata.get("default_branch", "")
        if not isinstance(self.distribution_branch, str) or not self.distribution_branch:
            raise RuntimeError("GitHub returned an invalid distribution branch.")
        run(["git", "check-ref-format", "--branch", self.distribution_branch], capture=True)
        pages = self.api("repos/" + DISTRIBUTION + "/pages")
        if (not isinstance(pages, dict) or not isinstance(pages.get("source"), dict)
                or pages.get("build_type") != "legacy" or pages["source"].get("branch") != self.distribution_branch
                or pages.get("source", {}).get("path") != "/"):
            raise RuntimeError("Distribution Pages must already publish its default branch at /. Existing Pages settings were not replaced.")
        public_key = run(["ssh-keygen", "-y", "-f", str(self.state / "deploy-key")], capture=True)
        public_key = " ".join(public_key.split()[:2])
        keys = self.api("repos/" + DISTRIBUTION + "/keys?per_page=100")
        if not isinstance(keys, list) or not any(isinstance(item, dict) and isinstance(item.get("key"), str) and " ".join(item["key"].split()[:2]) == public_key
                                               and item.get("read_only") is False for item in keys):
            raise RuntimeError("The saved deploy key is not registered with write access to the distribution repository. Restore the original setup/key.")
        publishers = {"Signed release", "Automatic version and release", "Customer documentation"}
        for status in ("queued", "in_progress", "waiting", "pending", "requested"):
            runs = self.api("repos/" + SOURCE + "/actions/runs?status=" + status + "&per_page=100")
            if not isinstance(runs, dict) or not isinstance(runs.get("workflow_runs"), list):
                raise RuntimeError("GitHub returned an invalid publishing-workflow list.")
            if any(not isinstance(item, dict) for item in runs["workflow_runs"]):
                raise RuntimeError("GitHub returned an invalid workflow entry.")
            if any(item.get("name") in publishers and item.get("status") != "completed" for item in runs["workflow_runs"]):
                raise RuntimeError("A GitHub publishing workflow is still active. Let it finish or stop it before local deployment.")
        run(["multipass", "version"], capture=True, env=self.environment, timeout=60)
        print("Preflight passed: " + SOURCE + " " + self.branch + " @ " + self.commit, flush=True)

    def existing_vms(self):
        result = parse_json(run(["multipass", "list", "--format", "json"], capture=True, env=self.environment, timeout=60), "Multipass")
        if (not isinstance(result, dict) or not isinstance(result.get("list"), list)
                or any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in result["list"])):
            raise RuntimeError("Multipass returned an invalid VM listing.")
        return {item["name"] for item in result["list"]}

    def recover(self):
        if not self.journal.exists():
            return
        record = parse_json(self.journal.read_text(), "Local recovery journal")
        vm = record.get("vm", "") if isinstance(record, dict) else ""
        if not isinstance(record, dict) or record.get("schema") != JOURNAL_SCHEMA or not re.fullmatch(r"lasa-local-[0-9a-f]{12}", vm):
            raise RuntimeError("The local deployment recovery journal is invalid; no VM was removed.")
        if vm in self.existing_vms():
            print("Removing this publisher's interrupted VM before retry: " + vm, flush=True)
            run(["multipass", "delete", "--purge", vm], env=self.environment, timeout=180)
        self.journal.unlink()

    def deploy(self):
        # A kernel-held lock releases automatically after interruptions. The journal
        # separately recovers a guest that might outlive a killed Mac process.
        descriptor = os.open(self.state / "local-deploy.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as lock:
            if os.fstat(lock.fileno()).st_uid != os.getuid() or stat.S_IMODE(os.fstat(lock.fileno()).st_mode) & 0o077:
                raise RuntimeError("The local publication lock has unsafe ownership/permissions.")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuntimeError("Another local deployment is running on this Mac.") from None
            self.recover()
            self._deploy()

    def _deploy(self):
        self.stage = "fetching version history"
        fetch = ["git", "-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential", "fetch", "--tags"]
        if run(["git", "rev-parse", "--is-shallow-repository"], capture=True) == "true":
            fetch.append("--unshallow")
        run(fetch + ["https://github.com/" + SOURCE + ".git", self.branch], env=self.github_environment)
        if run(["git", "rev-parse", "FETCH_HEAD"], capture=True) != self.commit:
            raise RuntimeError("The source branch advanced during preflight; update the checkout and retry.")
        with tempfile.TemporaryDirectory(prefix="lasa-local-") as directory:
            temporary = Path(directory)
            bundle = temporary / "source.bundle"
            run(["git", "bundle", "create", str(bundle), self.branch, "--tags"], capture=True)
            self.vm = "lasa-local-" + uuid.uuid4().hex[:12]
            if self.vm in self.existing_vms():
                raise RuntimeError("The generated VM name is already in use; no existing VM was changed.")
            write_private(self.journal, {"schema": JOURNAL_SCHEMA, "vm": self.vm, "commit": self.commit, "host": socket.gethostname()})
            try:
                self.stage = "creating the local Ubuntu VM"
                run(["multipass", "launch", "24.04", "--name", self.vm, "--cpus", str(self.options.cpus),
                     "--memory", self.options.memory, "--disk", self.options.disk], env=self.environment, timeout=900)
                self.stage = "bootstrapping Git in the fresh VM"
                self.guest("sudo", "apt-get", "update", "-o", "APT::Update::Error-Mode=any")
                self.guest("sudo", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", "--no-install-recommends", "git", "ca-certificates")
                run(["multipass", "transfer", str(bundle), self.vm + ":/home/ubuntu/source.bundle"], env=self.environment)
                self.guest("git", "clone", "--branch", self.branch, "/home/ubuntu/source.bundle", GUEST)
                self.guest("git", "-C", GUEST, "remote", "set-url", "origin", "https://github.com/" + SOURCE + ".git")
                self.stage = "installing tools inside the disposable VM"
                self.guest("sudo", "bash", GUEST + "/scripts/local-deploy-linux.sh", "prepare")
                self.stage = "verification (publishing credentials have not been transferred)"
                self.guest("bash", GUEST + "/scripts/local-deploy-linux.sh", "verify")
                verification = parse_json(self.guest("cat", GUEST + "/.build/local-verification.json", capture=True), "VM verification")
                if (not isinstance(verification, dict) or verification.get("schema") != "lasa.local-verification/v1"
                        or verification.get("source_revision") != self.commit or verification.get("verified") is not True):
                    raise RuntimeError("VM verification did not establish this source revision; no credentials were transferred.")
                self.stage = "checking the LASA domain and selecting local publishing"
                domain_environment = dict(self.github_environment)
                for name in ("GODADDY_API_KEY", "GODADDY_API_SECRET"):
                    if name in os.environ:
                        domain_environment[name] = os.environ[name]
                run(["bash", "scripts/repair-docs-https.sh", DISTRIBUTION], env=domain_environment)
                run(["gh", "variable", "set", "PUBLISHING_PROVIDER", "--repo", SOURCE, "--body", "local"],
                    capture=True, env=self.github_environment, timeout=120)
                self.stage = "loading existing signing/deploy keys"
                with tempfile.TemporaryDirectory(prefix="lasa-gpg-", dir="/tmp") as alias_dir:
                    alias = Path(alias_dir) / "home"
                    alias.symlink_to(self.state / "gnupg", target_is_directory=True)
                    try:
                        key = run(["gpg", "--homedir", str(alias), "--batch", "--armor", "--export-secret-keys", self.fingerprint], capture=True)
                    finally:
                        subprocess.run(["gpgconf", "--homedir", str(alias), "--kill", "gpg-agent"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, env=self.environment)
                if not key:
                    raise RuntimeError("Existing OpenPGP signing key could not be exported.")
                credentials = {"schema": "lasa.local-credentials/v1", "source_revision": self.commit, "source_branch": self.branch,
                               "distribution_branch": self.distribution_branch, "GH_TOKEN": self.token, "APT_SIGNING_KEY": key,
                               "APT_SIGNING_FINGERPRINT": self.fingerprint, "APK_PUBLIC_KEY_SHA256": self.apk_pin,
                               "APK_SIGNING_KEY": (self.state / "apk-signing-key.pem").read_text(),
                               "DISTRIBUTION_DEPLOY_KEY": (self.state / "deploy-key").read_text()}
                self.guest("install", "-d", "-m", "0700", "/home/ubuntu/.lasa-local")
                self.stage = "publishing verified releases, packages and documentation"
                # Multipass supports '-' as stdin. No additional Mac credential
                # payload file survives an interrupted transfer.
                run(["multipass", "transfer", "-", self.vm + ":/home/ubuntu/.lasa-local/credentials.json"],
                    capture=True, env=self.environment, input_text=json.dumps(credentials))
                self.guest("chmod", "0600", "/home/ubuntu/.lasa-local/credentials.json")
                self.guest("bash", GUEST + "/scripts/local-deploy-linux.sh", "publish")
                self.stage = "complete"
            finally:
                # Never retain a VM containing owner publishing credentials, even on failure.
                if self.stage == "complete":
                    self.stage = "cleaning up the completed publisher VM"
                if self.vm in self.existing_vms():
                    print("Removing disposable publisher VM: " + self.vm, flush=True)
                    run(["multipass", "delete", "--purge", self.vm], env=self.environment, timeout=180)
                self.journal.unlink(missing_ok=True)
        print("Local deployment completed: releases, signed Linux repositories, Linux Homebrew and https://lasa.secureobs.com/", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--cpus", type=int, default=2)
    parser.add_argument("--memory", default="4G")
    parser.add_argument("--disk", default="40G")
    options = parser.parse_args()
    if not 1 <= options.cpus <= 32 or any(not re.fullmatch(r"[1-9][0-9]*[MG]", value) for value in (options.memory, options.disk)):
        parser.error("Use 1-32 CPUs and integer memory/disk sizes such as 4G and 40G")
    deployment = None
    try:
        if sys.platform != "darwin":
            raise RuntimeError("The local orchestration command requires macOS; Linux workers run inside its disposable VM.")
        deployment = Deployment(options)
        deployment.preflight()
        if not options.check:
            deployment.deploy()
    except (RuntimeError, OSError, ValueError, KeyError, KeyboardInterrupt) as error:
        stage = deployment.stage if deployment else "initialization"
        # Never include subprocess arguments or credential payloads in diagnostics.
        message = "interrupted" if isinstance(error, KeyboardInterrupt) else str(error)
        print("Local deployment stopped during " + stage + ": " + message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
