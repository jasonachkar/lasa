"""Actual Git/crypto/filesystem orchestration with fixture GitHub and Multipass services.

No live VM, owner key, network publication or OS package installation is used.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("local_deploy_integration", ROOT / "scripts/deploy-local.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

HELPER = r'''import json, os, pathlib, shutil, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
base = pathlib.Path(os.environ["FIXTURE_BASE"])
with (base / "commands.jsonl").open("a") as log:
    log.write(json.dumps({"tool": name, "args": args, "gh_token_present": bool(os.environ.get("GH_TOKEN"))}) + "\n")
if name == "git":
    if "fetch" in args:
        args = ["fetch", "--tags", str(base / "origin.git"), "feature/lasa"]
    sys.exit(subprocess.call([os.environ["FIXTURE_GIT"], *args]))
if name == "gh":
    if args[:2] == ["variable", "set"]:
        (base / "provider").write_text(args[-1]); sys.exit(0)
    route = next((arg for arg in args if arg.startswith("repos/")), "")
    if route.endswith("git/ref/heads/feature%2Flasa"):
        result = {"object": {"sha": os.environ["FIXTURE_REVISION"]}}
    elif route.endswith("homebrew-lasa"):
        result = {"visibility": "public", "default_branch": "pages"}
    elif route.endswith("/pages"):
        result = {"build_type": "legacy", "source": {"branch": "pages", "path": "/"}}
    elif "/keys?" in route:
        result = [{"key": (base / "deploy.pub").read_text(), "read_only": False}]
    elif "/actions/runs?" in route:
        result = {"workflow_runs": []}
    elif route.endswith("/actions/variables/PUBLISHING_PROVIDER"):
        print((base / "provider").read_text()); sys.exit(0)
    else:
        raise SystemExit("unsupported fixture GitHub operation")
    print(json.dumps(result)); sys.exit(0)
if name != "multipass":
    raise SystemExit("unsupported fixture command")
if os.environ.get("GH_TOKEN") or os.environ.get("LASA_GITHUB_TOKEN"):
    raise SystemExit("owner token leaked to Multipass environment")
vms = base / "vms"
vms.mkdir(exist_ok=True)
if args[0] == "version":
    print("fixture Multipass service"); sys.exit(0)
if args[0] == "list":
    print(json.dumps({"list": [{"name": p.name} for p in vms.iterdir()]})); sys.exit(0)
if args[0] == "launch":
    vm = args[args.index("--name") + 1]
    (vms / vm / "home/ubuntu").mkdir(parents=True); sys.exit(0)
if args[0] == "delete":
    shutil.rmtree(vms / args[-1]); sys.exit(0)
if args[0] == "transfer":
    source, destination = args[1:]
    vm, target = destination.split(":", 1)
    destination = vms / vm / target.lstrip("/")
    if source == "-":
        destination.write_text(sys.stdin.read())
    else:
        shutil.copy2(source, destination)
    sys.exit(0)
if args[0] != "exec":
    raise SystemExit("unsupported fixture Multipass operation")
vm = vms / args[1]
command = args[args.index("--") + 1:]
def translate(arg):
    return str(vm / arg.lstrip("/")) if arg.startswith("/home/ubuntu/") else arg
command = [translate(arg) for arg in command]
if command[:2] in (["sudo", "apt-get"], ["sudo", "env"]):
    sys.exit(0)  # Guest-only bootstrap is simulated, never installed on the test host.
if command[0] == "sudo" and command[-1] == "prepare":
    sys.exit(0)  # Package provisioning belongs to real VM validation, not this fixture.
if command[0] == "bash" and command[-1] == "verify":
    if (vm / "home/ubuntu/.lasa-local/credentials.json").exists():
        raise SystemExit("credentials arrived before verification")
    if os.environ.get("FIXTURE_FAIL_VERIFY") == "1":
        raise SystemExit(17)
    source = vm / "home/ubuntu/lasa"
    revision = subprocess.check_output([os.environ["FIXTURE_GIT"], "rev-parse", "HEAD"], cwd=source, text=True).strip()
    (source / ".build").mkdir()
    (source / ".build/local-verification.json").write_text(json.dumps({"schema": "lasa.local-verification/v1", "verified": True, "source_revision": revision}))
    sys.exit(0)
if command[0] == "bash" and command[-1] == "publish":
    source = vm / "home/ubuntu/lasa"
    sys.exit(subprocess.call([sys.executable, str(source / "scripts/local-release.py"), str(vm / "home/ubuntu/.lasa-local/credentials.json")], cwd=source))
if command[0] == "git":
    command[0] = os.environ["FIXTURE_GIT"]
elif command[0] not in ("install", "chmod", "cat"):
    raise SystemExit("unsupported fixture guest command; refusing host execution")
sys.exit(subprocess.call(command))
'''


@unittest.skipUnless(all(shutil.which(tool) for tool in ("git", "gpg", "gpgconf", "openssl", "ssh-keygen")), "local Git/crypto tools unavailable")
class LocalOrchestrationIntegration(unittest.TestCase):
    def exercise(self, fail_verification):
        with tempfile.TemporaryDirectory(prefix="lasa-local-test-") as directory:
            base = Path(directory)
            source = base / "source"
            scripts = source / "scripts"
            scripts.mkdir(parents=True)
            (scripts / "local-release.py").write_text((ROOT / "scripts/local-release.py").read_text())
            (scripts / "check-publisher.sh").write_text((ROOT / "scripts/check-publisher.sh").read_text())
            (scripts / "repair-docs-https.sh").write_text("#!/bin/sh\nexit 0\n")
            (scripts / "release.sh").write_text("#!/bin/sh\nset -eu\nbash scripts/check-publisher.sh local\n" + shlex.quote(sys.executable) + " - <<'PY'\nimport json, os, pathlib\npathlib.Path(os.environ['FIXTURE_BASE'], 'published.json').write_text(json.dumps({'secrets_present': all(os.environ.get(k) for k in ('GH_TOKEN','APT_SIGNING_KEY','APK_SIGNING_KEY','DISTRIBUTION_DEPLOY_KEY')), 'provider': os.environ['LASA_RELEASE_PROVIDER'], 'source': os.environ['GITHUB_REPOSITORY']}))\nPY\n")
            real_git = shutil.which("git")
            subprocess.run([real_git, "init", "-q", "-b", "feature/lasa", str(source)], check=True)
            for field, value in (("user.name", "Fixture"), ("user.email", "fixture@example.invalid")):
                subprocess.run([real_git, "-C", str(source), "config", field, value], check=True)
            subprocess.run([real_git, "-C", str(source), "add", "."], check=True)
            subprocess.run([real_git, "-C", str(source), "commit", "-qm", "fixture reviewed source"], check=True)
            revision = subprocess.check_output([real_git, "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
            subprocess.run([real_git, "init", "-q", "--bare", str(base / "origin.git")], check=True)
            subprocess.run([real_git, "-C", str(source), "push", "-q", str(base / "origin.git"), "feature/lasa"], check=True)
            state = base / "home/Library/Application Support/lasa-distribution/jasonachkar_lasa"
            state.mkdir(parents=True, mode=0o700)
            gnupg = state / "gnupg"
            gnupg.mkdir(mode=0o700)
            # Short alias matches the production Mac GnuPG socket workaround.
            with tempfile.TemporaryDirectory(prefix="lasa-test-gpg-", dir="/tmp") as alias_dir:
                alias = Path(alias_dir) / "home"
                alias.symlink_to(gnupg, target_is_directory=True)
                subprocess.run(["gpg", "--homedir", str(alias), "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "Local deployment fixture <fixture@example.invalid>", "ed25519", "sign", "0"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                output = subprocess.check_output(["gpg", "--homedir", str(alias), "--batch", "--with-colons", "--list-secret-keys"], text=True, stderr=subprocess.DEVNULL)
                fingerprint = next(line.split(":")[9] for line in output.splitlines() if line.startswith("fpr:"))
                subprocess.run(["gpgconf", "--homedir", str(alias), "--kill", "gpg-agent"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (state / "signing-fingerprint").write_text(fingerprint)
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024", "-out", str(state / "apk-signing-key.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            public = subprocess.check_output(["openssl", "pkey", "-in", str(state / "apk-signing-key.pem"), "-pubout"], stderr=subprocess.DEVNULL)
            (state / "apk-public-key.sha256").write_text(hashlib.sha256(public).hexdigest())
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(state / "deploy-key")], check=True)
            shutil.copy2(state / "deploy-key.pub", base / "deploy.pub")
            original = {item.name: item.read_bytes() for item in state.iterdir() if item.is_file()}
            binary = base / "bin"
            binary.mkdir()
            for name in ("git", "gh", "multipass"):
                path = binary / name
                path.write_text("#!" + sys.executable + "\n" + HELPER)
                path.chmod(0o700)
            environment = dict(os.environ, PATH=str(binary) + ":" + os.environ["PATH"], LASA_GITHUB_TOKEN="FIXTURE_PRIVATE_GITHUB_TOKEN",
                               FIXTURE_BASE=str(base), FIXTURE_GIT=real_git, FIXTURE_REVISION=revision,
                               FIXTURE_FAIL_VERIFY="1" if fail_verification else "0")
            with patch.dict(os.environ, environment, clear=True), patch.object(module, "ROOT", source), patch.object(module.Path, "home", return_value=base / "home"):
                deployment = module.Deployment(argparse.Namespace(cpus=2, memory="4G", disk="40G"))
                deployment.preflight()
                if fail_verification:
                    with self.assertRaises(RuntimeError):
                        deployment.deploy()
                else:
                    deployment.deploy()
            observed = [json.loads(line) for line in (base / "commands.jsonl").read_text().splitlines()]
            self.assertTrue(all(not item["gh_token_present"] for item in observed if item["tool"] == "multipass"))
            self.assertNotIn("FIXTURE_PRIVATE_GITHUB_TOKEN", (base / "commands.jsonl").read_text())
            self.assertEqual(list((base / "vms").iterdir()), [])
            self.assertFalse((state / "local-deploy-active.json").exists())
            for name, content in original.items():
                self.assertEqual((state / name).read_bytes(), content)
            if fail_verification:
                self.assertFalse((base / "published.json").exists())
                self.assertFalse((base / "provider").exists())
                self.assertFalse(any("credentials.json" in " ".join(item["args"]) for item in observed))
            else:
                self.assertEqual(json.loads((base / "published.json").read_text()), {"secrets_present": True, "provider": "local", "source": "jasonachkar/lasa"})
                self.assertTrue(any(item["tool"] == "multipass" and item["args"][:2] == ["transfer", "-"] for item in observed))

    def test_actual_bundle_crypto_and_worker_flow(self):
        self.exercise(False)

    def test_failed_verification_never_transfers_owner_credentials(self):
        self.exercise(True)


class SharedReleaseIntegration(unittest.TestCase):
    def exercise(self, *, provider="local", advanced=False, github_origin=False, tag_mismatch=False, fresh=False):
        with tempfile.TemporaryDirectory(prefix="lasa-release-test-") as directory:
            base = Path(directory)
            source = base / "source"
            scripts = source / "scripts"
            scripts.mkdir(parents=True)
            for name in ("release.sh", "check-publisher.sh", "next-version.sh"):
                (scripts / name).write_text((ROOT / "scripts" / name).read_text())
            (scripts / "publish-docs.sh").write_text('#!/bin/sh\nprintf "docs %s\\n" "$1" >> "$FIXTURE_LOG"\n')
            (scripts / "publish-from-actions.sh").write_text('#!/bin/sh\nprintf "packages %s\\n" "$RELEASE_PROVENANCE" >> "$FIXTURE_LOG"\n')
            (scripts / "build-signed-packages.sh").write_text('#!/bin/sh\necho unexpected-rebuild >> "$FIXTURE_LOG"\nexit 99\n')
            if fresh:
                (scripts / "write-release-manifest.sh").write_text((ROOT / "scripts/write-release-manifest.sh").read_text())
                (scripts / "build-signed-packages.sh").write_text('#!/bin/sh\n' + shlex.quote(sys.executable) + " - <<'PY'\nfrom pathlib import Path\np=Path('dist'); (p/'licenses').mkdir(parents=True)\n(p/'licenses/LICENSE').write_text('fixture notice')\nfor arch,native in [('amd64','x86_64'),('arm64','aarch64')]:\n for name in [f'lasa-0.1.0-linux-{arch}',f'lasa-0.1.0-linux-{arch}.tar.gz',f'lasa_0.1.0_{arch}.deb',f'lasa-0.1.0-1.{native}.rpm',f'lasa-0.1.0-1-{native}.pkg.tar.zst',f'lasa-0.1.0-1-{native}.pkg.tar.zst.sig',f'lasa-0.1.0-r1-{native}.apk',f'lasa-{arch}.cdx.json']:\n  (p/name).write_text('fixture artifact bytes')\nPY\n")
            git = shutil.which("git")
            subprocess.run([git, "init", "-q", "-b", "feature/lasa", str(source)], check=True)
            subprocess.run([git, "-C", str(source), "config", "user.name", "Fixture"], check=True)
            subprocess.run([git, "-C", str(source), "config", "user.email", "fixture@example.invalid"], check=True)
            subprocess.run([git, "-C", str(source), "add", "."], check=True)
            subprocess.run([git, "-C", str(source), "commit", "-qm", "fixture source"], check=True)
            revision = subprocess.check_output([git, "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
            binary = base / "bin"
            binary.mkdir()
            gh = binary / "gh"
            gh.write_text("#!" + sys.executable + "\n" + '''import os, pathlib, sys
args = sys.argv[1:]
route = next((arg for arg in args if arg.startswith("repos/")), "")
state = pathlib.Path(os.environ["FIXTURE_STATE"])
fresh = os.environ["FIXTURE_FRESH"] == "1"
if route.endswith("PUBLISHING_PROVIDER"):
    print(os.environ["FIXTURE_PROVIDER"])
elif "/git/ref/heads/feature%2Flasa" in route:
    print(os.environ["FIXTURE_REVISION"])
elif "/releases/tags/v0.1.0" in route:
    if fresh and not state.exists():
        print("HTTP 404", file=sys.stderr); raise SystemExit(1)
    print("SHA256SUMS" if args[-1] == ".assets[].name" and os.environ["FIXTURE_GITHUB_ORIGIN"] == "1" else "SHA256SUMS.asc" if args[-1] == ".assets[].name" else "true" if fresh and state.read_text() == "draft" else "false")
elif route.endswith("/commits/v0.1.0"):
    print("0" * 40 if os.environ["FIXTURE_TAG_MISMATCH"] == "1" else os.environ["FIXTURE_REVISION"])
elif fresh and route.endswith("/git/refs") and "POST" in args:
    print("{}")
elif fresh and args[:2] == ["release", "view"]:
    raise SystemExit(0 if state.exists() else 1)
elif fresh and args[:2] == ["release", "create"]:
    if state.exists(): raise SystemExit("refusing existing release")
    state.write_text("draft")
elif fresh and args[:2] == ["release", "upload"]:
    if state.read_text() != "draft": raise SystemExit("refusing published overwrite")
    for name in args[3:]:
        if name != "--clobber" and not pathlib.Path(name).is_file(): raise SystemExit("missing release asset")
elif fresh and args[:2] == ["release", "edit"]:
    if state.read_text() != "draft": raise SystemExit("refusing unexpected release state")
    state.write_text("published")
else:
    raise SystemExit("unexpected release mutation in reuse fixture")
''')
            gh.chmod(0o700)
            for name, body in (("gpg", '#!/bin/sh\ncase " $* " in *" --import "*) cat >/dev/null;; *" --detach-sign "*) for last do :; done; printf "fixture signature" > "$last.asc";; *" --export "*) echo "fixture public key";; esac\n'), ("gpgconf", '#!/bin/sh\nexit 0\n')):
                path = binary / name
                path.write_text(body)
                path.chmod(0o700)
            log = base / "publications"
            environment = dict(os.environ, PATH=str(binary) + ":" + os.environ["PATH"], APT_SIGNING_KEY="FIXTURE_PRIVATE_KEY",
                               APT_SIGNING_FINGERPRINT="A" * 40, GITHUB_REPOSITORY="jasonachkar/lasa", RUNNER_TEMP=directory,
                               LASA_RELEASE_PROVIDER="local", LASA_RELEASE_BRANCH="feature/lasa", FIXTURE_PROVIDER=provider,
                               FIXTURE_REVISION="f" * 40 if advanced else revision, FIXTURE_LOG=str(log),
                               FIXTURE_GITHUB_ORIGIN="1" if github_origin else "0", FIXTURE_TAG_MISMATCH="1" if tag_mismatch else "0",
                               FIXTURE_FRESH="1" if fresh else "0", FIXTURE_STATE=str(base / "release-state"))
            result = subprocess.run(["bash", "scripts/release.sh"], cwd=source, env=environment, text=True, capture_output=True, timeout=10)
            self.assertNotIn("FIXTURE_PRIVATE_KEY", result.stdout + result.stderr)
            if provider != "local" or advanced or tag_mismatch:
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(log.exists())
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(log.read_text().splitlines(), ["docs 0.1.0", "packages " + ("github" if github_origin else "openpgp"), "docs current"])
                if fresh:
                    self.assertEqual((base / "release-state").read_text(), "published")
                    self.assertTrue((source / "dist/SHA256SUMS.asc").exists())

    def test_published_openpgp_release_is_reused_without_rebuild(self):
        self.exercise()

    def test_existing_github_release_keeps_attestation_policy(self):
        self.exercise(github_origin=True)

    def test_changed_provider_stops_before_publication(self):
        self.exercise(provider="azure")

    def test_advanced_source_branch_stops_before_publication(self):
        self.exercise(advanced=True)

    def test_existing_release_for_another_commit_cannot_be_reused(self):
        self.exercise(tag_mismatch=True)

    def test_new_release_allocates_tag_uploads_all_formats_and_publishes_docs(self):
        self.exercise(fresh=True)


if __name__ == "__main__":
    unittest.main()
