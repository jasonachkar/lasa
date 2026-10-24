#!/usr/bin/env python3
"""Load a verified guest's short-lived publication credentials without shell eval."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SECRET_FIELDS = ("GH_TOKEN", "APT_SIGNING_KEY", "APK_SIGNING_KEY", "DISTRIBUTION_DEPLOY_KEY")


def read_credentials(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 1 << 20:
        raise ValueError("Credential file must be a private, owner-controlled regular file under 1 MiB")
    with path.open("rb") as stream:
        content = stream.read((1 << 20) + 1)
    if len(content) > 1 << 20:
        raise ValueError("Credential file exceeds its 1 MiB budget; contents withheld")
    data = json.loads(content)
    if not isinstance(data, dict) or data.get("schema") != "lasa.local-credentials/v1":
        raise ValueError("Invalid local credential schema; contents withheld")
    # Consume only an identified credential payload. A mistaken path to an
    # unrelated private key/config must never delete the owner's original file.
    path.unlink()
    required = SECRET_FIELDS + ("source_revision", "source_branch", "distribution_branch", "APT_SIGNING_FINGERPRINT", "APK_PUBLIC_KEY_SHA256")
    if any(not isinstance(data.get(name), str) or not data[name] or len(data[name]) > 65536 for name in required):
        raise ValueError("Local publication credentials are missing or malformed; values withheld")
    if not re.fullmatch(r"[0-9a-f]{40}", data["source_revision"]) or not re.fullmatch(r"[A-F0-9]{40}", data["APT_SIGNING_FINGERPRINT"]) or not re.fullmatch(r"[a-f0-9]{64}", data["APK_PUBLIC_KEY_SHA256"]):
        raise ValueError("Invalid public revision/signing identity in local publication credentials")
    return data


def publish(path):
    data = read_credentials(path)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    verification = json.loads((ROOT / ".build/local-verification.json").read_text())
    if (not isinstance(verification, dict) or verification.get("schema") != "lasa.local-verification/v1"
            or data["source_revision"] != revision or verification.get("source_revision") != revision or verification.get("verified") is not True):
        raise ValueError("This source revision has no successful local verification record; publication refused")
    for branch in (data["source_branch"], data["distribution_branch"]):
        subprocess.run(["git", "check-ref-format", "--branch", branch], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    environment = dict(os.environ)
    environment.update({name: data[name] for name in SECRET_FIELDS + ("APT_SIGNING_FINGERPRINT", "APK_PUBLIC_KEY_SHA256")})
    environment.update({"GITHUB_REPOSITORY": "jasonachkar/lasa", "DISTRIBUTION_REPOSITORY": "jasonachkar/homebrew-lasa",
                        "GH_HOST": "github.com",
                        "DISTRIBUTION_BRANCH": data["distribution_branch"], "LASA_RELEASE_BRANCH": data["source_branch"],
                        "LASA_RELEASE_PROVIDER": "local", "DOCS_SITE_URL": "https://lasa.secureobs.com/",
                        "APT_REPOSITORY_URL": "https://lasa.secureobs.com/apt"})
    with tempfile.TemporaryDirectory(prefix="lasa-local-release-") as directory:
        environment["RUNNER_TEMP"] = directory
        subprocess.run(["bash", "scripts/release.sh"], cwd=ROOT, env=environment, check=True)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("Usage: local-release.py PRIVATE_CREDENTIAL_FILE")
        publish(Path(sys.argv[1]))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError, KeyboardInterrupt) as error:
        # Never stringify a CalledProcessError: commands and credential values stay private.
        detail = ("publication command failed; see its preceding stage output" if isinstance(error, subprocess.CalledProcessError)
                  else "interrupted" if isinstance(error, KeyboardInterrupt) else str(error))
        print("Local release stopped: " + detail, file=sys.stderr)
        sys.exit(1)
