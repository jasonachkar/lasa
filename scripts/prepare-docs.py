#!/usr/bin/env python3
"""Create an explicit customer-only input tree; never copy the docs parent."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess

root = Path(__file__).resolve().parent.parent
destination = root / ".build/public-docs"
if destination.exists():
    shutil.rmtree(destination)
shutil.copytree(root / "docs/website", destination)
for source in sorted((root / "docs/customer").glob("*.md")):
    text = source.read_text()
    # The website's brand and sidebar already link home; keep the link in source Markdown only.
    text = text.replace("[Documentation home](../../README.md)\n", "")
    text = text.replace("../../deploy/systemd/", "assets/systemd/")
    text = text.replace("../../schemas/", "assets/schemas/")
    if "../maintainer/" in text or "../../README.md" in text:
        raise SystemExit(f"Customer page links to private maintainer content: {source}")
    (destination / source.name).write_text(text)
for name, source in (("systemd", root / "deploy/systemd"), ("schemas", root / "schemas")):
    shutil.copytree(source, destination / "assets" / name)
digest = hashlib.sha256()
for file in sorted(destination.rglob("*")):
    if file.is_file():
        digest.update(file.relative_to(destination).as_posix().encode() + b"\0" + file.read_bytes())
revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
(destination / "build-info.json").write_text(json.dumps({"source_revision": revision, "content_sha256": digest.hexdigest()}, sort_keys=True) + "\n")
print(f"Prepared {len(list(destination.glob('*.md')))} customer pages; maintainer docs excluded")
