#!/usr/bin/env python3
"""Prevent a retried older release from moving the documentation alias back."""
import json
from pathlib import Path
import re
import sys


def semver(value):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError(f"Expected a stable documentation version, got {value!r}")
    return tuple(map(int, value.split(".")))


try:
    requested = semver(sys.argv[1])
    versions = json.loads(Path(sys.argv[2]).read_text())
    if not isinstance(versions, list) or any(not isinstance(item, dict) or not isinstance(item.get("version"), str) or not isinstance(item.get("aliases", []), list) for item in versions):
        raise ValueError("The existing version index must be a list of version/alias objects")
    latest = [item["version"] for item in versions if "latest" in item.get("aliases", [])]
    if len(latest) > 1:
        raise ValueError("The existing site has multiple latest aliases")
    published = [(semver(item["version"]), item["version"]) for item in versions
                 if item["version"] not in {"current", "preview"}]
    if published:
        newest, newest_label = max(published)
        if requested < newest:
            raise ValueError(f"Refusing to roll back documentation from {newest_label} to {sys.argv[1]}")
except (ValueError, KeyError, TypeError, OSError, IndexError) as error:
    raise SystemExit(f"Documentation version validation failed: {error}")
