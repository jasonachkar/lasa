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
    requested = None if sys.argv[1] == "current" else semver(sys.argv[1])
    versions = json.loads(Path(sys.argv[2]).read_text())
    if not isinstance(versions, list) or any(not isinstance(item, dict) or not isinstance(item.get("version"), str) or not isinstance(item.get("aliases", []), list) for item in versions):
        raise ValueError("The existing version index must be a list of version/alias objects")
    names = [item["version"] for item in versions]
    if len(names) != len(set(names)):
        raise ValueError("The existing site has duplicate version entries")
    for item in versions:
        if item["version"] not in ("current", "preview"):
            semver(item["version"])
        if any(not isinstance(alias, str) for alias in item.get("aliases", [])):
            raise ValueError("Documentation aliases must be strings")
    latest = [item["version"] for item in versions if "latest" in item.get("aliases", [])]
    if len(latest) > 1:
        raise ValueError("The existing site has multiple latest aliases")
    released = [semver(name) for name in names if name not in ("current", "preview")]
    if requested is not None and released and requested < max(released):
        newest = ".".join(map(str, max(released)))
        raise ValueError(f"Refusing to roll back documentation from {newest} to {sys.argv[1]}")
    print("latest")
except (ValueError, KeyError, TypeError, OSError, IndexError) as error:
    raise SystemExit(f"Documentation version validation failed: {error}")
