#!/usr/bin/env python3
"""Create or verify an exact, flat manifest of versioned LASA release assets."""

import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit


def verify_sboms(directory, version, canonicalize=False):
    for arch in ("amd64", "arm64"):
        path = directory / f"lasa-{arch}.cdx.json"
        sbom = json.loads(path.read_text())
        component = sbom["metadata"]["component"]
        components = sbom["components"]
        if sbom["bomFormat"] != "CycloneDX" or component["version"] != f"v{version}":
            raise ValueError(f"{arch}: invalid CycloneDX metadata")
        if not component["name"].endswith("/lasa") or not components:
            raise ValueError(f"{arch}: missing LASA identity or dependencies")
        target = parse_qs(urlsplit(component["purl"]).query)
        if target.get("goos") != ["linux"] or target.get("goarch") != [arch]:
            raise ValueError(f"{arch}: incorrect target platform in SBOM")
        module_allowlist = Path(__file__).resolve().parents[2] / "tools/dependencies.allow"
        expected_modules = set(module_allowlist.read_text().splitlines())
        expected_modules.remove("github.com/jasonachkar/lasa")
        expected_modules.add("std")
        if {dep["name"] for dep in components} != expected_modules:
            raise ValueError(f"{arch}: unexpected Go dependency inventory")
        if canonicalize:
            # CycloneDX allows omission of the generator's wall-clock metadata.
            sbom["metadata"].pop("timestamp", None)
            path.write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n")


def asset_names(version):
    names = [f"lasa-{version}-licenses.tar.gz"]
    for arch in ("amd64", "arm64"):
        binary = f"lasa-{version}-linux-{arch}"
        names.extend((binary, binary + ".tar.gz", f"lasa_{version}_{arch}.deb",
                      f"lasa-{arch}.cdx.json"))
    return sorted(names)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--sboms", action="store_true")
    mode.add_argument("--canonicalize-sboms", action="store_true")
    parser.add_argument("directory", type=Path)
    parser.add_argument("version")
    args = parser.parse_args()
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", args.version):
        parser.error("expected a stable version")

    try:
        names = asset_names(args.version)
        if not (args.sboms or args.canonicalize_sboms):
            entries = {entry.name: entry for entry in args.directory.iterdir()}
            if set(entries) - {"SHA256SUMS"} != set(names):
                raise ValueError("missing or unexpected release assets")
            if any(entry.is_symlink() or not entry.is_file() for entry in entries.values()):
                raise ValueError("release assets must be regular files")
            lines = []
            for name in names:
                entry = entries[name]
                if entry.stat().st_size == 0:
                    raise ValueError(f"empty release asset: {name}")
                with entry.open("rb") as asset:
                    lines.append(f"{hashlib.file_digest(asset, 'sha256').hexdigest()}  {name}\n")
            expected = "".join(lines).encode("ascii")
            manifest = args.directory / "SHA256SUMS"
            if args.write:
                manifest.write_bytes(expected)
            elif manifest.read_bytes() != expected:
                raise ValueError("the manifest does not exactly match the release assets")
        verify_sboms(args.directory, args.version, args.canonicalize_sboms)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f"Release asset verification failed: {error}\n")


if __name__ == "__main__":
    main()
