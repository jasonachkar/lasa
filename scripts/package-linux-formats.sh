#!/usr/bin/env bash
# Supplement the existing DEB/archive build with native RPM, Pacman and APK packages.
set -euo pipefail
version=${1:?Usage: package-linux-formats.sh VERSION STAGING_ROOT}
stage=${2:?Missing staging root}
cd "$(dirname "$0")/.."
bash scripts/install-packaging-tools.sh
nfpm="$PWD/.build/package-tools/nfpm-2.48.0/nfpm"
for arch in amd64 arm64; do
  case "$arch" in amd64) native=x86_64;; arm64) native=aarch64;; esac
  config="$stage/nfpm-$arch.json"
  python3 - "$stage/$arch/usr" "$config" "$version" "$arch" <<'PY'
import json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
contents = [{'src': str(p), 'dst': '/usr/' + p.relative_to(root).as_posix(),
             'file_info': {'mode': p.stat().st_mode & 0o777, 'owner': 'root', 'group': 'root'}}
            for p in sorted(root.rglob('*')) if p.is_file()]
config = {'name': 'lasa', 'arch': sys.argv[4], 'platform': 'linux', 'version': sys.argv[3], 'release': '1',
          'maintainer': 'Jason Achkar Diab <jasonachkardiab@gmail.com>', 'license': 'MIT',
          'homepage': 'https://lasa.secureobs.com/', 'description': 'Read-only Linux attack surface analyzer. Requires openat2 and visible procfs. Installation starts no service or scan.',
          'contents': contents, 'rpm': {'summary': 'Linux attack surface analyzer', 'buildhost': 'lasa-release', 'compression': 'gzip'},
          'archlinux': {'packager': 'Jason Achkar Diab <jasonachkardiab@gmail.com>'}}
if os.environ.get('RPM_SIGNING_KEY_FILE'):
    fingerprint = os.environ['APT_SIGNING_FINGERPRINT']
    config['rpm']['signature'] = {'key_file': os.environ['RPM_SIGNING_KEY_FILE'], 'key_id': fingerprint[-16:]}
pathlib.Path(sys.argv[2]).write_text(json.dumps(config))
PY
  "$nfpm" package --packager rpm --config "$config" --target "dist/lasa-$version-1.$native.rpm"
  "$nfpm" package --packager archlinux --config "$config" --target "dist/lasa-$version-1-$native.pkg.tar.zst"
  "$nfpm" package --packager apk --config "$config" --target "dist/lasa-$version-r1-$native.apk"
  if [ -n "${APK_SIGNING_KEY_FILE:-}" ]; then
    python3 scripts/sign-apk.py "dist/lasa-$version-r1-$native.apk" "$APK_SIGNING_KEY_FILE"
  fi
done
