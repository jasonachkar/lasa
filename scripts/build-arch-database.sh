#!/usr/bin/env bash
# Pacman 6 embeds package signatures by default; 7 requires --include-sigs.
set -euo pipefail
[[ $# = 2 ]] || { echo 'Usage: build-arch-database.sh REPOSITORY_DIRECTORY PACKAGE_FILENAME' >&2; exit 1; }
directory=$(cd "$1" && pwd)
package=$2
[[ $package =~ ^lasa-([0-9]+\.[0-9]+\.[0-9]+)-1-(x86_64|aarch64)\.pkg\.tar\.zst$ ]] || {
  echo 'Unexpected LASA Arch package filename.' >&2; exit 1;
}
package_version="${BASH_REMATCH[1]}-1"
if [ ! -s "$directory/$package" ] || [ ! -s "$directory/$package.sig" ]; then
  echo 'Arch package and detached signature are required.' >&2
  exit 1
fi
version=$(LC_ALL=C repo-add --version)
[[ $version =~ ^repo-add\ \(pacman\)\ ([0-9]+)\. ]] || { echo 'Cannot identify the installed repo-add version; no database was updated.' >&2; exit 1; }
case "${BASH_REMATCH[1]}" in
  6) options=(--prevent-downgrade);;
  7) options=(--include-sigs --prevent-downgrade);;
  *) echo 'Arch publication requires a supported repo-add 6.x or 7.x; no database was updated.' >&2; exit 1;;
esac
(cd "$directory" && repo-add "${options[@]}" lasa.db.tar.gz "$package")
# Confirm the security property independently of repo-add's option/default rules.
# This supplements the caller's real GPG verification; it does not replace it.
python3 - "$directory" "$package" "$package_version" <<'PY'
import base64, hashlib, pathlib, sys, tarfile
root, package, version = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
expected_entry = 'lasa-' + version + '/desc'
try:
    with (root / (package + '.sig')).open('rb') as stream:
        expected_signature = stream.read((1 << 20) + 1)
        if len(expected_signature) > 1 << 20:
            raise ValueError('package signature exceeds the metadata budget')
    digest = hashlib.sha256()
    with (root / package).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    expected_hash = digest.hexdigest()
    for name in ('lasa.db.tar.gz', 'lasa.files.tar.gz'):
        description = None
        with tarfile.open(root / name, 'r|gz') as archive:
            total = 0
            for count, entry in enumerate(archive, 1):
                total += entry.size
                if count > 128 or entry.size > 1 << 20 or total > 8 << 20:
                    raise ValueError(name + ' exceeds the metadata budget')
                if entry.name == expected_entry:
                    if description is not None or not entry.isfile():
                        raise ValueError(name + ' has an ambiguous/non-regular package description')
                    description = archive.extractfile(entry).read().decode('utf-8')
                elif entry.name.endswith('/desc'):
                    raise ValueError(name + ' contains unexpected package/version metadata')
        if description is None:
            raise ValueError(name + ' lacks the expected LASA package description')
        fields = {}
        for block in description.strip().split('\n\n'):
            if not block.strip():
                continue
            lines = block.splitlines()
            if lines[0] in fields:
                raise ValueError(name + ' contains duplicate metadata fields')
            fields[lines[0]] = lines[1:]
        for key, value in (('%NAME%', 'lasa'), ('%VERSION%', version), ('%FILENAME%', package), ('%SHA256SUM%', expected_hash)):
            if fields.get(key) != [value]:
                raise ValueError(name + ' has inconsistent ' + key + ' metadata')
        encoded = ''.join(fields.get('%PGPSIG%', []))
        if not encoded or base64.b64decode(encoded, validate=True) != expected_signature:
            raise ValueError(name + ' does not embed the matching detached package signature (PGPSIG)')
except (OSError, ValueError, UnicodeError, tarfile.TarError) as error:
    raise SystemExit('Arch repository validation failed: ' + str(error)) from None
PY
