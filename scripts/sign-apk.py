#!/usr/bin/env python3
"""Wrap an APK v2 control/index gzip member with an OpenSSL RSA/SHA-256 signature.

No cryptographic primitive is implemented here. The APK v2 wire layout follows
abuild-sign: a cut tar signature member, then the original gzip stream(s).
"""
import argparse
import gzip
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import zlib


def sign(path, key):
    with path.open('rb') as source:
        raw = source.read((128 << 20) + 1)
    if len(raw) > 128 << 20:
        raise ValueError('APK/index exceeds the 128MiB signing budget')
    decoder = zlib.decompressobj(31)
    control = decoder.decompress(raw, 8 << 20)
    if not decoder.eof:
        raise ValueError('Invalid or oversized APK control/index gzip member')
    with tarfile.open(fileobj=io.BytesIO(control), mode='r:') as archive:
        names = archive.getnames()
    if any(name.startswith('.SIGN.') for name in names):
        raise ValueError('Refusing to add another signature to an already signed APK/index')
    if not ('.PKGINFO' in names or 'APKINDEX' in names):
        raise ValueError('Expected an unsigned APK v2 control member or APKINDEX')
    member = raw[:len(raw) - len(decoder.unused_data)]
    signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(key), '-passin', 'pass:'], input=member,
                               stdout=subprocess.PIPE, check=True, timeout=30).stdout
    entry = tarfile.TarInfo('.SIGN.RSA256.lasa.rsa.pub')
    entry.mode, entry.uid, entry.gid = 0o644, 0, 0
    entry.mtime, entry.size = int(os.environ.get('SOURCE_DATE_EPOCH', '0')), len(signature)
    # APK concatenates tar members without the normal end-of-archive zero blocks.
    cut_tar = entry.tobuf(format=tarfile.USTAR_FORMAT) + signature + b'\0' * (-len(signature) % 512)
    signed = gzip.compress(cut_tar, compresslevel=9, mtime=0) + raw
    fd, name = tempfile.mkstemp(prefix='.lasa-apk-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as target:
            target.write(signed)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('key', type=Path)
    args = parser.parse_args()
    try:
        sign(args.path, args.key)
    except (ValueError, OSError, zlib.error, tarfile.TarError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'APK signing failed for {args.path}: {error}\n')
