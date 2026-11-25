#!/usr/bin/env python3
"""Deterministically convert an ASCII-armored OpenPGP public key to binary.

Used for the keyring shipped in the DEB, so packaging needs no GnuPG state and
produces identical bytes on every build. The armor checksum is verified.
"""
import base64
import sys


def crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def dearmor(text: str) -> bytes:
    lines = text.replace("\r\n", "\n").split("\n")
    begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = "-----END PGP PUBLIC KEY BLOCK-----"
    if lines.count(begin) != 1 or lines.count(end) != 1:
        raise ValueError("expected exactly one armored public key block")
    body = lines[lines.index(begin) + 1:lines.index(end)]
    # Armor headers end at the first blank line.
    if "" in body:
        body = body[body.index("") + 1:]
    checksum = None
    if body and body[-1].startswith("="):
        checksum = body.pop()[1:]
    data = base64.b64decode("".join(body), validate=True)
    if not data:
        raise ValueError("empty key block")
    if checksum is not None:
        expected = int.from_bytes(base64.b64decode(checksum, validate=True), "big")
        if crc24(data) != expected:
            raise ValueError("armor checksum mismatch")
    # Packet tag 6 (public key) must come first.
    first = data[0]
    tag = (first & 0x3F) if first & 0x40 else ((first >> 2) & 0x0F)
    if not first & 0x80 or tag != 6:
        raise ValueError("data does not start with a public key packet")
    return data


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: dearmor.py INPUT.asc OUTPUT.gpg")
    try:
        with open(sys.argv[1], encoding="ascii") as source:
            payload = dearmor(source.read())
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise SystemExit(f"Cannot dearmor {sys.argv[1]}: {error}")
    with open(sys.argv[2], "wb") as output:
        output.write(payload)
