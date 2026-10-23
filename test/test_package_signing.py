"""APK v2 RSA256 framing and non-destructive failure checks, with real OpenSSL."""
import gzip
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
import zlib

spec = importlib.util.spec_from_file_location('sign_apk', Path(__file__).resolve().parents[1] / 'scripts/sign-apk.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class APKSignatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / 'private.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(self.key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.public = self.root / 'public.pem'
        subprocess.run(['openssl', 'pkey', '-in', str(self.key), '-pubout', '-out', str(self.public)], check=True)

    def unsigned_index(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:') as archive:
            data = b'P:lasa\nV:1.0.0-r1\nA:x86_64\n\n'
            entry = tarfile.TarInfo('APKINDEX')
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        return gzip.compress(output.getvalue(), mtime=0)

    def test_openssl_verifies_exact_original_control_stream(self):
        path = self.root / 'APKINDEX.tar.gz'
        original = self.unsigned_index()
        path.write_bytes(original)
        module.sign(path, self.key)
        decoder = zlib.decompressobj(31)
        signature_tar = decoder.decompress(path.read_bytes())
        self.assertEqual(decoder.unused_data, original)
        with tarfile.open(fileobj=io.BytesIO(signature_tar), mode='r:') as archive:
            self.assertEqual(archive.getnames(), ['.SIGN.RSA256.lasa.rsa.pub'])
            signature = archive.extractfile('.SIGN.RSA256.lasa.rsa.pub').read()
        signature_path = self.root / 'signature'
        signature_path.write_bytes(signature)
        subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(self.public), '-signature', str(signature_path)], input=original, check=True, stdout=subprocess.DEVNULL)
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        signed = path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'already signed'):
            module.sign(path, self.key)
        self.assertEqual(path.read_bytes(), signed)

    def test_truncated_or_wrong_control_never_replaces_input(self):
        for data in [b'invalid', self.unsigned_index()[:12], gzip.compress(b'not a tar')]:
            path = self.root / 'broken.apk'
            path.write_bytes(data)
            with self.assertRaises((ValueError, zlib.error, tarfile.TarError)):
                module.sign(path, self.key)
            self.assertEqual(path.read_bytes(), data)
            self.assertFalse(list(self.root.glob('.lasa-apk-*')))


if __name__ == '__main__':
    unittest.main()
