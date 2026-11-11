"""Run with Python; OPENSSL may select an explicit OpenSSL executable."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "independent", Path(__file__).resolve().parents[1] / "scripts/independent_verify.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class IndependentChecks(unittest.TestCase):
    def test_real_signature_and_tampering_with_recomputed_inventory(self):
        openssl = os.environ.get("OPENSSL", "openssl")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repository"
            repo.mkdir()
            content = root / "content"
            content.write_bytes(b"independent CMS test")
            key, cert, signed = root / "key.pem", root / "cert.pem", repo / "test.toa"
            def run(*args):
                subprocess.run([openssl, *map(str, args)], check=True, capture_output=True)
            run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=test",
                "-days", "1", "-keyout", key, "-out", cert)
            run("cms", "-sign", "-binary", "-nodetach", "-in", content,
                "-signer", cert, "-inkey", key, "-outform", "DER", "-out", signed)
            def inventory():
                (root / "experiment.json").write_text(json.dumps({"format_version": 4,
                    "repository_sha256": {signed.name: hashlib.sha256(signed.read_bytes()).hexdigest()}}))
            inventory()
            self.assertEqual(checker.verify(root, openssl)["status"], "valid")
            raw = signed.read_bytes()
            signed.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
            self.assertEqual(checker.verify(root, openssl)["error"]["code"], "sha256")
            inventory()
            self.assertEqual(checker.verify(root, openssl)["error"]["code"], "cms_signature")
            signed.unlink()
            self.assertEqual(checker.verify(root, openssl)["error"]["code"], "inventory")


if __name__ == "__main__":
    unittest.main()
