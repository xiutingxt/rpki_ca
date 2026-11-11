"""Independent public-file inventory and OpenSSL CMS checks, without Rust code.

This deliberately does not claim certificate-path or RPKI profile validation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import sys


def verify(directory, openssl="openssl"):
    report = {
        "status": "invalid",
        "scope": "inventory_sha256_and_cms_signatures_only",
        "limitations": ["no trust-path, revocation, time or RFC3779 validation",
                        "no object profile or expected-payload validation"],
        "checks": {},
    }
    stage, name = "input", None
    try:
        bundle = json.loads((directory / "experiment.json").read_text(encoding="utf-8"))
        if bundle["format_version"] not in (1, 2, 3, 4):
            raise ValueError("unsupported bundle version")
        repo = directory / "repository"
        stage = "inventory"
        names = bundle["repository_sha256"]
        if set(names) != {p.name for p in repo.iterdir()}:
            raise ValueError("repository inventory mismatch")
        for name, expected in names.items():
            if Path(name).name != name or "/" in name or "\\" in name:
                raise ValueError("unsafe repository filename")
            path = repo / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("repository entry must be a regular file")
            stage = "sha256"
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError("SHA-256 mismatch")
            checks = ["sha256"]
            if path.suffix in (".roa", ".asa", ".aspa", ".toa", ".sav", ".mft"):
                stage = "cms_signature"
                with tempfile.TemporaryDirectory(prefix="rpki-cms-") as tmp:
                    result = subprocess.run(
                        [openssl, "cms", "-verify", "-inform", "DER", "-binary",
                         "-in", str(path.resolve()), "-noverify",
                         "-out", str(Path(tmp) / "content.der")],
                        capture_output=True, text=True, check=False,
                    )
                if result.returncode:
                    raise ValueError(result.stderr.strip() or "OpenSSL CMS verification failed")
                checks.append("openssl_cms_signature")
            report["checks"][name] = checks
            stage = "inventory"
        report["status"] = "valid"
    except (OSError, ValueError, KeyError, TypeError) as error:
        report["error"] = {"code": stage, "object": name, "message": str(error)}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", required=True, type=Path)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    report = verify(args.dir, args.openssl)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "valid" else 1


if __name__ == "__main__":
    sys.exit(main())
