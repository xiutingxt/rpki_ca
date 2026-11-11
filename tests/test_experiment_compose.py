import argparse
import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "experiment_compose", ROOT / "scripts" / "experiment_compose.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExperimentComposeTests(unittest.TestCase):
    def request(self, directory: Path) -> Path:
        path = directory / "request.json"
        path.write_text(
            json.dumps(
                {
                    "ca": {"name": "compose-test"},
                    "valid_days": 30,
                    "resources": ["192.0.2.0/24"],
                    "asn_resources": [64496],
                    "objects": [
                        {
                            "kind": "roa",
                            "definition": {
                                "asn": 64496,
                                "prefixes": [
                                    {"prefix": "192.0.2.0/24", "max_length": 24}
                                ],
                            },
                        },
                        {
                            "kind": "aspa",
                            "definition": {
                                "customer_asn": 64496,
                                "provider_asns": [64497],
                            },
                        },
                        {
                            "kind": "toa",
                            "definition": {
                                "asns": [64496],
                                "prefixes": ["192.0.2.0/24"],
                                "roa_overlap_justification": "API test",
                            },
                        },
                        {
                            "kind": "sispi",
                            "definition": {
                                "asn": 64496,
                                "addresses": ["192.0.2.1"],
                            },
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_prepare_maps_experiment_settings_to_compose(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            request = self.request(directory)
            base_env = directory / "base.env"
            base_env.write_text(
                "API_TOKEN=test-token\nRPKI_CA_IMAGE_VERSION=testing\n",
                encoding="utf-8",
            )
            output = directory / "generated.env"

            MODULE.prepare(
                argparse.Namespace(
                    request=request,
                    base_env=base_env,
                    output_env=output,
                    data_dir=Path(r"C:\work\ca-data"),
                    api_port=3300,
                    token=None,
                )
            )
            values = MODULE.read_dotenv(output)

            self.assertEqual(values["CA_NAME"], "compose-test")
            self.assertEqual(values["CA_RESOURCES"], "192.0.2.0/24")
            self.assertEqual(values["CA_AS_RESOURCES"], "64496")
            self.assertEqual(values["PUBLISH_NEXT_HOURS"], "720")
            self.assertEqual(values["PUBLISH_NEXT_JITTER_HOURS"], "0")
            self.assertEqual(values["CA_DATA_DIR"], "C:/work/ca-data")
            self.assertEqual(values["API_TOKEN"], "test-token")

    def test_submit_uses_delta_endpoints_and_skips_existing_roa(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            request = self.request(directory)
            env_file = directory / "generated.env"
            env_file.write_text('API_TOKEN="test-token"\n', encoding="utf-8")
            calls = []

            def fake_http(method, url, token, payload=None):
                calls.append((method, url, token, payload))
                if method == "GET":
                    return [
                        {
                            "asn": 64496,
                            "prefix": "192.0.2.0/24",
                            "max_length": None,
                            "comment": None,
                            "roa_objects": ["example.roa"],
                        }
                    ]
                return {"status": "ok"}

            with redirect_stdout(io.StringIO()):
                with mock.patch.object(MODULE, "http_json", side_effect=fake_http):
                    MODULE.submit(
                        argparse.Namespace(
                            request=request,
                            env_file=env_file,
                            base_url="http://127.0.0.1:3300",
                        )
                    )

            self.assertEqual(calls[0][0:3], ("GET", "http://127.0.0.1:3300/api/v1/roas", "test-token"))
            posts = [call for call in calls if call[0] == "POST"]
            self.assertEqual(len(posts), 3)
            self.assertEqual(
                [call[1].rsplit("/", 1)[-1] for call in posts],
                ["aspas", "toas", "sispis"],
            )
            self.assertTrue(all(call[3]["removed"] == [] for call in posts))

    def test_existing_ca_comparison_reads_persisted_schema(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            request = self.request(directory)
            ca_toml = directory / "ca.toml"
            ca_toml.write_text(
                '''
name = "compose-test"
repository_uri = "rsync://localhost/rpki/"
certificate_uri = "rsync://localhost/rpki/example.cer"
development_ca_validity_days = 365
ca_renew_before_days = 30
development_resources = ["192.0.2.0/24"]
development_asns = [64496]

[timing]
roa_valid_weeks = 52
aspa_valid_weeks = 52
sispi_valid_weeks = 52
toa_valid_weeks = 52
toa_review_days = 90
publish_next_hours = 720
publish_next_jitter_hours = 0
publish_hours_before_next = 8
'''.lstrip(),
                encoding="utf-8",
            )

            MODULE.check_existing(
                argparse.Namespace(request=request, ca_toml=ca_toml)
            )

            changed = json.loads(request.read_text(encoding="utf-8"))
            changed["ca"]["name"] = "different"
            request.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaises(SystemExit):
                MODULE.check_existing(
                    argparse.Namespace(request=request, ca_toml=ca_toml)
                )


if __name__ == "__main__":
    unittest.main()
