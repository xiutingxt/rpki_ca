#!/usr/bin/env python3
"""Container helpers for the Bash Compose launcher.

The shell script remains the public entry point. This module uses only the
Python standard library to prepare a Compose environment, check an existing
CA, and submit the experiment request through the HTTP API.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import sys
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, NoReturn


DEFAULTS: dict[str, Any] = {
    "name": "offline-experiment",
    "repository_uri": "rsync://localhost/rpki/",
    "development_ca_validity_days": 365,
    "ca_renew_before_days": 30,
    "roa_valid_weeks": 52,
    "aspa_valid_weeks": 52,
    "sispi_valid_weeks": 52,
    "toa_valid_weeks": 52,
    "valid_days": 30,
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"error: {message}")


def load_request(path: Path) -> dict[str, Any]:
    try:
        request = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read request {path}: {error}")

    ca = request.get("ca", {})
    objects = request.get("objects")
    if not isinstance(ca, dict):
        fail("request.ca must be an object")
    if not isinstance(objects, list) or not objects:
        fail("request.objects must be a non-empty array")
    if not isinstance(request.get("resources"), list):
        fail("request.resources must be an array")
    if not isinstance(request.get("asn_resources"), list):
        fail("request.asn_resources must be an array")
    if not request["resources"] and not request["asn_resources"]:
        fail("the development CA needs at least one IP or ASN resource")

    merged = dict(DEFAULTS)
    merged.update(ca)
    request["ca"] = merged
    valid_days = request.get("valid_days", DEFAULTS["valid_days"])
    if not isinstance(valid_days, int) or isinstance(valid_days, bool) or not 1 <= valid_days <= 363:
        fail("request.valid_days must be an integer between 1 and 363")
    request["valid_days"] = valid_days
    if valid_days >= int(merged["development_ca_validity_days"]):
        fail("request.valid_days must leave at least one day before CA expiry")
    for index, item in enumerate(objects):
        if not isinstance(item, dict):
            continue
        kind = item.get("kind")
        weeks = merged.get(f"{kind}_valid_weeks")
        if weeks is not None and valid_days >= int(weeks) * 7:
            fail(
                f"request.valid_days must leave at least one day before "
                f"objects[{index}] {kind} EE expiry"
            )
    return request


def read_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as error:
        fail(f"cannot read Compose environment {path}: {error}")

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            quote = value[0]
            value = value[1:-1]
            if quote == '"':
                value = (
                    value.replace("$$", "$")
                    .replace("\\\"", '"')
                    .replace("\\\\", "\\")
                )
        values[key] = value
    return values


def dotenv_value(value: Any) -> str:
    text = str(value)
    if "\n" in text or "\r" in text:
        fail("Compose environment values cannot contain newlines")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "$$")
    return f'"{escaped}"'


def prepare(args: argparse.Namespace) -> None:
    request = load_request(args.request)
    ca = request["ca"]
    base = read_dotenv(args.base_env)
    token = args.token or os.environ.get("API_TOKEN") or base.get("API_TOKEN")
    if not token:
        fail("API_TOKEN is missing; set it in docker/.env, the environment, or --token")

    values = {
        "RPKI_CA_IMAGE_NAME": base.get("RPKI_CA_IMAGE_NAME", "rpki-ca"),
        "RPKI_CA_IMAGE_VERSION": base.get("RPKI_CA_IMAGE_VERSION", "0.1.0"),
        "CA_DATA_DIR": str(args.data_dir).replace("\\", "/"),
        "API_PORT": args.api_port,
        "API_TOKEN": token,
        "CORS_ORIGIN": base.get("CORS_ORIGIN", ""),
        "CA_NAME": ca["name"],
        "REPOSITORY_URI": ca["repository_uri"],
        "DEVELOPMENT_CA_VALIDITY_DAYS": ca["development_ca_validity_days"],
        "CA_RENEW_BEFORE_DAYS": ca["ca_renew_before_days"],
        "ROA_VALID_WEEKS": ca["roa_valid_weeks"],
        "ASPA_VALID_WEEKS": ca["aspa_valid_weeks"],
        "SISPI_VALID_WEEKS": ca["sispi_valid_weeks"],
        "TOA_VALID_WEEKS": ca["toa_valid_weeks"],
        "TOA_REVIEW_DAYS": base.get("TOA_REVIEW_DAYS", "90"),
        "PUBLISH_NEXT_HOURS": int(request.get("valid_days", 30)) * 24,
        "PUBLISH_NEXT_JITTER_HOURS": 0,
        "PUBLISH_HOURS_BEFORE_NEXT": base.get("PUBLISH_HOURS_BEFORE_NEXT", "8"),
        "CA_RESOURCES": " ".join(str(value) for value in request["resources"]),
        "CA_AS_RESOURCES": " ".join(str(value) for value in request["asn_resources"]),
    }

    args.output_env.parent.mkdir(parents=True, exist_ok=True)
    body = "# Generated by scripts/experiment-compose.sh; contains API_TOKEN.\n"
    body += "".join(f"{key}={dotenv_value(value)}\n" for key, value in values.items())
    args.output_env.write_text(body, encoding="utf-8", newline="\n")
    try:
        args.output_env.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def normalized_uri(value: Any) -> str:
    return str(value).rstrip("/") + "/"


def check_existing(args: argparse.Namespace) -> None:
    if not args.ca_toml.exists():
        return

    request = load_request(args.request)
    request_ca = request["ca"]
    try:
        actual = tomllib.loads(args.ca_toml.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"cannot read existing CA configuration {args.ca_toml}: {error}")

    timing = actual.get("timing", {})
    comparisons = {
        "name": (actual.get("name"), request_ca["name"]),
        "repository_uri": (
            normalized_uri(actual.get("repository_uri", "")),
            normalized_uri(request_ca["repository_uri"]),
        ),
        "development_ca_validity_days": (
            actual.get("development_ca_validity_days"),
            request_ca["development_ca_validity_days"],
        ),
        "ca_renew_before_days": (
            actual.get("ca_renew_before_days"),
            request_ca["ca_renew_before_days"],
        ),
        "roa_valid_weeks": (timing.get("roa_valid_weeks"), request_ca["roa_valid_weeks"]),
        "aspa_valid_weeks": (timing.get("aspa_valid_weeks"), request_ca["aspa_valid_weeks"]),
        "sispi_valid_weeks": (timing.get("sispi_valid_weeks"), request_ca["sispi_valid_weeks"]),
        "toa_valid_weeks": (timing.get("toa_valid_weeks"), request_ca["toa_valid_weeks"]),
        "publish_next_hours": (
            timing.get("publish_next_hours"),
            int(request.get("valid_days", 30)) * 24,
        ),
        "publish_next_jitter_hours": (
            timing.get("publish_next_jitter_hours"),
            0,
        ),
        "resources": (
            sorted(str(value) for value in actual.get("development_resources", [])),
            sorted(str(value) for value in request["resources"]),
        ),
        "asn_resources": (
            sorted(str(value) for value in actual.get("development_asns", [])),
            sorted(str(value) for value in request["asn_resources"]),
        ),
    }
    mismatches = [
        f"  {key}: existing={old!r}, requested={new!r}"
        for key, (old, new) in comparisons.items()
        if old != new
    ]
    if mismatches:
        fail(
            "the data directory already contains a CA with different settings:\n"
            + "\n".join(mismatches)
            + "\nChoose another --data-dir to create a new CA, or use a matching request."
        )


def read_token(path: Path) -> str:
    token = read_dotenv(path).get("API_TOKEN")
    if not token:
        fail(f"API_TOKEN is missing from generated environment {path}")
    return token


def http_json(
    method: str,
    url: str,
    token: str,
    payload: dict[str, Any] | None = None,
) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        fail(f"{method} {url} returned HTTP {error.code}: {body}")
    except urllib.error.URLError as error:
        fail(f"cannot reach {url}: {error.reason}")
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return body.decode("utf-8", errors="replace")


def roa_key(value: dict[str, Any]) -> tuple[Any, Any, Any]:
    prefix = value.get("prefix")
    max_length = value.get("max_length")
    if max_length is None and isinstance(prefix, str):
        try:
            max_length = ipaddress.ip_network(prefix, strict=False).prefixlen
        except ValueError:
            pass
    return value.get("asn"), prefix, max_length


def collect_payloads(request: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    payloads: dict[str, list[dict[str, Any]]] = {
        "roa": [],
        "aspa": [],
        "toa": [],
        "sispi": [],
    }
    for index, item in enumerate(request["objects"]):
        if not isinstance(item, dict):
            fail(f"request.objects[{index}] must be an object")
        kind = item.get("kind")
        definition = item.get("definition")
        if kind not in payloads or not isinstance(definition, dict):
            fail(f"request.objects[{index}] has an unsupported kind or definition")
        if kind == "roa":
            prefixes = definition.get("prefixes")
            if not isinstance(prefixes, list) or not prefixes:
                fail(f"request.objects[{index}].definition.prefixes must be non-empty")
            for prefix in prefixes:
                if not isinstance(prefix, dict) or "prefix" not in prefix:
                    fail(f"request.objects[{index}] contains an invalid ROA prefix")
                config: dict[str, Any] = {
                    "asn": definition.get("asn"),
                    "prefix": prefix["prefix"],
                    "max_length": prefix.get("max_length"),
                }
                payloads["roa"].append(config)
        else:
            payloads[kind].append(definition)
    return payloads


def submit(args: argparse.Namespace) -> None:
    request = load_request(args.request)
    token = read_token(args.env_file)
    base_url = args.base_url.rstrip("/")
    payloads = collect_payloads(request)
    results: dict[str, Any] = {}

    existing_roas = http_json("GET", f"{base_url}/api/v1/roas", token)
    if not isinstance(existing_roas, list):
        fail("GET /api/v1/roas did not return an array")
    existing_keys = {
        roa_key(item) for item in existing_roas if isinstance(item, dict)
    }
    new_roas = [item for item in payloads["roa"] if roa_key(item) not in existing_keys]
    if new_roas:
        results["roas"] = http_json(
            "POST",
            f"{base_url}/api/v1/roas",
            token,
            {"added": new_roas, "removed": []},
        )
    elif payloads["roa"]:
        results["roas"] = "all requested ROA configurations already exist"

    for kind, endpoint in (("aspa", "aspas"), ("toa", "toas"), ("sispi", "sispis")):
        if payloads[kind]:
            results[endpoint] = http_json(
                "POST",
                f"{base_url}/api/v1/{endpoint}",
                token,
                {"added": payloads[kind], "removed": []},
            )

    print(json.dumps(results, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--request", type=Path, required=True)
    prepare_parser.add_argument("--base-env", type=Path, required=True)
    prepare_parser.add_argument("--output-env", type=Path, required=True)
    prepare_parser.add_argument("--data-dir", type=Path, required=True)
    prepare_parser.add_argument("--api-port", type=int, required=True)
    prepare_parser.add_argument("--token")
    prepare_parser.set_defaults(function=prepare)

    check_parser = subparsers.add_parser("check-existing")
    check_parser.add_argument("--request", type=Path, required=True)
    check_parser.add_argument("--ca-toml", type=Path, required=True)
    check_parser.set_defaults(function=check_existing)

    submit_parser = subparsers.add_parser("submit")
    submit_parser.add_argument("--request", type=Path, required=True)
    submit_parser.add_argument("--env-file", type=Path, required=True)
    submit_parser.add_argument("--base-url", required=True)
    submit_parser.set_defaults(function=submit)
    health_parser = subparsers.add_parser("health")
    health_parser.add_argument("--base-url", required=True)
    health_parser.set_defaults(function=lambda args: urllib.request.urlopen(
        args.base_url.rstrip("/") + "/healthz", timeout=2
    ).close())
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
