#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if command -v cygpath >/dev/null 2>&1; then PROJECT_DIR="$(cygpath -m "$PROJECT_DIR")"; fi
OPTIONS=(--rm --entrypoint rpki-ca --mount "type=bind,source=$PROJECT_DIR,target=/work" --workdir /work)
if [[ -n "${RPKI_CA_DOCKER_NETWORK:-}" ]]; then OPTIONS+=(--network "$RPKI_CA_DOCKER_NETWORK"); fi
if ! command -v cygpath >/dev/null 2>&1; then OPTIONS+=(--user "$(id -u):$(id -g)"); fi
MSYS_NO_PATHCONV=1 docker run "${OPTIONS[@]}" "${RPKI_CA_IMAGE:-rpki-ca:0.1.0}" "$@"
