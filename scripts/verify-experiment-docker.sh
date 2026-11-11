#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
if command -v cygpath >/dev/null 2>&1; then PROJECT_DIR="$(cygpath -m "$PROJECT_DIR")"; fi
MSYS_NO_PATHCONV=1 docker run --rm --entrypoint python3 --mount "type=bind,source=$PROJECT_DIR,target=/work,readonly" --workdir /work "${RPKI_CA_TOOLS_IMAGE:-rpki-ca-tools:local}" /opt/rpki-tools/independent_verify.py "$@"
