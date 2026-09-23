#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
prepare_environment
OBJECT_NAME="$(<"${STATE_DIR}/toa-object-name")"; ARGS=()
for value in "${E2E_TOA_ASNS[@]}"; do ARGS+=(--asn "${value}"); done
for value in "${E2E_TOA_PREFIXES[@]}"; do ARGS+=(--prefix "${value}"); done
compose exec -T rpki-ca rpki-ca verify-toa --dir "${CONTAINER_CA_DIR}" --object="${OBJECT_NAME}" "${ARGS[@]}"
log "[PASS] TOA CMS, profile, EE resources, CRL, and Manifest verified"
