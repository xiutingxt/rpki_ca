#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
prepare_environment
OBJECT_NAME="$(<"${STATE_DIR}/sispi-object-name")"; ARGS=()
for value in "${E2E_SISPI_ADDRESSES[@]}"; do ARGS+=(--address "${value}"); done
compose exec -T rpki-ca rpki-ca verify-sispi --dir "${CONTAINER_CA_DIR}" --object="${OBJECT_NAME}" --asn "${E2E_SISPI_ASN}" "${ARGS[@]}"
log "[PASS] SiSPI CMS, profile, EE AS resources, CRL, and Manifest verified"
