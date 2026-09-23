#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
[[ -f "${STATE_DIR}/roa-object-name" ]] || { log "ERROR: run 3_roa_issue.sh first"; exit 1; }
OBJECT_NAME="$(<"${STATE_DIR}/roa-object-name")"; PREFIX_ARGS=()
for prefix in "${E2E_ROA_PREFIXES[@]}"; do PREFIX_ARGS+=(--prefix "${prefix}"); done
compose exec -T rpki-ca rpki-ca verify-roa --dir "${CONTAINER_CA_DIR}" --object="${OBJECT_NAME}" \
  --asn "${E2E_ROA_ASN}" "${PREFIX_ARGS[@]}"
log "[PASS] ROA payload, EE certificate, CRL, and Manifest verified"
