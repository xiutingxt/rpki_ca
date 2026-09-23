#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

[[ -f "${STATE_DIR}/sispi-object-name" ]] || { log "ERROR: run 12_sispi_issue.sh first"; exit 1; }
OBJECT_NAME="$(<"${STATE_DIR}/sispi-object-name")"
log "Withdrawing SiSPI for AS${E2E_SISPI_AS_ID} by stable logical identity"
verify_logical_withdrawal "/api/v1/sispis/${E2E_SISPI_AS_ID}" "${OBJECT_NAME}"
log "[PASS] SiSPI withdrawn and publication metadata renewed"
