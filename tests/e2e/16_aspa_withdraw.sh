#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

[[ -f "${STATE_DIR}/aspa-object-name" ]] || { log "ERROR: run 6_aspa_issue.sh first"; exit 1; }
OBJECT_NAME="$(<"${STATE_DIR}/aspa-object-name")"
log "Withdrawing ASPA for Customer AS${E2E_ASPA_CUSTOMER_ASN} by stable logical identity"
verify_logical_withdrawal "/api/v1/aspas/${E2E_ASPA_CUSTOMER_ASN}" "${OBJECT_NAME}"
log "[PASS] ASPA withdrawn and publication metadata renewed"
