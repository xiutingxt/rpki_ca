#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

[[ -f "${STATE_DIR}/toa-object-name" && -f "${STATE_DIR}/toa-logical-key" ]] || { log "ERROR: run 9_toa_issue.sh first"; exit 1; }
OBJECT_NAME="$(<"${STATE_DIR}/toa-object-name")"
LOGICAL_KEY="$(<"${STATE_DIR}/toa-logical-key")"
log "Withdrawing TOA by stable content identity ${LOGICAL_KEY}"
verify_logical_withdrawal "/api/v1/toas/${LOGICAL_KEY}" "${OBJECT_NAME}"
log "[PASS] TOA withdrawn and publication metadata renewed"
