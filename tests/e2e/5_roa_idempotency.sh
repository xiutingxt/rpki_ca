#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
for command in curl grep; do require_command "${command}"; done
OBJECT_NAME="$(<"${STATE_DIR}/roa-object-name")"
RESPONSE="$(curl --silent --show-error --fail --request POST "${BASE_URL}/api/v1/roas" \
  --header "Authorization: Bearer ${API_TOKEN}" --header "Idempotency-Key: ${IDEMPOTENCY_KEY}" \
  --header 'Content-Type: application/json' --data "$(roa_request_json)")"
log "Repeated API response: ${RESPONSE}"
printf '%s' "${RESPONSE}" | grep -q '"created":false' || { log "ERROR: ROA was reissued"; exit 1; }
printf '%s' "${RESPONSE}" | grep -q "\"object_name\":\"${OBJECT_NAME}\"" || { log "ERROR: object changed"; exit 1; }
log "[PASS] ROA request is idempotent"
