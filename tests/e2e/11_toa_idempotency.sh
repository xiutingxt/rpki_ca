#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
prepare_environment
OBJECT_NAME="$(<"${STATE_DIR}/toa-object-name")"
RESPONSE="$(curl --silent --show-error --fail --request POST "${BASE_URL}/api/v1/toas" --header "Authorization: Bearer ${API_TOKEN}" --header 'Content-Type: application/json' --data "{\"added\":[$(toa_request_json)],\"removed\":[]}")"
printf '%s' "${RESPONSE}" | grep -q "\"object_name\":\"${OBJECT_NAME}\"" || { log "ERROR: TOA changed"; exit 1; }
printf '%s' "${RESPONSE}" | grep -q '"unchanged":\["toa:' || { log "ERROR: TOA was reissued"; exit 1; }
log "[PASS] TOA API is idempotent"
