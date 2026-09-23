#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
prepare_environment
OBJECT_NAME="$(<"${STATE_DIR}/sispi-object-name")"
RESPONSE="$(curl --silent --show-error --fail --request POST "${BASE_URL}/api/v1/sispis" --header "Authorization: Bearer ${API_TOKEN}" --header 'Content-Type: application/json' --data "{\"added\":[$(sispi_request_json)],\"removed\":[]}")"
printf '%s' "${RESPONSE}" | grep -q "\"object_name\":\"${OBJECT_NAME}\"" || { log "ERROR: SiSPI changed"; exit 1; }
printf '%s' "${RESPONSE}" | grep -q '"unchanged":\["sispi:AS' || { log "ERROR: SiSPI was reissued"; exit 1; }
log "[PASS] SiSPI API is idempotent"
