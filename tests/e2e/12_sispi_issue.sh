#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
prepare_environment
REQUEST="$(sispi_request_json)"
RESPONSE="$(curl --silent --show-error --fail --request POST "${BASE_URL}/api/v1/sispis" --header "Authorization: Bearer ${API_TOKEN}" --header 'Content-Type: application/json' --data "{\"added\":[${REQUEST}],\"removed\":[]}")"
log "SiSPI API response: ${RESPONSE}"
OBJECT_NAME="$(printf '%s' "${RESPONSE}" | sed -n 's/.*"object_name":"\([^"]*\)".*/\1/p')"
[[ "${OBJECT_NAME}" =~ ^[A-Za-z0-9_-]{27}\.sav$ ]] || { log "ERROR: invalid RFC 6481 SiSPI name"; exit 1; }
printf '%s' "${OBJECT_NAME}" >"${STATE_DIR}/sispi-object-name"
curl --silent --show-error --fail "${BASE_URL}/repository/${OBJECT_NAME}" --output "${STATE_DIR}/${OBJECT_NAME}"
log "[PASS] SiSPI issued and downloaded as ${OBJECT_NAME}"
