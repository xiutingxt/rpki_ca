#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
prepare_environment
REQUEST="$(toa_request_json)"
RESPONSE="$(curl --silent --show-error --fail --request POST "${BASE_URL}/api/v1/toas" --header "Authorization: Bearer ${API_TOKEN}" --header 'Content-Type: application/json' --data "${REQUEST}")"
log "TOA API response: ${RESPONSE}"
OBJECT_NAME="$(printf '%s' "${RESPONSE}" | sed -n 's/.*"object_name":"\([^"]*\)".*/\1/p')"
LOGICAL_KEY="$(printf '%s' "${RESPONSE}" | sed -n 's/.*"logical_key":"toa:\([0-9a-f]*\)".*/\1/p')"
[[ "${OBJECT_NAME}" =~ ^[A-Za-z0-9_-]{27}\.toa$ ]] || { log "ERROR: invalid RFC 6481 TOA name"; exit 1; }
[[ "${LOGICAL_KEY}" =~ ^[0-9a-f]{64}$ ]] || { log "ERROR: invalid TOA logical key"; exit 1; }
printf '%s' "${OBJECT_NAME}" >"${STATE_DIR}/toa-object-name"
printf '%s' "${LOGICAL_KEY}" >"${STATE_DIR}/toa-logical-key"
curl --silent --show-error --fail "${BASE_URL}/repository/${OBJECT_NAME}" --output "${STATE_DIR}/${OBJECT_NAME}"
log "[PASS] TOA issued and downloaded as ${OBJECT_NAME}"
