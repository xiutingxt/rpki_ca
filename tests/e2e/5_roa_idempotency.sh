#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
for command in curl grep; do require_command "${command}"; done
OBJECT_NAME="$(<"${STATE_DIR}/roa-object-name")"
ERROR_FILE="${STATE_DIR}/duplicate-roa-response.json"
STATUS="$(curl --silent --show-error --output "${ERROR_FILE}" --write-out '%{http_code}' \
  --request POST "${BASE_URL}/api/v1/roas" \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header 'Content-Type: application/json' --data "$(roa_request_json)")"
RESPONSE="$(<"${ERROR_FILE}")"
log "Duplicate authorization response (${STATUS}): ${RESPONSE}"
[[ "${STATUS}" == "422" ]] || { log "ERROR: duplicate ROA authorization was not rejected"; exit 1; }
printf '%s' "${RESPONSE}" | grep -q '"duplicates":\[' || { log "ERROR: structured duplicate detail is missing"; exit 1; }
CURRENT="$(curl --silent --show-error --fail "${BASE_URL}/api/v1/roas" --header "Authorization: Bearer ${API_TOKEN}")"
printf '%s' "${CURRENT}" | grep -q "${OBJECT_NAME}" || { log "ERROR: duplicate request changed the derived ROA"; exit 1; }
log "[PASS] Duplicate ROA authorization rejected without reissuing"
