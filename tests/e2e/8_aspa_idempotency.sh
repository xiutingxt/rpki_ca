#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
for command in curl grep; do require_command "${command}"; done
OBJECT_NAME="$(<"${STATE_DIR}/aspa-object-name")"
RESPONSE="$(curl --silent --show-error --fail --request POST "${BASE_URL}/api/v1/aspas" \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header 'Content-Type: application/json' --data "{\"added\":[$(aspa_request_json)],\"removed\":[]}")"
log "Repeated API response: ${RESPONSE}"
printf '%s' "${RESPONSE}" | grep -q '"unchanged":\["aspa:AS' || { log "ERROR: ASPA was reissued"; exit 1; }
printf '%s' "${RESPONSE}" | grep -q "\"object_name\":\"${OBJECT_NAME}\"" || { log "ERROR: object changed"; exit 1; }
log "[PASS] ASPA request is idempotent"

UPDATED_RESPONSE="$(curl --silent --show-error --fail --request POST "${BASE_URL}/api/v1/aspas" \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header 'Content-Type: application/json' \
  --data "{\"added\":[{\"customer_asn\":${E2E_ASPA_CUSTOMER_ASN},\"provider_asns\":[64510]}],\"removed\":[]}")"
log "Changed logical-object response: ${UPDATED_RESPONSE}"
printf '%s' "${UPDATED_RESPONSE}" | grep -q '"updated":\["aspa:AS' || { log "ERROR: changed ASPA was not treated as an update"; exit 1; }
UPDATED_NAME="$(printf '%s' "${UPDATED_RESPONSE}" | sed -n 's/.*"object_name":"\([^"]*\)".*/\1/p')"
[[ -n "${UPDATED_NAME}" && "${UPDATED_NAME}" != "${OBJECT_NAME}" ]] || { log "ERROR: ASPA update did not replace the published object"; exit 1; }
OLD_STATUS="$(curl --silent --output /dev/null --write-out '%{http_code}' "${BASE_URL}/repository/${OBJECT_NAME}")"
[[ "${OLD_STATUS}" == "404" ]] || { log "ERROR: replaced ASPA remains downloadable"; exit 1; }
printf '%s' "${UPDATED_NAME}" >"${STATE_DIR}/aspa-object-name"
log "[PASS] Changed Provider set replaced the ASPA and withdrew the previous file"
