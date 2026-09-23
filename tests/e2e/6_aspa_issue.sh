#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
for command in curl sed grep sha256sum wc; do require_command "${command}"; done
prepare_environment
REQUEST="$(aspa_request_json)"
log "ASPA input: Customer AS${E2E_ASPA_CUSTOMER_ASN}; Providers: ${E2E_ASPA_PROVIDER_ASNS[*]}"
RESPONSE="$(curl --silent --show-error --fail --request POST "${BASE_URL}/api/v1/aspas" \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header 'Content-Type: application/json' --data "{\"added\":[${REQUEST}],\"removed\":[]}")"
log "API response: ${RESPONSE}"
OBJECT_NAME="$(printf '%s' "${RESPONSE}" | sed -n 's/.*"object_name":"\([^"]*\)".*/\1/p')"
[[ "${OBJECT_NAME}" =~ ^[A-Za-z0-9_-]{27}\.asa$ ]] || { log "ERROR: object_name is not the RFC 6481 key-derived ASPA name"; exit 1; }
printf '%s' "${RESPONSE}" | grep -q '"created":\["aspa:AS' || { log "ERROR: ASPA was not newly created"; exit 1; }
printf '%s' "${OBJECT_NAME}" >"${STATE_DIR}/aspa-object-name"
DOWNLOAD_DIR="${STATE_DIR}/downloads"; mkdir -p "${DOWNLOAD_DIR}"
CERT_NAME="$(publication_name cer)"
CRL_NAME="$(publication_name crl)"
MANIFEST_NAME="$(publication_name mft)"
log "RFC 6481 publication names: ${CERT_NAME}, ${CRL_NAME}, ${MANIFEST_NAME}"
for name in "${CERT_NAME}" "${CRL_NAME}" "${MANIFEST_NAME}" "${OBJECT_NAME}"; do
  curl --silent --show-error --fail "${BASE_URL}/repository/${name}" --output "${DOWNLOAD_DIR}/${name}"
  log "Downloaded ${name}: $(wc -c <"${DOWNLOAD_DIR}/${name}") bytes"
done
sha256sum "${DOWNLOAD_DIR}/${OBJECT_NAME}"
log "[PASS] ASPA issued and publication set downloaded"
