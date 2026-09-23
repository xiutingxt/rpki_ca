#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

for command in curl grep; do require_command "${command}"; done
[[ -f "${STATE_DIR}/roa-object-name" ]] || { log "ERROR: run 3_roa_issue.sh first"; exit 1; }

OBJECT_NAME="$(<"${STATE_DIR}/roa-object-name")"
CRL_NAME="$(publication_name crl)"
MANIFEST_NAME="$(publication_name mft)"
log "Removing desired ROA authorizations that derive ${OBJECT_NAME}"

RESPONSE="$(curl --silent --show-error --fail --request POST \
  "${BASE_URL}/api/v1/roas" \
  --header "Authorization: Bearer ${API_TOKEN}" \
  --header 'Content-Type: application/json' --data "$(roa_remove_json)")"
log "Authorization removal response: ${RESPONSE}"
printf '%s' "${RESPONSE}" | grep -q '"configurations":\[\]' || { log "ERROR: ROA authorizations remain configured"; exit 1; }

HTTP_STATUS="$(curl --silent --output /dev/null --write-out '%{http_code}' \
  "${BASE_URL}/repository/${OBJECT_NAME}")"
[[ "${HTTP_STATUS}" == "404" ]] || {
  log "ERROR: withdrawn object is still downloadable (HTTP ${HTTP_STATUS})"
  exit 1
}

CRL_INSPECTION="$(curl --silent --show-error --fail \
  "${BASE_URL}/api/v1/repository/objects/${CRL_NAME}" \
  --header "Authorization: Bearer ${API_TOKEN}")"
printf '%s' "${CRL_INSPECTION}" | grep -Eq '"revokedCertificateCount":[1-9][0-9]*' || {
  log "ERROR: repository CRL contains no revoked certificates"
  exit 1
}
printf '%s' "${CRL_INSPECTION}" | grep -Eq '"revocationDate":"[^"]+"' || {
  log "ERROR: CRL inspection does not expose revocation dates"
  exit 1
}
if printf '%s' "${CRL_INSPECTION}" | grep -Fq 'Name(['; then
  log "ERROR: CRL issuer is exposed as an ASN.1 debug dump"
  exit 1
fi
printf '%s' "${CRL_INSPECTION}" | grep -q '"signatureAlgorithm":{"name":"sha256WithRSAEncryption","oid":"1.2.840.113549.1.1.11"}' || {
  log "ERROR: CRL inspection does not expose the RFC 6487 signature algorithm"
  exit 1
}

MANIFEST_INSPECTION="$(curl --silent --show-error --fail \
  "${BASE_URL}/api/v1/repository/objects/${MANIFEST_NAME}" \
  --header "Authorization: Bearer ${API_TOKEN}")"
if printf '%s' "${MANIFEST_INSPECTION}" | grep -q "${OBJECT_NAME}"; then
  log "ERROR: new Manifest still lists the withdrawn object"
  exit 1
fi
printf '%s' "${MANIFEST_INSPECTION}" | grep -q "${CRL_NAME}" || {
  log "ERROR: new Manifest does not list the current CRL"
  exit 1
}

log "[PASS] Object removed, EE certificate revoked, and CRL/Manifest atomically renewed"
