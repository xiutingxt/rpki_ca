#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
source "${SCRIPT_DIR}/config.sh"
COMPOSE_FILE="${REPO_ROOT}/docker/compose.yaml"
PROJECT_NAME="${RPKI_CA_E2E_PROJECT:-${E2E_PROJECT_NAME}}"
API_PORT="${RPKI_CA_E2E_PORT:-${E2E_API_PORT}}"
BASE_URL="http://127.0.0.1:${API_PORT}"
API_TOKEN="${RPKI_CA_E2E_TOKEN:-${E2E_API_TOKEN}}"
IDEMPOTENCY_KEY="${RPKI_CA_E2E_KEY:-${E2E_IDEMPOTENCY_KEY}}"
STATE_DIR="${E2E_STATE_DIR:-${REPO_ROOT}/target/e2e-state}"
CONTAINER_CA_DIR="/var/lib/rpki/ca"
COMPOSE_COMMAND=()

log() { printf '%s %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*"; }

require_command() {
  command -v "$1" >/dev/null || { log "ERROR: required command not found: $1"; return 1; }
}

detect_compose() {
  require_command docker
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_COMMAND=(docker compose)
  elif command -v docker-compose >/dev/null && docker-compose version >/dev/null 2>&1; then
    COMPOSE_COMMAND=(docker-compose)
  else
    log "ERROR: neither 'docker compose' nor 'docker-compose' is available"
    return 1
  fi
}

compose() {
  ((${#COMPOSE_COMMAND[@]})) || detect_compose
  if [[ "${1:-}" == "exec" ]]; then
    MSYS_NO_PATHCONV=1 "${COMPOSE_COMMAND[@]}" \
      --project-name "${PROJECT_NAME}" --file "${COMPOSE_FILE}" "$@"
  else
    "${COMPOSE_COMMAND[@]}" \
      --project-name "${PROJECT_NAME}" --file "${COMPOSE_FILE}" "$@"
  fi
}

prepare_environment() {
  export API_PORT API_TOKEN
  export CA_DATA_DIR="${STATE_DIR}/ca-data"
  export REPOSITORY_URI="${E2E_REPOSITORY_URI}"
  export CA_NAME="${E2E_CA_NAME}"
  export DEVELOPMENT_CA_VALIDITY_DAYS="${E2E_DEVELOPMENT_CA_VALIDITY_DAYS}"
  export CA_RESOURCES="${E2E_CA_RESOURCES[*]}"
  export CA_AS_RESOURCES="${E2E_CA_AS_RESOURCES[*]}"
  mkdir -p "${STATE_DIR}"
}

publication_name() {
  local extension="$1" names
  names="$(compose exec -T rpki-ca find "${CONTAINER_CA_DIR}/repository" -maxdepth 1 -type f -name "*.${extension}" -printf '%f\n' | tr -d '\r')"
  [[ -n "${names}" && "${names}" != *$'\n'* ]] || {
    log "ERROR: expected exactly one .${extension} repository object, got: ${names:-none}"
    return 1
  }
  printf '%s' "${names}"
}

aspa_request_json() {
  local separator="" provider
  printf '{"customer_asn":%s,"provider_asns":[' "${E2E_ASPA_CUSTOMER_ASN}"
  for provider in "${E2E_ASPA_PROVIDER_ASNS[@]}"; do
    printf '%s%s' "${separator}" "${provider}"
    separator=","
  done
  printf ']}'
}

roa_request_json() {
  local separator="" spec prefix max_length
  printf '{"added":['
  for spec in "${E2E_ROA_PREFIXES[@]}"; do
    prefix="${spec%,*}"
    max_length="${spec##*,}"
    printf '%s{"asn":%s,"prefix":"%s","max_length":%s}' \
      "${separator}" "${E2E_ROA_ASN}" "${prefix}" "${max_length}"
    separator=","
  done
  printf '],"removed":[]}'
}

roa_remove_json() {
  local separator="" spec prefix max_length
  printf '{"added":[],"removed":['
  for spec in "${E2E_ROA_PREFIXES[@]}"; do
    prefix="${spec%,*}"
    max_length="${spec##*,}"
    printf '%s{"asn":%s,"prefix":"%s","max_length":%s}' \
      "${separator}" "${E2E_ROA_ASN}" "${prefix}" "${max_length}"
    separator=","
  done
  printf ']}'
}

toa_request_json() {
  local separator="" value
  printf '{"asns":['
  for value in "${E2E_TOA_ASNS[@]}"; do printf '%s%s' "${separator}" "${value}"; separator=","; done
  printf '],"prefixes":['; separator=""
  for value in "${E2E_TOA_PREFIXES[@]}"; do printf '%s"%s"' "${separator}" "${value}"; separator=","; done
  printf ']}'
}

sispi_request_json() {
  local separator="" value
  printf '{"as_id":%s,"addresses":[' "${E2E_SISPI_AS_ID}"
  for value in "${E2E_SISPI_ADDRESSES[@]}"; do
    printf '%s"%s"' "${separator}" "${value}"
    separator=","
  done
  printf ']}'
}

verify_logical_withdrawal() {
  local endpoint="$1" object_name="$2" crl_name manifest_name response status
  crl_name="$(publication_name crl)"
  manifest_name="$(publication_name mft)"
  response="$(curl --silent --show-error --fail --request DELETE \
    "${BASE_URL}${endpoint}" --header "Authorization: Bearer ${API_TOKEN}")"
  printf '%s' "${response}" | grep -q "\"object_name\":\"${object_name}\"" || {
    log "ERROR: withdrawal response does not identify ${object_name}"
    return 1
  }
  printf '%s' "${response}" | grep -q '"ee_certificate_revoked":true' || {
    log "ERROR: active object EE certificate was not revoked"
    return 1
  }
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    "${BASE_URL}/repository/${object_name}")"
  [[ "${status}" == "404" ]] || {
    log "ERROR: withdrawn object remains downloadable (HTTP ${status})"
    return 1
  }
  local manifest
  manifest="$(curl --silent --show-error --fail \
    "${BASE_URL}/api/v1/repository/objects/${manifest_name}" \
    --header "Authorization: Bearer ${API_TOKEN}")"
  ! printf '%s' "${manifest}" | grep -q "${object_name}" || {
    log "ERROR: Manifest still contains withdrawn object ${object_name}"
    return 1
  }
  local crl
  crl="$(curl --silent --show-error --fail \
    "${BASE_URL}/api/v1/repository/objects/${crl_name}" \
    --header "Authorization: Bearer ${API_TOKEN}")"
  printf '%s' "${crl}" | grep -Eq '"revokedCertificateCount":[1-9][0-9]*' || {
    log "ERROR: CRL contains no revoked certificate after withdrawal"
    return 1
  }
}
