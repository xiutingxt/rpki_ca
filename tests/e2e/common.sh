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
  export REPOSITORY_URI="${E2E_REPOSITORY_URI}"
  export CA_NAME="${E2E_CA_NAME}"
  export DEVELOPMENT_CA_VALIDITY_DAYS="${E2E_DEVELOPMENT_CA_VALIDITY_DAYS}"
  export CA_RESOURCES="${E2E_CA_RESOURCES[*]}"
  export CA_AS_RESOURCES="${E2E_CA_AS_RESOURCES[*]}"
  mkdir -p "${STATE_DIR}"
}

publication_name() {
  local extension="$1" names
  names="$(compose exec -T rpki-ca find /data/repository -maxdepth 1 -type f -name "*.${extension}" -printf '%f\n' | tr -d '\r')"
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
  printf '{"asn":%s,"prefixes":[' "${E2E_ROA_ASN}"
  for spec in "${E2E_ROA_PREFIXES[@]}"; do
    prefix="${spec%,*}"
    max_length="${spec##*,}"
    printf '%s{"prefix":"%s","max_length":%s}' \
      "${separator}" "${prefix}" "${max_length}"
    separator=","
  done
  printf ']}'
}
