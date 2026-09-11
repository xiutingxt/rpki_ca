#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

require_command curl
prepare_environment
log "Building image and starting shared E2E Compose project '${PROJECT_NAME}'"
log "API endpoint: ${BASE_URL}"
COMPOSE_LOG="${STATE_DIR}/compose-up.log"
if ! compose up --detach --build > "${COMPOSE_LOG}" 2>&1; then
  log "ERROR: Compose build/start failed; full output follows"
  cat "${COMPOSE_LOG}"
  exit 1
fi
log "[PASS] Image built and container started"

log "Waiting for API health check"
for attempt in $(seq 1 60); do
  if response="$(curl --silent --show-error --fail "${BASE_URL}/healthz" 2>/dev/null)"; then
    log "Health response: ${response}"
    CERT_NAME="$(publication_name cer)"
    CRL_NAME="$(publication_name crl)"
    MANIFEST_NAME="$(publication_name mft)"
    log "[PASS] CA initialized with ${CERT_NAME}, ${CRL_NAME}, and ${MANIFEST_NAME}"
    exit 0
  fi
  log "Health attempt ${attempt}/60: not ready"
  sleep 2
done
log "ERROR: API did not become healthy"
exit 1
