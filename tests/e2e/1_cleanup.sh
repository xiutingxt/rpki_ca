#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

log "Cleaning Compose project '${PROJECT_NAME}', containers, network, and data volume"
if compose down --volumes --remove-orphans > /dev/null 2>&1; then
  log "[PASS] Compose resources removed"
else
  log "[WARN] Compose cleanup returned an error; resources may already be absent"
fi

if [[ -d "${STATE_DIR}" && "${STATE_DIR}" == "${REPO_ROOT}"/target/e2e-* ]]; then
  rm -rf -- "${STATE_DIR}"
  log "Removed test state directory: ${STATE_DIR}"
fi
log "Cleanup complete"
