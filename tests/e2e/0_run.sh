#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

MODE="${1:-all}"
case "${MODE}" in all|roa|aspa|toa|sispi) ;; *) printf 'Usage: %s [all|roa|aspa|toa|sispi]\n' "$0" >&2; exit 2 ;; esac
STEP=0
step() { STEP=$((STEP + 1)); printf '\n'; log "===== STEP ${STEP}: $* ====="; }
run_step() { step "$1"; "${BASH}" "${SCRIPT_DIR}/$2"; }
finish() {
  status=$?
  trap - EXIT INT TERM
  if ((status != 0)); then
    log "Test failed with exit code ${status}; container logs follow"
    compose logs --no-color || true
  fi
  step "Clean shared test environment"
  E2E_STATE_DIR="${STATE_DIR}" "${BASH}" "${SCRIPT_DIR}/1_cleanup.sh" || true
  exit "${status}"
}
trap finish EXIT INT TERM

cd "${REPO_ROOT}"
mkdir -p "${REPO_ROOT}/target"
STATE_DIR="$(mktemp -d "${REPO_ROOT}/target/e2e-state.XXXXXX")"
export E2E_STATE_DIR="${STATE_DIR}"

run_step "Remove stale Compose test environment" 1_cleanup.sh
mkdir -p "${STATE_DIR}"
run_step "Start Compose and initialize shared CA" 2_start.sh
if [[ "${MODE}" == all || "${MODE}" == roa ]]; then
  run_step "Issue and download ROA" 3_roa_issue.sh
  run_step "Verify ROA publication set" 4_roa_verify.sh
  run_step "Reject duplicate ROA authorization" 5_roa_idempotency.sh
fi
if [[ "${MODE}" == all || "${MODE}" == aspa ]]; then
  run_step "Issue and download ASPA" 6_aspa_issue.sh
  run_step "Verify ASPA publication set" 7_aspa_verify.sh
  run_step "Verify ASPA API idempotency" 8_aspa_idempotency.sh
fi
if [[ "${MODE}" == all || "${MODE}" == toa ]]; then
  run_step "Issue and download TOA" 9_toa_issue.sh
  run_step "Verify TOA publication set" 10_toa_verify.sh
  run_step "Verify TOA API idempotency" 11_toa_idempotency.sh
fi
if [[ "${MODE}" == all || "${MODE}" == sispi ]]; then
  run_step "Issue and download SiSPI" 12_sispi_issue.sh
  run_step "Verify SiSPI publication set" 13_sispi_verify.sh
  run_step "Verify SiSPI API idempotency" 14_sispi_idempotency.sh
fi
if [[ "${MODE}" == all || "${MODE}" == roa ]]; then
  run_step "Remove ROA authorizations and verify CRL/Manifest transition" 15_roa_withdraw.sh
fi
if [[ "${MODE}" == all || "${MODE}" == aspa ]]; then
  run_step "Withdraw ASPA by Customer ASN" 16_aspa_withdraw.sh
fi
if [[ "${MODE}" == all || "${MODE}" == toa ]]; then
  run_step "Withdraw TOA by content identity" 17_toa_withdraw.sh
fi
if [[ "${MODE}" == all || "${MODE}" == sispi ]]; then
  run_step "Withdraw SiSPI by AS ID" 18_sispi_withdraw.sh
fi
step "End-to-end result"
log "RESULT: PASS - ${MODE} authorization, issuance, download, validation, duplicate, and withdrawal checks passed"
