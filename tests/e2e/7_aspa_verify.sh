#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
[[ -f "${STATE_DIR}/aspa-object-name" ]] || { log "ERROR: run 6_aspa_issue.sh first"; exit 1; }
OBJECT_NAME="$(<"${STATE_DIR}/aspa-object-name")"; PROVIDER_ARGS=()
for provider in "${E2E_ASPA_PROVIDER_ASNS[@]}"; do PROVIDER_ARGS+=(--provider-asn "${provider}"); done
compose exec -T rpki-ca rpki-ca verify-aspa --dir /data --object "${OBJECT_NAME}" \
  --customer-asn "${E2E_ASPA_CUSTOMER_ASN}" "${PROVIDER_ARGS[@]}"
log "[PASS] ASPA payload, EE certificate, CRL, and Manifest verified"
