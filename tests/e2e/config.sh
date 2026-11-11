#!/usr/bin/env bash

# Docker Compose test environment.
E2E_PROJECT_NAME="rpki-ca-e2e"
E2E_API_PORT="3100"
E2E_API_TOKEN="e2e-test-token-do-not-use-in-production"
E2E_IDEMPOTENCY_KEY="e2e-roa-request-001"
E2E_ASPA_IDEMPOTENCY_KEY="e2e-aspa-request-001"
E2E_TOA_IDEMPOTENCY_KEY="e2e-toa-request-001"
E2E_SISPI_IDEMPOTENCY_KEY="e2e-sispi-request-001"

# Development CA initialized for this isolated test.
E2E_REPOSITORY_URI="rsync://localhost/e2e/"
E2E_CA_NAME="e2e-development-ca"
E2E_DEVELOPMENT_CA_VALIDITY_DAYS="30"
E2E_CA_RESOURCES=(
  "192.0.2.0/24"
  "2001:db8::/48"
)
E2E_CA_AS_RESOURCES=("64496")

# ROA request and expected verification result. Each entry is PREFIX,MAX_LENGTH.
E2E_ROA_ASN="64496"
E2E_ROA_PREFIXES=(
  "192.0.2.0/24,26"
  "2001:db8::/48,64"
)

E2E_ASPA_CUSTOMER_ASN="64496"
E2E_ASPA_PROVIDER_ASNS=("64497" "64498")

E2E_TOA_ASNS=("0" "64496" "64497")
E2E_TOA_PREFIXES=("192.0.2.0/24" "2001:db8::/48")

E2E_SISPI_ASN="64496"
E2E_SISPI_ADDRESSES=("192.0.2.1" "2001:db8::1")
