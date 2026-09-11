#!/bin/sh
set -eu

initialize_ca() {
    set -- rpki-ca init \
        --dir "${CA_DIR}" \
        --repository-uri "${REPOSITORY_URI}" \
        --name "${CA_NAME}" \
        --development-ca-validity-days "${DEVELOPMENT_CA_VALIDITY_DAYS}" \
        --ca-renew-before-days "${CA_RENEW_BEFORE_DAYS}" \
        --roa-valid-weeks "${ROA_VALID_WEEKS}" \
        --aspa-valid-weeks "${ASPA_VALID_WEEKS}" \
        --publish-next-hours "${PUBLISH_NEXT_HOURS}" \
        --publish-next-jitter-hours "${PUBLISH_NEXT_JITTER_HOURS}" \
        --publish-hours-before-next "${PUBLISH_HOURS_BEFORE_NEXT}"
    for resource in ${CA_RESOURCES}; do
        set -- "$@" --resource "${resource}"
    done
    for asn in ${CA_AS_RESOURCES:-}; do
        set -- "$@" --asn-resource "${asn}"
    done
    "$@"
}

if [ ! -f "${CA_DIR}/ca.toml" ]; then
    echo "Initializing development RPKI CA in ${CA_DIR}"
    initialize_ca
fi

if [ "${1:-idle}" = "idle" ]; then
    exec rpki-ca serve --dir "${CA_DIR}" --bind "${API_BIND}"
fi

exec "$@"
