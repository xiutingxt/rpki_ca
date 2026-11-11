#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
REQUEST="${PROJECT_DIR}/examples/experiment.json"
OUTPUT="${PROJECT_DIR}/data/experiments/$(date -u +%Y%m%d-%H%M%S)-$$"
BINARY=""
VALID_DAYS=""
CA_DIR=""

usage() {
    cat <<'EOF'
Usage: bash scripts/experiment.sh [--request FILE] [--output NEW_DIR] [--binary FILE] [--valid-days DAYS]

Sign and verify an isolated experiment; export public materials without private keys.
Works in Linux Bash and Git Bash. Explicit relative paths use the caller's directory.
By default, build offline into the project's target/ directory and sign the sample JSON.
--binary selects an existing rpki-ca executable and skips the build.
--valid-days overrides JSON valid_days (1..363; default 30), without random jitter.
--ca DIR exports the existing CA's public snapshot without renewing or signing.
         It cannot be combined with --valid-days.
EOF
}

while (($#)); do
    case "$1" in
        --request|--output|--binary|--valid-days|--ca)
            if (($# < 2)) || [[ -z "$2" || "$2" == --* ]]; then
                printf 'Missing value for %s\n' "$1" >&2
                exit 2
            fi
            case "$1" in
                --request) REQUEST="$2" ;;
                --output) OUTPUT="$2" ;;
                --binary) BINARY="$2" ;;
                --valid-days) VALID_DAYS="$2" ;;
                --ca) CA_DIR="$2" ;;
            esac
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$CA_DIR" ]]; then
    [[ -f "$REQUEST" ]] || { printf 'Request file not found: %s\n' "$REQUEST" >&2; exit 1; }
elif [[ -n "$VALID_DAYS" ]]; then
    printf '%s\n' '--valid-days cannot change an existing snapshot.' >&2
    exit 2
fi
[[ ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] || {
    printf 'Output already exists; choose a new directory: %s\n' "$OUTPUT" >&2
    exit 1
}

if [[ -z "$BINARY" ]]; then
    (cd -- "$PROJECT_DIR" && cargo build --locked --offline --target-dir "${PROJECT_DIR}/target")
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) BINARY="${PROJECT_DIR}/target/debug/rpki-ca.exe" ;;
        *) BINARY="${PROJECT_DIR}/target/debug/rpki-ca" ;;
    esac
fi

ARGS=(experiment --request "$REQUEST" --output "$OUTPUT")
if [[ -n "$CA_DIR" ]]; then
    ARGS=(export-experiment --dir "$CA_DIR" --output "$OUTPUT")
fi
if [[ -n "$VALID_DAYS" ]]; then
    ARGS+=(--valid-days "$VALID_DAYS")
fi
"$BINARY" "${ARGS[@]}"
printf 'Experiment bundle: %s\n' "$OUTPUT"
printf 'Verify again: %q verify-experiment --dir %q\n' "$BINARY" "$OUTPUT"
