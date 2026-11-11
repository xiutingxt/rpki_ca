#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
CALLER_DIR="$(pwd -P)"
COMPOSE_FILE="${PROJECT_DIR}/docker/compose.yaml"

REQUEST="${PROJECT_DIR}/examples/experiment.json"
OUTPUT=""
DATA_DIR="${PROJECT_DIR}/data/compose-experiment"
BASE_ENV="${PROJECT_DIR}/docker/.env"
PROJECT_NAME="rpki-ca-experiment"
API_PORT="3000"
API_TOKEN_VALUE=""
BUILD=1
DOWN_AFTER=0

usage() {
  cat <<'EOF'
Usage:
  bash scripts/experiment-compose.sh --output DIR [options]

Starts rpki-ca with Docker Compose, submits an experiment request through the
HTTP API, and exports a self-contained snapshot. The service and CA data are
kept by default so later requests can reuse the same CA.

Options:
  --request FILE       Experiment request JSON (default: examples/experiment.json)
  --output DIR         New host directory for the exported snapshot (required)
  --data-dir DIR       Persistent Compose data (default: data/compose-experiment)
  --env-file FILE      Base Compose environment (default: docker/.env)
  --project-name NAME  Compose project name (default: rpki-ca-experiment)
  --api-port PORT      Published API port (default: 3000)
  --token TOKEN        Override API_TOKEN from the environment/base env file
  --no-build           Do not build the image before starting
  --down-after         Stop and remove the Compose container after export
  -h, --help           Show this help

The request's ca section controls initialization when --data-dir has no CA.
If a CA already exists there, its key settings must match the request. An
export from a reused CA contains all objects currently held by that CA.
Python runs in rpki-ca-tools:local; host Python/Rust are not required.
--no-build requires both the CA and tools images to have been built already.
EOF
}

absolute_path() {
  local value="$1"
  case "$value" in
    /* | [A-Za-z]:/* | [A-Za-z]:\\*) printf '%s\n' "$value" ;;
    *) printf '%s/%s\n' "$CALLER_DIR" "$value" ;;
  esac
}

while (($#)); do
  case "$1" in
    --request) REQUEST="${2:?missing value for --request}"; shift 2 ;;
    --output) OUTPUT="${2:?missing value for --output}"; shift 2 ;;
    --data-dir) DATA_DIR="${2:?missing value for --data-dir}"; shift 2 ;;
    --env-file) BASE_ENV="${2:?missing value for --env-file}"; shift 2 ;;
    --project-name) PROJECT_NAME="${2:?missing value for --project-name}"; shift 2 ;;
    --api-port) API_PORT="${2:?missing value for --api-port}"; shift 2 ;;
    --token) API_TOKEN_VALUE="${2:?missing value for --token}"; shift 2 ;;
    --no-build) BUILD=0; shift ;;
    --down-after) DOWN_AFTER=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$OUTPUT" ]]; then
  echo "error: --output is required" >&2
  usage >&2
  exit 2
fi
if [[ ! "$API_PORT" =~ ^[0-9]+$ ]] || ((API_PORT < 1 || API_PORT > 65535)); then
  echo "error: --api-port must be between 1 and 65535" >&2
  exit 2
fi

REQUEST="$(absolute_path "$REQUEST")"
OUTPUT="$(absolute_path "$OUTPUT")"
DATA_DIR="$(absolute_path "$DATA_DIR")"
BASE_ENV="$(absolute_path "$BASE_ENV")"

[[ -f "$REQUEST" ]] || { echo "error: request not found: $REQUEST" >&2; exit 2; }
[[ -f "$BASE_ENV" ]] || {
  echo "error: Compose environment not found: $BASE_ENV" >&2
  echo "Create it from docker/.env.example and set API_TOKEN." >&2
  exit 2
}
[[ ! -e "$OUTPUT" ]] || { echo "error: output already exists: $OUTPUT" >&2; exit 2; }

TOOLS_IMAGE="${RPKI_CA_TOOLS_IMAGE:-rpki-ca-tools:local}"

if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "error: Docker Compose is required" >&2
  exit 2
fi

mkdir -p -- "$DATA_DIR/ca" "$(dirname -- "$OUTPUT")"
DATA_DIR="$(cd -- "$DATA_DIR" && pwd -P)"
OUTPUT_PARENT="$(cd -- "$(dirname -- "$OUTPUT")" && pwd -P)"
OUTPUT="${OUTPUT_PARENT}/$(basename -- "$OUTPUT")"
GENERATED_ENV="${DATA_DIR}/.experiment-compose.env"

# Convert Git Bash paths before passing bind sources to the Linux Docker daemon.
docker_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi
}
if ((BUILD)); then
  MSYS_NO_PATHCONV=1 docker build --target tools -f "$(docker_path "$PROJECT_DIR/docker/Dockerfile")" -t "$TOOLS_IMAGE" "$(docker_path "$PROJECT_DIR")"
fi
helper() {
  local network="${HELPER_NETWORK:-}" index=0 flag path parent
  local -a mounts=() args=()
  while (($#)); do
    flag="$1"; shift
    case "$flag" in
      --request|--base-env|--output-env|--ca-toml|--env-file)
        path="$1"; shift; parent="$(dirname -- "$path")"
        mounts+=(--mount "type=bind,source=$(docker_path "$parent"),target=/input$index$( [[ "$flag" = --output-env ]] || printf ',readonly' )")
        args+=("$flag" "/input$index/$(basename -- "$path")"); index=$((index + 1)) ;;
      --data-dir) args+=("$flag" "$(docker_path "$1")"); shift ;;
      *) args+=("$flag") ;;
    esac
  done
  local -a options=(--rm --entrypoint python3)
  if command -v id >/dev/null 2>&1 && ! command -v cygpath >/dev/null 2>&1; then options+=(--user "$(id -u):$(id -g)"); fi
  if [[ -n "$network" ]]; then options+=(--network "$network"); fi
  MSYS_NO_PATHCONV=1 docker run "${options[@]}" --env API_TOKEN "${mounts[@]}" "$TOOLS_IMAGE" /opt/rpki-tools/experiment_compose.py "${args[@]}"
}

helper check-existing \
  --request "$REQUEST" \
  --ca-toml "${DATA_DIR}/ca/ca.toml"

PREPARE_ARGS=(
  prepare
  --request "$REQUEST"
  --base-env "$BASE_ENV"
  --output-env "$GENERATED_ENV"
  --data-dir "$DATA_DIR"
  --api-port "$API_PORT"
)
if [[ -n "$API_TOKEN_VALUE" ]]; then
  PREPARE_ARGS+=(--token "$API_TOKEN_VALUE")
fi
helper "${PREPARE_ARGS[@]}"

compose() {
  MSYS_NO_PATHCONV=1 "${COMPOSE[@]}" \
    --env-file "$(docker_path "$GENERATED_ENV")" \
    --project-name "$PROJECT_NAME" \
    --file "$(docker_path "$COMPOSE_FILE")" \
    "$@"
}

cleanup() {
  local status=$?
  if ((DOWN_AFTER)); then
    compose down || true
  fi
  exit "$status"
}
trap cleanup EXIT

UP_ARGS=(up --detach)
if ((BUILD)); then
  UP_ARGS+=(--build)
fi
compose "${UP_ARGS[@]}"

BASE_URL="http://127.0.0.1:${API_PORT}"
HELPER_NETWORK="container:$(compose ps -q rpki-ca)"
CONTAINER_BASE_URL="http://127.0.0.1:3000"
echo "Waiting for ${BASE_URL}/healthz ..."
healthy=0
for _ in $(seq 1 60); do
  if helper health --base-url "$CONTAINER_BASE_URL" >/dev/null 2>&1; then
    healthy=1
    break
  fi
  sleep 2
done
if ((healthy == 0)); then
  echo "error: API did not become healthy; recent container logs follow" >&2
  compose logs --tail 100 rpki-ca >&2 || true
  exit 1
fi

echo "Submitting signed-object requests through the HTTP API ..."
helper submit \
  --request "$REQUEST" \
  --env-file "$GENERATED_ENV" \
  --base-url "$CONTAINER_BASE_URL"

EXPORT_ID="compose-$(date -u +%Y%m%dT%H%M%SZ)-$$"
CONTAINER_OUTPUT="/var/lib/rpki/exports/${EXPORT_ID}"
HOST_STAGING="${DATA_DIR}/exports/${EXPORT_ID}"

echo "Exporting and verifying the CA snapshot ..."
set +e
MSYS_NO_PATHCONV=1 compose exec -T rpki-ca \
  rpki-ca export-experiment \
  --dir /var/lib/rpki/ca \
  --output "$CONTAINER_OUTPUT"
EXPORT_STATUS=$?
set -e

if [[ ! -d "$HOST_STAGING" ]]; then
  echo "error: snapshot was not produced at $HOST_STAGING" >&2
  exit 1
fi
mv -- "$HOST_STAGING" "$OUTPUT"

if ((EXPORT_STATUS != 0)); then
  echo "error: snapshot verification failed; diagnostic files were kept at $OUTPUT" >&2
  exit "$EXPORT_STATUS"
fi

echo "Snapshot: $OUTPUT"
if ((DOWN_AFTER)); then
  echo "Compose service will now be stopped; CA data remains at: $DATA_DIR"
else
  echo "Compose service remains running at: $BASE_URL"
  echo "Persistent CA data: $DATA_DIR"
  echo "Stop it later with:"
  printf '  docker compose --env-file %q --project-name %q --file %q down\n' \
    "$GENERATED_ENV" "$PROJECT_NAME" "$COMPOSE_FILE"
fi
