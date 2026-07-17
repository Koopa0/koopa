#!/usr/bin/env bash

set -Eeuo pipefail

DEPLOY_SHA="${1:-}"
if [[ ! "$DEPLOY_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "ERROR: deploy SHA must be exactly 40 lowercase hexadecimal characters"
  exit 1
fi
readonly DEPLOY_SHA

# Do not trust ambient BUILD_SHA or Compose dotenv precedence. Make the
# immutable deploy identity an exported readonly value, then prove the
# effective Compose model agrees before building or replacing containers.
BUILD_SHA="$DEPLOY_SHA"
readonly BUILD_SHA
export BUILD_SHA

# Pin Compose's source, environment and project identity. The VPS shell and
# production .env must not be able to add another Compose file, activate a
# profile, select a second project, or silently remove orphaned services.
DEPLOY_COMPOSE_PROJECT=koopa0dev
DEPLOY_COMPOSE_FILE="$PWD/docker-compose.yml"
DEPLOY_COMPOSE_ENV_FILE="$PWD/.env"
readonly DEPLOY_COMPOSE_PROJECT DEPLOY_COMPOSE_FILE DEPLOY_COMPOSE_ENV_FILE
if [[ ! -f "$DEPLOY_COMPOSE_FILE" || ! -f "$DEPLOY_COMPOSE_ENV_FILE" ]]; then
  echo "ERROR: committed Compose file or production environment is missing"
  exit 1
fi
COMPOSE_FILE="$DEPLOY_COMPOSE_FILE"
COMPOSE_PROJECT_NAME="$DEPLOY_COMPOSE_PROJECT"
COMPOSE_ENV_FILES="$DEPLOY_COMPOSE_ENV_FILE"
COMPOSE_DISABLE_ENV_FILE=0
COMPOSE_PROFILES=
COMPOSE_REMOVE_ORPHANS=0
export COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_ENV_FILES
export COMPOSE_DISABLE_ENV_FILE COMPOSE_PROFILES COMPOSE_REMOVE_ORPHANS
compose() {
  docker compose \
    --project-name "$DEPLOY_COMPOSE_PROJECT" \
    --file "$DEPLOY_COMPOSE_FILE" \
    --env-file "$DEPLOY_COMPOSE_ENV_FILE" \
    "$@"
}

compose_config=$(compose config --format json)
for svc in backend mcp; do
  if ! resolved_sha=$(jq -er --arg svc "$svc" \
    '.services[$svc].build.args.BUILD_SHA | select(type == "string" and length > 0)' \
    <<<"$compose_config"); then
    echo "ERROR: effective Compose config has no BUILD_SHA for $svc"
    exit 1
  fi
  if [[ "$resolved_sha" != "$DEPLOY_SHA" ]]; then
    echo "ERROR: effective Compose BUILD_SHA for $svc is $resolved_sha; expected $DEPLOY_SHA"
    exit 1
  fi
done

# Silence Grafana alerts during deploy (5 min). Monitoring integration is
# best-effort and cannot change the build identity or deployment outcome.
grafana_line=$(grep -m1 '^GRAFANA_ADMIN_PASSWORD=' \
  "$HOME/server/observability/.env" 2>/dev/null || true)
GRAFANA_ADMIN_PASSWORD=${grafana_line#*=}
SILENCE_ID=
if [[ -n "$GRAFANA_ADMIN_PASSWORD" ]]; then
  SILENCE_ID=$(curl -sf -X POST http://localhost:3000/api/alertmanager/grafana/api/v2/silences \
    -H "Authorization: Basic $(printf 'admin:%s' "$GRAFANA_ADMIN_PASSWORD" | base64)" \
    -H "Content-Type: application/json" \
    -d "{
      \"matchers\": [{\"name\": \"severity\", \"value\": \".*\", \"isRegex\": true}],
      \"startsAt\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
      \"endsAt\": \"$(date -u -d '+5 min' +%Y-%m-%dT%H:%M:%SZ)\",
      \"createdBy\": \"ci-cd\",
      \"comment\": \"Deploy silence\"
    }" 2>/dev/null | jq -r '.silenceID' 2>/dev/null) || true
fi

# CLI build args bypass ambient Compose interpolation for the two Go images.
# Build every image before `up` so a failed build cannot replace a container.
compose build --build-arg "BUILD_SHA=$DEPLOY_SHA" backend mcp
compose build frontend
compose up -d --no-build

# Post-deploy health check
echo "Waiting for services to be ready..."
backend_receipt_sha=
mcp_receipt_sha=
for svc in backend mcp; do
  case $svc in
    backend) endpoint="http://localhost:8080/healthz" ;;
    mcp) endpoint="http://localhost:8081/healthz" ;;
  esac
  for i in $(seq 1 30); do
    if health_json=$(compose exec -T "$svc" wget -qO- "$endpoint" 2>/dev/null); then
      if ! observed_sha=$(jq -er \
        'select(.status == "ok") | .build.sha | select(type == "string" and length > 0)' \
        <<<"$health_json"); then
        echo "ERROR: $svc returned health JSON without status=ok and a build SHA"
        compose logs "$svc" --tail 20
        exit 1
      fi
      if [[ "$observed_sha" != "$DEPLOY_SHA" ]]; then
        echo "ERROR: $svc reports build SHA $observed_sha; expected $DEPLOY_SHA"
        compose logs "$svc" --tail 20
        exit 1
      fi
      case $svc in
        backend) backend_receipt_sha="$observed_sha" ;;
        mcp) mcp_receipt_sha="$observed_sha" ;;
      esac
      echo "$svc healthy at build $observed_sha after ${i}s"
      break
    fi
    if [[ "$i" -eq 30 ]]; then
      echo "ERROR: $svc failed health check after 30s"
      compose logs "$svc" --tail 20
      exit 1
    fi
    sleep 1
  done
done

# Expire the silence early after both running identities pass.
if [[ -n "$SILENCE_ID" && "$SILENCE_ID" != "null" ]]; then
  curl -sf -X DELETE "http://localhost:3000/api/alertmanager/grafana/api/v2/silence/${SILENCE_ID}" \
    -H "Authorization: Basic $(printf 'admin:%s' "$GRAFANA_ADMIN_PASSWORD" | base64)" \
    2>/dev/null || true
fi

# Cleanup is non-material. The terminal remote line is the only receipt the
# runner accepts, and it is derived from both observed container identities.
docker image prune -f || true
printf 'DEPLOY_RECEIPT sha=%s backend=%s mcp=%s\n' \
  "$DEPLOY_SHA" "$backend_receipt_sha" "$mcp_receipt_sha"
