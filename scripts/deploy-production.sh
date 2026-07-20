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

trader_db_snapshot() {
  local snapshot
  if ! snapshot=$(docker network inspect "trader-db" 2>/dev/null); then
    echo "ERROR: required trader-db network is missing or unreadable" >&2
    return 1
  fi
  printf '%s\n' "$snapshot"
}

validate_trader_db_network() {
  local snapshot=$1
  if ! jq -e '
    length == 1 and
    .[0].Name == "trader-db" and
    .[0].Driver == "bridge" and
    .[0].Scope == "local" and
    .[0].Internal == false and
    (((.[0] | has("EnableIPv4")) | not) or .[0].EnableIPv4 == true) and
    ((.[0].Options // {})["com.docker.network.bridge.enable_ip_masquerade"] // "true") == "true" and
    ((.[0].Options // {})["com.docker.network.bridge.inhibit_ipv4"] // "false") == "false" and
    ((.[0].Options // {})["com.docker.network.bridge.gateway_mode_ipv4"] // "nat") == "nat" and
    ((.[0].Labels // {}) | type == "object") and
    all((.[0].Labels // {}) | keys[]; startswith("com.docker.compose.") | not) and
    ((.[0].Containers // {}) | type == "object")
  ' >/dev/null <<<"$snapshot"; then
    echo "ERROR: trader-db network attributes do not match the approved bridge contract" >&2
    return 1
  fi
}

validate_trader_db_endpoints() {
  local snapshot=$1
  local require_postgres=$2
  local expected_postgres_id=${3:-}
  local endpoint_id endpoint_json project service
  local provider_count=0
  local trader_count=0
  local postgres_alias_count=0

  while IFS= read -r endpoint_id; do
    if ! endpoint_json=$(docker inspect "$endpoint_id" 2>/dev/null); then
      echo "ERROR: trader-db endpoint ownership is unreadable" >&2
      return 1
    fi
    if ! project=$(jq -er \
      '.[0].Config.Labels["com.docker.compose.project"] | select(type == "string" and length > 0)' \
      <<<"$endpoint_json"); then
      echo "ERROR: trader-db contains an endpoint without Compose ownership" >&2
      return 1
    fi
    if ! service=$(jq -er \
      '.[0].Config.Labels["com.docker.compose.service"] | select(type == "string" and length > 0)' \
      <<<"$endpoint_json"); then
      echo "ERROR: trader-db contains an endpoint without a Compose service" >&2
      return 1
    fi

    case "$project:$service" in
      koopa0dev:postgres)
        provider_count=$((provider_count + 1))
        if [[ -n "$expected_postgres_id" && "$endpoint_id" != "$expected_postgres_id" ]]; then
          echo "ERROR: trader-db PostgreSQL endpoint is not owned by this Compose deployment" >&2
          return 1
        fi
        if ! jq -e \
          '.[0].NetworkSettings.Networks["trader-db"].Aliases // [] | index("postgres") != null' \
          >/dev/null <<<"$endpoint_json"; then
          echo "ERROR: trader-db PostgreSQL endpoint has no postgres alias" >&2
          return 1
        fi
        postgres_alias_count=$((postgres_alias_count + 1))
        ;;
      tw-stock-trader:trader)
        trader_count=$((trader_count + 1))
        if jq -e \
          '.[0].NetworkSettings.Networks["trader-db"].Aliases // [] | index("postgres") != null' \
          >/dev/null <<<"$endpoint_json"; then
          echo "ERROR: trader-db postgres alias is claimed by the trader endpoint" >&2
          return 1
        fi
        ;;
      *)
        echo "ERROR: trader-db contains an unexpected endpoint" >&2
        return 1
        ;;
    esac
  done < <(jq -r '.[0].Containers // {} | keys[]' <<<"$snapshot")

  if ((provider_count > 1 || trader_count > 1 || postgres_alias_count > 1)); then
    echo "ERROR: trader-db contains duplicate approved endpoints or aliases" >&2
    return 1
  fi
  if [[ "$require_postgres" == "true" ]] &&
    ((provider_count != 1 || postgres_alias_count != 1)); then
    echo "ERROR: trader-db PostgreSQL endpoint is missing after deployment" >&2
    return 1
  fi
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

if ! jq -e '
  .networks["trader-db"].name == "trader-db" and
  .networks["trader-db"].external == true and
  ((.services.postgres.networks | keys | sort) == ["internal", "trader-db"]) and
  (.services.postgres.networks["trader-db"].aliases == ["postgres"]) and
  (((.services.postgres.networks.internal // {}).aliases // []) | length == 0) and
  all(
    .services | to_entries[];
    .key == "postgres" or
    ((((.value.networks // {}) | has("trader-db"))) | not)
  )
' >/dev/null <<<"$compose_config"; then
  echo "ERROR: effective Compose config violates the trader-db topology contract" >&2
  exit 1
fi

if ! trader_db_preflight=$(trader_db_snapshot); then
  exit 1
fi
if ! validate_trader_db_network "$trader_db_preflight" ||
  ! validate_trader_db_endpoints "$trader_db_preflight" false; then
  exit 1
fi

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

backend_ready=false
for i in $(seq 1 30); do
  if compose exec -T backend wget -qO- http://localhost:8080/readyz \
    >/dev/null 2>&1; then
    backend_ready=true
    echo "backend ready after ${i}s"
    break
  fi
  if [[ "$i" -eq 30 ]]; then
    echo "ERROR: backend failed database readiness after 30s"
    exit 1
  fi
  sleep 1
done
if [[ "$backend_ready" != "true" ]]; then
  echo "ERROR: backend database readiness was not established"
  exit 1
fi

postgres_container_id=$(compose ps -q postgres)
if [[ -z "$postgres_container_id" ]]; then
  echo "ERROR: Compose did not report a running PostgreSQL container" >&2
  exit 1
fi
if ! trader_db_postflight=$(trader_db_snapshot); then
  exit 1
fi
if ! validate_trader_db_network "$trader_db_postflight" ||
  ! validate_trader_db_endpoints \
    "$trader_db_postflight" true "$postgres_container_id"; then
  exit 1
fi
if ! postgres_container=$(docker inspect "$postgres_container_id" 2>/dev/null); then
  echo "ERROR: deployed PostgreSQL topology is unreadable" >&2
  exit 1
fi
if ! jq -e '
  length == 1 and
  ((.[0].NetworkSettings.Networks | keys | sort) == ["internal", "trader-db"]) and
  (.[0].NetworkSettings.Networks["trader-db"].Aliases // [] | index("postgres") != null)
' >/dev/null <<<"$postgres_container"; then
  echo "ERROR: deployed PostgreSQL container is not exact dual-home" >&2
  exit 1
fi

# Expire the silence early after both running identities pass.
if [[ -n "$SILENCE_ID" && "$SILENCE_ID" != "null" ]]; then
  curl -sf -X DELETE "http://localhost:3000/api/alertmanager/grafana/api/v2/silence/${SILENCE_ID}" \
    -H "Authorization: Basic $(printf 'admin:%s' "$GRAFANA_ADMIN_PASSWORD" | base64)" \
    2>/dev/null || true
fi

# Cleanup is non-material. The final two lines are bounded receipts: topology
# gates first, then the unchanged terminal build-identity receipt.
docker image prune -f >/dev/null || true
printf '%s\n' 'TOPOLOGY_RECEIPT network=trader-db postgres=internal,trader-db alias=postgres unexpected_endpoints=none backend_ready=ok mcp_health=ok'
printf 'DEPLOY_RECEIPT sha=%s backend=%s mcp=%s\n' \
  "$DEPLOY_SHA" "$backend_receipt_sha" "$mcp_receipt_sha"
