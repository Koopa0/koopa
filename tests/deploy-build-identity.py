#!/usr/bin/env python3
"""Verify the CI-approved SHA reaches both running service identities.

The test has two independent oracles:

1. Docker Compose must resolve BUILD_SHA into both image build arguments.
2. The real SSH script extracted from ci.yml must reject any runtime health
   response whose build SHA differs from the push SHA.
3. The GitHub-side receipt verifier must reject an SSH action that reports
   success without proving both running services reached the push SHA.

No production commands run. External commands in the extracted deploy script
are replaced with deterministic boundary stubs inside a temporary HOME.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
from copy import deepcopy


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
COMPOSE = ROOT / "docker-compose.yml"
DEPLOY_ENTRYPOINT = ROOT / "scripts/deploy-production.sh"
EXPECTED_SHA = "1111111111111111111111111111111111111111"
TOPOLOGY_RECEIPT = (
    "TOPOLOGY_RECEIPT network=trader-db postgres=internal,trader-db "
    "alias=postgres unexpected_endpoints=none backend_ready=ok mcp_health=ok"
)


class ContractFailure(RuntimeError):
    """A deploy identity invariant was not satisfied."""


def extract_ssh_script(path: Path, deploy_sha: str = EXPECTED_SHA) -> str:
    """Extract the unique literal SSH script block without parsing YAML."""
    lines = path.read_text(encoding="utf-8").splitlines()
    markers = [
        i
        for i, line in enumerate(lines)
        if line.lstrip() == "script: |" and len(line) - len(line.lstrip()) == 10
    ]
    if len(markers) != 1:
        raise ContractFailure(
            f"caught:deploy-script-count expected=1 got={len(markers)}"
        )

    marker = markers[0]
    marker_indent = len(lines[marker]) - len(lines[marker].lstrip())
    body: list[str] = []
    for line in lines[marker + 1 :]:
        if line.strip():
            indent = len(line) - len(line.lstrip())
            if indent <= marker_indent:
                break
        body.append(line)

    if not body:
        raise ContractFailure("caught:deploy-script-empty")

    nonempty_indents = [len(line) - len(line.lstrip()) for line in body if line]
    body_indent = min(nonempty_indents)
    if body_indent <= marker_indent:
        raise ContractFailure("caught:deploy-script-indent-invalid")

    script = "\n".join(
        line[body_indent:] if line.strip() else "" for line in body
    )
    if "${{ github.sha }}" not in script:
        raise ContractFailure("caught:github-sha-not-consumed")
    return script.replace("${{ github.sha }}", deploy_sha) + "\n"


def extract_named_run_script(path: Path, step_name: str) -> str:
    """Extract the literal run block from one uniquely named Actions step."""
    lines = path.read_text(encoding="utf-8").splitlines()
    markers = [
        i for i, line in enumerate(lines) if line.strip() == f"- name: {step_name}"
    ]
    if len(markers) != 1:
        raise ContractFailure(
            f"caught:deploy-receipt-step-count expected=1 got={len(markers)}"
        )

    step = markers[0]
    step_indent = len(lines[step]) - len(lines[step].lstrip())
    run_markers: list[int] = []
    for i in range(step + 1, len(lines)):
        line = lines[i]
        if line.strip():
            indent = len(line) - len(line.lstrip())
            if indent <= step_indent and line.lstrip().startswith("- "):
                break
            if line.strip() == "run: |":
                run_markers.append(i)
    if len(run_markers) != 1:
        raise ContractFailure(
            f"caught:deploy-receipt-run-count expected=1 got={len(run_markers)}"
        )

    marker = run_markers[0]
    marker_indent = len(lines[marker]) - len(lines[marker].lstrip())
    body: list[str] = []
    for line in lines[marker + 1 :]:
        if line.strip():
            indent = len(line) - len(line.lstrip())
            if indent <= marker_indent:
                break
        body.append(line)
    if not body:
        raise ContractFailure("caught:deploy-receipt-run-empty")

    body_indent = min(len(line) - len(line.lstrip()) for line in body if line)
    return "\n".join(
        line[body_indent:] if line.strip() else "" for line in body
    ) + "\n"


def render_compose_config() -> tuple[dict[str, object] | None, list[str]]:
    """Render the tracked Compose model with a deterministic build identity."""
    env = os.environ.copy()
    env["BUILD_SHA"] = EXPECTED_SHA
    proc = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            "/dev/null",
            "-f",
            str(COMPOSE),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None, [
            "caught:compose-config-failed "
            f"exit={proc.returncode} stderr={proc.stderr.strip()}"
        ]

    try:
        config = json.loads(proc.stdout)
    except json.JSONDecodeError as err:
        return None, [f"caught:compose-config-invalid-json error={err}"]

    return config, []


def check_compose_build_args(config: dict[str, object]) -> list[str]:
    services = config.get("services", {})
    if not isinstance(services, dict):
        return ["caught:compose-services-invalid"]

    failures: list[str] = []
    for service in ("backend", "mcp"):
        service_config = services.get(service, {})
        if not isinstance(service_config, dict):
            failures.append(f"caught:{service}-compose-service-invalid")
            continue
        build = service_config.get("build") or {}
        if not isinstance(build, dict):
            failures.append(f"caught:{service}-compose-build-invalid")
            continue
        actual = (build.get("args") or {}).get("BUILD_SHA")
        if actual != EXPECTED_SHA:
            failures.append(
                f"caught:{service}-build-sha-not-propagated "
                f"expected={EXPECTED_SHA} actual={actual!r}"
            )
    return failures


def compose_topology_failures(config: dict[str, object]) -> list[str]:
    """Return named failures for the provider-side trader-db contract."""
    failures: list[str] = []
    networks = config.get("networks")
    services = config.get("services")
    if not isinstance(networks, dict):
        return ["caught:compose-networks-invalid"]
    if not isinstance(services, dict):
        return ["caught:compose-services-invalid"]

    provider = networks.get("trader-db")
    if not isinstance(provider, dict):
        failures.append("caught:compose-trader-db-network-missing")
    else:
        if provider.get("name") != "trader-db" or provider.get("external") is not True:
            failures.append("caught:compose-trader-db-network-not-external")

    postgres = services.get("postgres")
    if not isinstance(postgres, dict):
        failures.append("caught:compose-postgres-service-missing")
        return failures
    postgres_networks = postgres.get("networks")
    if not isinstance(postgres_networks, dict):
        failures.append("caught:compose-postgres-networks-invalid")
        postgres_networks = {}
    if set(postgres_networks) != {"internal", "trader-db"}:
        failures.append("caught:compose-postgres-network-membership-invalid")

    provider_attachment = postgres_networks.get("trader-db")
    if not isinstance(provider_attachment, dict):
        failures.append("caught:compose-postgres-alias-missing")
    elif provider_attachment.get("aliases") != ["postgres"]:
        failures.append("caught:compose-postgres-alias-not-unique")

    internal_attachment = postgres_networks.get("internal")
    if isinstance(internal_attachment, dict) and internal_attachment.get("aliases"):
        failures.append("caught:compose-postgres-alias-leaked-to-internal")

    for service_name, service_config in services.items():
        if service_name == "postgres" or not isinstance(service_config, dict):
            continue
        service_networks = service_config.get("networks") or {}
        if isinstance(service_networks, dict) and "trader-db" in service_networks:
            failures.append(
                f"caught:compose-unexpected-trader-db-member service={service_name}"
            )

    return failures


def check_compose_topology_mutations(config: dict[str, object]) -> list[str]:
    """Prove the test oracle turns red for each load-bearing topology mutation."""
    failures: list[str] = []
    if baseline := compose_topology_failures(config):
        return baseline

    def require_failure(name: str, mutant: dict[str, object], marker: str) -> None:
        observed = compose_topology_failures(mutant)
        if not any(failure.startswith(marker) for failure in observed):
            failures.append(
                f"caught:mutation-survived name={name} expected={marker!r} "
                f"observed={observed!r}"
            )

    missing_network = deepcopy(config)
    del missing_network["networks"]["trader-db"]  # type: ignore[index]
    require_failure(
        "missing-provider-network",
        missing_network,
        "caught:compose-trader-db-network-missing",
    )

    extra_network = deepcopy(config)
    extra_network["services"]["postgres"]["networks"]["edge"] = None  # type: ignore[index]
    require_failure(
        "extra-postgres-network",
        extra_network,
        "caught:compose-postgres-network-membership-invalid",
    )

    missing_alias = deepcopy(config)
    missing_alias["services"]["postgres"]["networks"]["trader-db"] = None  # type: ignore[index]
    require_failure(
        "missing-postgres-alias",
        missing_alias,
        "caught:compose-postgres-alias-missing",
    )

    colliding_alias = deepcopy(config)
    colliding_alias["services"]["backend"]["networks"]["trader-db"] = {  # type: ignore[index]
        "aliases": ["postgres"]
    }
    require_failure(
        "colliding-postgres-alias",
        colliding_alias,
        "caught:compose-unexpected-trader-db-member",
    )

    other_service = deepcopy(config)
    other_service["services"]["mcp"]["networks"]["trader-db"] = None  # type: ignore[index]
    require_failure(
        "other-service-joins-trader-db",
        other_service,
        "caught:compose-unexpected-trader-db-member",
    )

    return failures


def write_executable(path: Path, source: str) -> None:
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o755)


def install_boundary_stubs(bin_dir: Path) -> None:
    write_executable(
        bin_dir / "git",
        r'''
        #!/usr/bin/env bash
        set -eu
        printf 'git BUILD_SHA=%s %s\n' "${BUILD_SHA:-}" "$*" >> "$HARNESS_LOG"
        if [[ -n "${COMPOSE_FILE:-}" || -n "${COMPOSE_ENV_FILES:-}" || -n "${COMPOSE_DISABLE_ENV_FILE:-}" ]]; then
          printf 'ambient-compose file=%s env_files=%s disable_env=%s\n' \
            "${COMPOSE_FILE:-}" "${COMPOSE_ENV_FILES:-}" "${COMPOSE_DISABLE_ENV_FILE:-}" \
            >> "$HARNESS_LOG"
        fi
        if [[ "${1:-}" == "rev-parse" && "${2:-}" == "HEAD" ]]; then
          printf '%s\n' "$CHECKED_OUT_SHA"
          exit 0
        fi
        if [[ "${1:-}" == "rev-parse" && "${2:-}" == "$EXPECTED_SHA:scripts/deploy-production.sh" ]]; then
          printf '%s\n' "$DEPLOY_ENTRYPOINT_BLOB"
          exit 0
        fi
        if [[ "${1:-}" == "cat-file" && "${2:-}" == "blob" && "${3:-}" == "$DEPLOY_ENTRYPOINT_BLOB" ]]; then
          cat "$DEPLOY_ENTRYPOINT_SOURCE"
          exit 0
        fi
        if [[ "${1:-}" == "hash-object" && "${2:-}" == "--no-filters" && -n "${3:-}" ]]; then
          if [[ -n "${RELEASE_ENTRYPOINT_BLOB_OVERRIDE:-}" && "$3" == */scripts/deploy-production.sh ]]; then
            printf '%s\n' "$RELEASE_ENTRYPOINT_BLOB_OVERRIDE"
          else
            "$REAL_GIT_BIN" hash-object --no-filters "$3"
          fi
          exit 0
        fi
        if [[ "${1:-}" == "hash-object" && -n "${2:-}" ]]; then
          "$REAL_GIT_BIN" hash-object --no-filters "$2"
          exit 0
        fi
        if [[ "${1:-}" == "archive" && "${2:-}" == "--format=tar" && "${3:-}" == "--output" && "${5:-}" == "$EXPECTED_SHA" ]]; then
          "$REAL_GIT_BIN" -C "$REAL_REPO_ROOT" archive --format=tar --output="$4" HEAD
          exit 0
        fi
        ''',
    )
    write_executable(
        bin_dir / "docker",
        r'''
        #!/usr/bin/env bash
        set -eu
        if [[ "${1:-}" == "compose" ]]; then
          shift
          compose_project=
          compose_file=
          compose_env_file=
          while [[ $# -gt 0 ]]; do
            case "$1" in
              --project-name) compose_project="$2"; shift 2 ;;
              --file) compose_file="$2"; shift 2 ;;
              --env-file) compose_env_file="$2"; shift 2 ;;
              *) break ;;
            esac
          done
          printf 'compose-control project=%s file=%s env_file=%s profiles=%s remove_orphans=%s\n' \
            "$compose_project" "$compose_file" "$compose_env_file" \
            "${COMPOSE_PROFILES:-}" "${COMPOSE_REMOVE_ORPHANS:-}" \
            >> "$HARNESS_LOG"
          set -- compose "$@"
        fi
        printf 'docker BUILD_SHA=%s %s\n' "${BUILD_SHA:-}" "$*" >> "$HARNESS_LOG"

        if [[ "${1:-}" == "network" && "${2:-}" == "inspect" ]]; then
          count_file="$HARNESS_STATE_DIR/network-inspect-count"
          count=0
          if [[ -f "$count_file" ]]; then
            count=$(cat "$count_file")
          fi
          count=$((count + 1))
          printf '%s\n' "$count" > "$count_file"
          if [[ "$count" -eq 1 ]]; then
            mode="$NETWORK_PRE_MODE"
          else
            mode="$NETWORK_POST_MODE"
          fi
          printf 'network-inspect phase=%s mode=%s\n' "$count" "$mode" >> "$HARNESS_LOG"
          case "$mode" in
            inspect-fail) exit 1 ;;
            empty)
              containers='{}'
              ;;
            postgres-only)
              containers='{"provider-postgres-id":{"Name":"koopa0dev-postgres-1"}}'
              ;;
            unexpected-endpoint)
              containers='{"provider-postgres-id":{"Name":"koopa0dev-postgres-1"},"rogue-id":{"Name":"rogue"}}'
              ;;
            missing-postgres)
              containers='{"trader-id":{"Name":"tw-stock-trader-trader-1"}}'
              ;;
            *)
              containers='{"provider-postgres-id":{"Name":"koopa0dev-postgres-1"},"trader-id":{"Name":"tw-stock-trader-trader-1"}}'
              ;;
          esac
          driver=bridge
          scope=local
          internal=false
          enable_ipv4=true
          options='{}'
          labels='{}'
          case "$mode" in
            wrong-driver) driver=overlay ;;
            wrong-scope) scope=swarm ;;
            internal) internal=true ;;
            ipv4-disabled) enable_ipv4=false ;;
            unsafe-egress) options='{"com.docker.network.bridge.enable_ip_masquerade":"false"}' ;;
            icc-disabled) options='{"com.docker.network.bridge.enable_icc":"false"}' ;;
            inhibit-ipv4) options='{"com.docker.network.bridge.inhibit_ipv4":"true"}' ;;
            routed-gateway) options='{"com.docker.network.bridge.gateway_mode_ipv4":"routed"}' ;;
            isolated-gateway) options='{"com.docker.network.bridge.gateway_mode_ipv4":"isolated"}' ;;
            compose-owned) labels='{"com.docker.compose.project":"rogue","com.docker.compose.network":"trader-db"}' ;;
          esac
          printf '[{"Name":"trader-db","Driver":"%s","Scope":"%s","Internal":%s,"EnableIPv4":%s,"Options":%s,"Labels":%s,"Containers":%s}]\n' \
            "$driver" "$scope" "$internal" "$enable_ipv4" "$options" "$labels" "$containers"
          exit 0
        fi

        if [[ "${1:-}" == "inspect" ]]; then
          container_id="${2:-}"
          inspect_phase=1
          if [[ -f "$HARNESS_STATE_DIR/network-inspect-count" ]]; then
            inspect_phase=$(cat "$HARNESS_STATE_DIR/network-inspect-count")
          fi
          case "$container_id" in
            provider-postgres-id)
              postgres_mode="$POSTGRES_PRE_MODE"
              if [[ "$inspect_phase" -gt 1 ]]; then
                postgres_mode="$POSTGRES_LIVE_MODE"
              fi
              case "$postgres_mode" in
                valid)
                  networks='{"internal":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":["postgres","koopa0dev-postgres-1"]},"trader-db":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":["postgres","koopa0dev-postgres-1"]}}'
                  ;;
                missing-internal)
                  networks='{"trader-db":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":["postgres","koopa0dev-postgres-1"]}}'
                  ;;
                missing-provider)
                  networks='{"internal":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":["postgres","koopa0dev-postgres-1"]}}'
                  ;;
                missing-alias)
                  networks='{"internal":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":["postgres","koopa0dev-postgres-1"]},"trader-db":{"Aliases":["koopa0dev-postgres-1"],"DNSNames":["koopa0dev-postgres-1"]}}'
                  ;;
                missing-dns-name)
                  networks='{"internal":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":["postgres","koopa0dev-postgres-1"]},"trader-db":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":["koopa0dev-postgres-1"]}}'
                  ;;
                malformed-dns-names)
                  networks='{"internal":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":["postgres","koopa0dev-postgres-1"]},"trader-db":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":"postgres"}}'
                  ;;
                extra-network)
                  networks='{"edge":{"Aliases":["koopa0dev-postgres-1"],"DNSNames":["koopa0dev-postgres-1"]},"internal":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":["postgres","koopa0dev-postgres-1"]},"trader-db":{"Aliases":["koopa0dev-postgres-1","postgres"],"DNSNames":["postgres","koopa0dev-postgres-1"]}}'
                  ;;
                *) printf 'unexpected postgres live mode: %s\n' "$postgres_mode" >&2; exit 67 ;;
              esac
              printf '[{"Config":{"Labels":{"com.docker.compose.project":"koopa0dev","com.docker.compose.service":"postgres"}},"NetworkSettings":{"Networks":%s}}]\n' "$networks"
              ;;
            trader-id)
              aliases='["tw-stock-trader-trader-1"]'
              dns_names='["trader","tw-stock-trader-trader-1"]'
              dns_names_field=",\"DNSNames\":$dns_names"
              trader_dns_mode="$TRADER_PRE_DNS_MODE"
              if [[ "$inspect_phase" -gt 1 ]]; then
                trader_dns_mode="$TRADER_DNS_MODE"
              fi
              case "$trader_dns_mode" in
                valid) ;;
                collision)
                  dns_names='["postgres","trader","tw-stock-trader-trader-1"]'
                  dns_names_field=",\"DNSNames\":$dns_names"
                  ;;
                missing) dns_names_field= ;;
                malformed) dns_names_field=',"DNSNames":"trader"' ;;
                *) printf 'unexpected trader DNS mode: %s\n' "$trader_dns_mode" >&2; exit 71 ;;
              esac
              printf '[{"Config":{"Labels":{"com.docker.compose.project":"tw-stock-trader","com.docker.compose.service":"trader"}},"NetworkSettings":{"Networks":{"trader-db":{"Aliases":%s%s}}}}]\n' "$aliases" "$dns_names_field"
              ;;
            rogue-id)
              printf '[{"Config":{"Labels":{"com.docker.compose.project":"rogue","com.docker.compose.service":"rogue"}},"NetworkSettings":{"Networks":{"trader-db":{"Aliases":["rogue"]}}}}]\n'
              ;;
            *) printf 'unexpected inspect id: %s\n' "$container_id" >&2; exit 68 ;;
          esac
          exit 0
        fi

        if [[ "${1:-}" == "compose" && "${2:-}" == "up" ]]; then
          exit 0
        fi
        if [[ "${1:-}" == "compose" && "${2:-}" == "build" ]]; then
          exit 0
        fi
        if [[ "${1:-}" == "compose" && "${2:-}" == "config" ]]; then
          config_sha="${COMPOSE_CONFIG_SHA:-${BUILD_SHA:-dev}}"
          config=$(printf '{"networks":{"edge":{"name":"edge","external":true},"internal":{"name":"internal","external":true},"trader-db":{"name":"trader-db","external":true}},"services":{"frontend":{"networks":{"edge":null}},"postgres":{"networks":{"internal":null,"trader-db":{"aliases":["postgres"]}}},"backend":{"build":{"args":{"BUILD_SHA":"%s"}},"networks":{"edge":null,"internal":null}},"mcp":{"build":{"args":{"BUILD_SHA":"%s"}},"networks":{"internal":null}}}}' \
            "$config_sha" "$config_sha")
          case "$COMPOSE_TOPOLOGY_MODE" in
            valid) ;;
            missing-provider) config=$(jq -c 'del(.networks["trader-db"])' <<<"$config") ;;
            extra-postgres-network) config=$(jq -c '.services.postgres.networks.edge = null' <<<"$config") ;;
            missing-alias) config=$(jq -c '.services.postgres.networks["trader-db"] = null' <<<"$config") ;;
            colliding-alias) config=$(jq -c '.services.backend.networks["trader-db"] = {"aliases":["postgres"]}' <<<"$config") ;;
            other-service) config=$(jq -c '.services.mcp.networks["trader-db"] = null' <<<"$config") ;;
            *) printf 'unexpected compose topology mode: %s\n' "$COMPOSE_TOPOLOGY_MODE" >&2; exit 69 ;;
          esac
          printf '%s\n' "$config"
          exit 0
        fi
        if [[ "${1:-}" == "compose" && "${2:-}" == "ps" && "${3:-}" == "-q" && "${4:-}" == "postgres" ]]; then
          printf '%s\n' 'provider-postgres-id'
          exit 0
        fi
        if [[ "${1:-}" == "image" && "${2:-}" == "prune" ]]; then
          exit 0
        fi
        if [[ "${1:-}" == "compose" && "${2:-}" == "logs" ]]; then
          exit 0
        fi
        if [[ "${1:-}" == "compose" && "${2:-}" == "exec" ]]; then
          service="${4:-}"
          endpoint="${!#}"
          if [[ "$service" == "backend" && "$endpoint" == *"/readyz" ]]; then
            printf 'probe backend-ready\n' >> "$HARNESS_LOG"
            case "$BACKEND_READY_MODE" in
              valid) printf 'ready\n' ;;
              http-fail) exit 7 ;;
              *) printf 'unexpected readiness mode: %s\n' "$BACKEND_READY_MODE" >&2; exit 70 ;;
            esac
            exit 0
          fi
          printf 'probe %s-health\n' "$service" >> "$HARNESS_LOG"
          case "$service" in
            backend) mode="$BACKEND_HEALTH_MODE"; sha="$BACKEND_HEALTH_SHA" ;;
            mcp) mode="$MCP_HEALTH_MODE"; sha="$MCP_HEALTH_SHA" ;;
            *) printf 'unexpected service: %s\n' "$service" >&2; exit 64 ;;
          esac
          case "$mode" in
            valid)
              printf '{"status":"ok","build":{"sha":"%s","built_at":"test","version":"test"}}\n' "$sha"
              ;;
            missing)
              printf '{"status":"ok","build":{"built_at":"test","version":"test"}}\n'
              ;;
            bad-status)
              printf '{"status":"starting","build":{"sha":"%s","built_at":"test","version":"test"}}\n' "$sha"
              ;;
            malformed)
              printf '{not-json\n'
              ;;
            http-fail)
              exit 7
              ;;
            *)
              printf 'unexpected health mode: %s\n' "$mode" >&2
              exit 65
              ;;
          esac
          exit 0
        fi

        printf 'unexpected docker invocation: %s\n' "$*" >&2
        exit 66
        ''',
    )
    write_executable(
        bin_dir / "curl",
        r'''
        #!/usr/bin/env bash
        set -eu
        printf 'curl BUILD_SHA=%s %s\n' "${BUILD_SHA:-}" "$*" >> "$HARNESS_LOG"
        if [[ " $* " == *" -X POST "* ]]; then
          printf '{"silenceID":"test-silence"}\n'
        fi
        ''',
    )
    write_executable(
        bin_dir / "date",
        r'''
        #!/usr/bin/env bash
        set -eu
        printf '%s\n' '2026-07-17T00:00:00Z'
        ''',
    )
    write_executable(
        bin_dir / "sleep",
        r'''
        #!/usr/bin/env bash
        set -eu
        printf 'sleep %s\n' "$*" >> "$HARNESS_LOG"
        ''',
    )


def run_deploy(
    script: str,
    *,
    backend_sha: str = EXPECTED_SHA,
    mcp_sha: str = EXPECTED_SHA,
    backend_mode: str = "valid",
    mcp_mode: str = "valid",
    backend_ready_mode: str = "valid",
    checked_out_sha: str = EXPECTED_SHA,
    grafana_env: str = "GRAFANA_ADMIN_PASSWORD=test-password\n",
    ambient_build_sha: str | None = None,
    ambient_compose_file: str | None = None,
    ambient_compose_env_files: str | None = None,
    ambient_compose_disable_env_file: str | None = None,
    compose_config_sha: str | None = None,
    compose_topology_mode: str = "valid",
    network_pre_mode: str = "valid",
    network_post_mode: str = "valid",
    postgres_pre_mode: str = "valid",
    postgres_live_mode: str = "valid",
    trader_pre_dns_mode: str = "valid",
    trader_dns_mode: str = "valid",
    release_entrypoint_blob_override: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], str]:
    with tempfile.TemporaryDirectory(prefix="koopa-deploy-identity-") as raw_tmp:
        tmp = Path(raw_tmp)
        home = tmp / "home"
        repo = home / "koopa0.dev"
        observability = home / "server/observability"
        bin_dir = tmp / "bin"
        runtime_tmp = tmp / "runtime-tmp"
        harness_state = tmp / "harness-state"
        repo.mkdir(parents=True)
        (repo / ".env").write_text("# deploy harness\n", encoding="utf-8")
        observability.mkdir(parents=True)
        bin_dir.mkdir()
        runtime_tmp.mkdir()
        harness_state.mkdir()
        (observability / ".env").write_text(grafana_env, encoding="utf-8")
        install_boundary_stubs(bin_dir)
        if DEPLOY_ENTRYPOINT.exists():
            entrypoint = repo / DEPLOY_ENTRYPOINT.relative_to(ROOT)
            entrypoint.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(DEPLOY_ENTRYPOINT, entrypoint)

        script_path = tmp / "deploy.sh"
        script_path.write_text(script, encoding="utf-8")
        log_path = tmp / "harness.log"

        env = os.environ.copy()
        env.update(
            {
                "HOME": str(home),
                "PATH": str(bin_dir) + os.pathsep + env["PATH"],
                "HARNESS_LOG": str(log_path),
                "EXPECTED_SHA": EXPECTED_SHA,
                "CHECKED_OUT_SHA": checked_out_sha,
                "BACKEND_HEALTH_MODE": backend_mode,
                "BACKEND_HEALTH_SHA": backend_sha,
                "MCP_HEALTH_MODE": mcp_mode,
                "MCP_HEALTH_SHA": mcp_sha,
                "BACKEND_READY_MODE": backend_ready_mode,
                "COMPOSE_TOPOLOGY_MODE": compose_topology_mode,
                "NETWORK_PRE_MODE": network_pre_mode,
                "NETWORK_POST_MODE": network_post_mode,
                "POSTGRES_PRE_MODE": postgres_pre_mode,
                "POSTGRES_LIVE_MODE": postgres_live_mode,
                "TRADER_PRE_DNS_MODE": trader_pre_dns_mode,
                "TRADER_DNS_MODE": trader_dns_mode,
                "HARNESS_STATE_DIR": str(harness_state),
                "DEPLOY_ENTRYPOINT_SOURCE": str(DEPLOY_ENTRYPOINT),
                "DEPLOY_ENTRYPOINT_BLOB": subprocess.check_output(
                    [shutil.which("git") or "git", "hash-object", str(DEPLOY_ENTRYPOINT)],
                    text=True,
                ).strip(),
                "REAL_GIT_BIN": shutil.which("git") or "git",
                "REAL_REPO_ROOT": str(ROOT),
                "TMPDIR": str(runtime_tmp),
            }
        )
        if ambient_build_sha is not None:
            env["BUILD_SHA"] = ambient_build_sha
        if ambient_compose_file is not None:
            env["COMPOSE_FILE"] = ambient_compose_file
        if ambient_compose_env_files is not None:
            env["COMPOSE_ENV_FILES"] = ambient_compose_env_files
        if ambient_compose_disable_env_file is not None:
            env["COMPOSE_DISABLE_ENV_FILE"] = ambient_compose_disable_env_file
        if compose_config_sha is not None:
            env["COMPOSE_CONFIG_SHA"] = compose_config_sha
        if release_entrypoint_blob_override is not None:
            env["RELEASE_ENTRYPOINT_BLOB_OVERRIDE"] = (
                release_entrypoint_blob_override
            )
        proc = subprocess.run(
            ["bash", str(script_path)],
            cwd=repo,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        log = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
        remnants = sorted(path.name for path in runtime_tmp.iterdir())
        if remnants:
            log += f"harness-runtime-temp-remnants={remnants!r}\n"
        return proc, log


def assert_invoked(log: str, marker: str, case: str) -> list[str]:
    if marker not in log:
        return [f"caught:{case}-not-invoked marker={marker!r}"]
    return []


def run_receipt_verifier(script: str, stdout: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update({"DEPLOY_SHA": EXPECTED_SHA, "DEPLOY_STDOUT": stdout})
    return subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def check_deploy_receipt() -> list[str]:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    failures: list[str] = []
    required_wiring = (
        "id: deploy_ssh",
        "capture_stdout: true",
        "DEPLOY_STDOUT: ${{ steps.deploy_ssh.outputs.stdout }}",
    )
    for needle in required_wiring:
        if needle not in workflow:
            failures.append(f"caught:deploy-receipt-wiring-missing needle={needle!r}")

    try:
        verifier = extract_named_run_script(WORKFLOW, "Verify deployment receipt")
    except ContractFailure as err:
        failures.append(str(err))
        return failures

    expected = (
        f"DEPLOY_RECEIPT sha={EXPECTED_SHA} "
        f"backend={EXPECTED_SHA} mcp={EXPECTED_SHA}"
    )
    positive = run_receipt_verifier(
        verifier, f"build output\n{TOPOLOGY_RECEIPT}\n{expected}\n"
    )
    if positive.returncode != 0:
        failures.append(
            "caught:valid-deploy-receipt-rejected "
            f"exit={positive.returncode} stderr={positive.stderr.strip()!r}"
        )

    cases = (
        ("missing-deploy-receipt-accepted", "Total reclaimed space: 0B\n"),
        (
            "stale-deploy-receipt-accepted",
            "DEPLOY_RECEIPT sha=dev backend=dev mcp=dev\n",
        ),
        ("missing-topology-receipt-accepted", f"build output\n{expected}\n"),
        (
            "forged-topology-receipt-accepted",
            "TOPOLOGY_RECEIPT network=internal postgres=internal "
            "alias=missing unexpected_endpoints=unknown "
            "backend_ready=ok mcp_health=ok\n"
            f"{expected}\n",
        ),
    )
    for name, stdout in cases:
        proc = run_receipt_verifier(verifier, stdout)
        if proc.returncode == 0:
            failures.append(f"caught:{name} exit=0")
    return failures


def run_git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run Git for the real-index stale-worktree regression fixture."""
    return subprocess.run(
        [shutil.which("git") or "git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def check_commit_object_entrypoint() -> list[str]:
    """Prove deploy executes a committed release, not stale working files.

    Git's skip-worktree bit is a real state in which `reset --hard <HEAD>` can
    report success while preserving different bytes at tracked paths. The
    deploy boundary must therefore materialize the whole tree addressed by
    DEPLOY_SHA, not merely extract its entrypoint.
    """
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="koopa-deploy-object-") as raw_tmp:
        tmp = Path(raw_tmp)
        origin = tmp / "origin.git"
        seed = tmp / "seed"
        home = tmp / "home"
        checkout = home / "koopa0.dev"

        for args, cwd in (
            (["init", "--bare", str(origin)], tmp),
            (["init", "-b", "main", str(seed)], tmp),
            (["config", "user.name", "deploy-test"], seed),
            (["config", "user.email", "deploy-test@example.invalid"], seed),
        ):
            proc = run_git(args, cwd)
            if proc.returncode != 0:
                return [
                    "caught:stale-worktree-fixture-git-failed "
                    f"args={args!r} exit={proc.returncode} stderr={proc.stderr.strip()!r}"
                ]

        committed = seed / "scripts/deploy-production.sh"
        committed.parent.mkdir(parents=True)
        committed.write_text(
            "#!/usr/bin/env bash\n"
            "set -Eeuo pipefail\n"
            "printf 'COMMIT_OBJECT_ENTRYPOINT sha=%s marker=%s\\n' \"$1\" \"$(cat source-marker.txt)\"\n",
            encoding="utf-8",
        )
        committed.chmod(0o755)
        (seed / "source-marker.txt").write_text(
            "COMMITTED_SOURCE\n", encoding="utf-8"
        )
        for args in (
            ["add", "scripts/deploy-production.sh", "source-marker.txt"],
            ["commit", "-m", "fixture"],
            ["remote", "add", "origin", str(origin)],
            ["push", "origin", "main"],
        ):
            proc = run_git(args, seed)
            if proc.returncode != 0:
                return [
                    "caught:stale-worktree-fixture-git-failed "
                    f"args={args!r} exit={proc.returncode} stderr={proc.stderr.strip()!r}"
                ]

        clone = run_git(["clone", "--branch", "main", str(origin), str(checkout)], tmp)
        if clone.returncode != 0:
            return [
                "caught:stale-worktree-fixture-clone-failed "
                f"exit={clone.returncode} stderr={clone.stderr.strip()!r}"
            ]
        sha_proc = run_git(["rev-parse", "HEAD"], checkout)
        if sha_proc.returncode != 0:
            return ["caught:stale-worktree-fixture-sha-unavailable"]
        deploy_sha = sha_proc.stdout.strip()
        (checkout / ".env").write_text("# release fixture\n", encoding="utf-8")

        skip = run_git(
            [
                "update-index",
                "--skip-worktree",
                "scripts/deploy-production.sh",
                "source-marker.txt",
            ],
            checkout,
        )
        if skip.returncode != 0:
            return [
                "caught:stale-worktree-fixture-skip-failed "
                f"exit={skip.returncode} stderr={skip.stderr.strip()!r}"
            ]
        stale = checkout / "scripts/deploy-production.sh"
        stale.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'STALE_WORKTREE_ENTRYPOINT\\n'\n"
            "exit 0\n",
            encoding="utf-8",
        )
        stale.chmod(0o755)
        (checkout / "source-marker.txt").write_text(
            "STALE_SOURCE\n", encoding="utf-8"
        )

        expected_blob = run_git(
            ["rev-parse", f"{deploy_sha}:scripts/deploy-production.sh"], checkout
        ).stdout.strip()
        actual_blob = run_git(
            ["hash-object", "scripts/deploy-production.sh"], checkout
        ).stdout.strip()
        if not expected_blob or not actual_blob or expected_blob == actual_blob:
            return [
                "caught:stale-worktree-fixture-not-applied "
                f"expected_blob={expected_blob!r} actual_blob={actual_blob!r}"
            ]

        script = extract_ssh_script(WORKFLOW, deploy_sha)
        script_path = tmp / "outer-deploy.sh"
        script_path.write_text(script, encoding="utf-8")
        runtime_tmp = tmp / "runtime-tmp"
        runtime_tmp.mkdir()
        env = os.environ.copy()
        env["HOME"] = str(home)
        env["TMPDIR"] = str(runtime_tmp)
        env.pop("BASH_ENV", None)
        env.pop("ENV", None)
        proc = subprocess.run(
            ["bash", str(script_path)],
            cwd=checkout,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        expected_marker = (
            f"COMMIT_OBJECT_ENTRYPOINT sha={deploy_sha} marker=COMMITTED_SOURCE"
        )
        if "STALE_WORKTREE_ENTRYPOINT" in proc.stdout:
            failures.append(
                "caught:stale-worktree-deploy-entrypoint-accepted "
                f"expected_blob={expected_blob} actual_blob={actual_blob}"
            )
        if expected_marker not in proc.stdout.splitlines():
            failures.append(
                "caught:commit-object-deploy-entrypoint-not-executed "
                f"exit={proc.returncode} stdout={proc.stdout.strip()!r} "
                f"stderr={proc.stderr.strip()!r}"
            )
        if proc.returncode != 0:
            failures.append(
                "caught:commit-object-deploy-entrypoint-rejected "
                f"exit={proc.returncode} stderr={proc.stderr.strip()!r}"
            )
        remnants = sorted(path.name for path in runtime_tmp.iterdir())
        if remnants:
            failures.append(
                "caught:deploy-release-temp-leaked "
                f"remnants={remnants!r}"
            )

    return failures


def check_deploy_script() -> list[str]:
    try:
        script = extract_ssh_script(WORKFLOW)
    except ContractFailure as err:
        return [str(err)]

    failures: list[str] = []
    if not DEPLOY_ENTRYPOINT.is_file():
        failures.append(
            "caught:tracked-deploy-entrypoint-missing "
            f"path={DEPLOY_ENTRYPOINT.relative_to(ROOT)}"
        )
        deploy_script = script
    else:
        deploy_script = DEPLOY_ENTRYPOINT.read_text(encoding="utf-8")
        required_outer = (
            'git archive --format=tar --output "$DEPLOY_ARCHIVE" "$DEPLOY_SHA"',
            'git hash-object --no-filters "$DEPLOY_RELEASE/scripts/deploy-production.sh"',
            'if [ "$RELEASE_ENTRYPOINT_BLOB" != "$DEPLOY_ENTRYPOINT_BLOB" ]; then',
            'trap cleanup_release 0',
            'BASH_ENV=/dev/null ENV=/dev/null /bin/bash --noprofile --norc '
            'scripts/deploy-production.sh "$DEPLOY_SHA"',
        )
        for needle in required_outer:
            if needle not in script:
                failures.append(
                    "caught:commit-object-deploy-boundary-missing "
                    f"needle={needle!r}"
                )
        required_entrypoint = (
            'DEPLOY_COMPOSE_PROJECT=koopa0dev',
            'COMPOSE_FILE="$DEPLOY_COMPOSE_FILE"',
            'COMPOSE_ENV_FILES="$DEPLOY_COMPOSE_ENV_FILE"',
            'COMPOSE_DISABLE_ENV_FILE=0',
            'COMPOSE_PROFILES=',
            'COMPOSE_REMOVE_ORPHANS=0',
            'docker compose',
            '--project-name "$DEPLOY_COMPOSE_PROJECT"',
            '--file "$DEPLOY_COMPOSE_FILE"',
            '--env-file "$DEPLOY_COMPOSE_ENV_FILE"',
            'docker network inspect "trader-db"',
            'http://localhost:8080/readyz',
            'TOPOLOGY_RECEIPT network=trader-db',
        )
        for needle in required_entrypoint:
            if needle not in deploy_script:
                failures.append(
                    "caught:explicit-compose-boundary-missing "
                    f"needle={needle!r}"
                )

    positive, positive_log = run_deploy(script)
    failures.extend(
        assert_invoked(positive_log, "reset --hard " + EXPECTED_SHA, "sha-reset")
    )
    failures.extend(
        assert_invoked(positive_log, "rev-parse HEAD", "sha-readback")
    )
    failures.extend(
        assert_invoked(
            positive_log,
            "docker BUILD_SHA="
            + EXPECTED_SHA
            + " compose build --build-arg BUILD_SHA="
            + EXPECTED_SHA
            + " backend mcp",
            "explicit-sha-build",
        )
    )
    failures.extend(
        assert_invoked(
            positive_log,
            "docker BUILD_SHA=" + EXPECTED_SHA + " compose build frontend",
            "frontend-build",
        )
    )
    failures.extend(
        assert_invoked(
            positive_log,
            "docker BUILD_SHA=" + EXPECTED_SHA + " compose up -d --no-build",
            "no-rebuild-up",
        )
    )
    failures.extend(assert_invoked(positive_log, "probe backend", "backend-health"))
    failures.extend(assert_invoked(positive_log, "probe mcp", "mcp-health"))
    failures.extend(
        assert_invoked(
            positive_log,
            "network-inspect phase=1 mode=valid",
            "trader-db-preflight",
        )
    )
    failures.extend(
        assert_invoked(
            positive_log,
            "network-inspect phase=2 mode=valid",
            "trader-db-postflight",
        )
    )
    failures.extend(
        assert_invoked(
            positive_log,
            "docker BUILD_SHA=" + EXPECTED_SHA + " compose ps -q postgres",
            "postgres-container-identity",
        )
    )
    failures.extend(
        assert_invoked(positive_log, "probe backend-ready", "backend-readiness")
    )
    if positive.returncode != 0:
        failures.append(
            "caught:matching-runtime-sha-rejected "
            f"exit={positive.returncode} stderr={positive.stderr.strip()!r}"
        )
    if "harness-runtime-temp-remnants=" in positive_log:
        failures.append("caught:deploy-release-temp-leaked-positive-path")

    # The deploy identity must remain bound to DEPLOY_SHA even when the remote
    # process starts with a stale BUILD_SHA. Production proved that both images
    # can be built as `dev`; this is a controlled ambient-environment class,
    # not a claim about the unavailable VPS root cause.
    clobbered, clobbered_log = run_deploy(
        script,
        backend_sha="dev",
        mcp_sha="dev",
        ambient_build_sha="dev",
    )
    failures.extend(
        assert_invoked(
            clobbered_log,
            "git BUILD_SHA=dev fetch origin",
            "ambient-build-sha-applied",
        )
    )
    if clobbered.returncode == 0:
        failures.append("caught:mutable-build-sha-clobber-accepted exit=0")

    recovered, recovered_log = run_deploy(script, ambient_build_sha="dev")
    failures.extend(
        assert_invoked(
            recovered_log,
            "git BUILD_SHA=dev fetch origin",
            "ambient-build-sha-positive-applied",
        )
    )
    failures.extend(
        assert_invoked(
            recovered_log,
            "docker BUILD_SHA="
            + EXPECTED_SHA
            + " compose build --build-arg BUILD_SHA="
            + EXPECTED_SHA
            + " backend mcp",
            "immutable-sha-build",
        )
    )
    if recovered.returncode != 0:
        failures.append(
            "caught:immutable-sha-clobber-rejected "
            f"exit={recovered.returncode} stderr={recovered.stderr.strip()!r}"
        )

    hostile_compose_file = "/tmp/ambient-compose.yml"
    hostile_env_files = "/dev/null"
    hostile, hostile_log = run_deploy(
        script,
        ambient_compose_file=hostile_compose_file,
        ambient_compose_env_files=hostile_env_files,
        ambient_compose_disable_env_file="1",
    )
    failures.extend(
        assert_invoked(
            hostile_log,
            f"ambient-compose file={hostile_compose_file} "
            f"env_files={hostile_env_files} disable_env=1",
            "ambient-compose-control-applied",
        )
    )
    compose_controls = [
        line for line in hostile_log.splitlines() if line.startswith("compose-control ")
    ]
    if not compose_controls:
        failures.append("caught:explicit-compose-control-not-observed")
    for line in compose_controls:
        if (
            "project=koopa0dev " not in line
            or "file=/tmp/ambient-compose.yml " in line
            or not line.split(" file=", 1)[1].split(" env_file=", 1)[0].endswith(
                "/docker-compose.yml"
            )
            or not line.split(" env_file=", 1)[1].split(" profiles=", 1)[0].endswith(
                "/.env"
            )
            or " profiles= remove_orphans=0" not in line
        ):
            failures.append(
                "caught:ambient-compose-control-reached-docker "
                f"line={line!r}"
            )
    if hostile.returncode != 0:
        failures.append(
            "caught:hostile-compose-environment-not-isolated "
            f"exit={hostile.returncode} stderr={hostile.stderr.strip()!r}"
        )

    config_mismatch, config_mismatch_log = run_deploy(
        script, compose_config_sha="dev"
    )
    failures.extend(
        assert_invoked(
            config_mismatch_log,
            "compose config --format json",
            "compose-config-mismatch-probed",
        )
    )
    if config_mismatch.returncode == 0:
        failures.append("caught:compose-config-sha-mismatch-accepted exit=0")
    if "compose build" in config_mismatch_log:
        failures.append("caught:compose-config-sha-mismatch-reached-build")

    release_mismatch, release_mismatch_log = run_deploy(
        script, release_entrypoint_blob_override="0" * 40
    )
    failures.extend(
        assert_invoked(
            release_mismatch_log,
            "hash-object --no-filters",
            "release-entrypoint-blob-mismatch-probed",
        )
    )
    if release_mismatch.returncode == 0:
        failures.append("caught:release-entrypoint-blob-mismatch-accepted exit=0")
    if "docker BUILD_SHA=" in release_mismatch_log:
        failures.append("caught:release-entrypoint-blob-mismatch-reached-docker")

    config_pos = deploy_script.find("compose config --format json")
    build_pos = deploy_script.find("compose build --build-arg")
    health_pos = deploy_script.find("# Post-deploy health check")
    ready_pos = deploy_script.find("http://localhost:8080/readyz")
    topology_pos = deploy_script.find("TOPOLOGY_RECEIPT network=trader-db")
    prune_pos = deploy_script.find("docker image prune -f")
    receipt_pos = deploy_script.find("DEPLOY_RECEIPT sha=")
    if min(
        config_pos,
        build_pos,
        health_pos,
        ready_pos,
        topology_pos,
        prune_pos,
        receipt_pos,
    ) < 0 or not (
        config_pos
        < build_pos
        < health_pos
        < ready_pos
        < prune_pos
        < topology_pos
        < receipt_pos
    ):
        failures.append(
            "caught:deploy-receipt-order-invalid "
            f"config={config_pos} build={build_pos} health={health_pos} "
            f"ready={ready_pos} prune={prune_pos} topology={topology_pos} "
            f"receipt={receipt_pos}"
        )
    if DEPLOY_ENTRYPOINT.is_file() and not deploy_script.rstrip().endswith(
        '"$DEPLOY_SHA" "$backend_receipt_sha" "$mcp_receipt_sha"'
    ):
        failures.append("caught:deploy-receipt-not-terminal")

    expected_receipt = (
        f"DEPLOY_RECEIPT sha={EXPECTED_SHA} "
        f"backend={EXPECTED_SHA} mcp={EXPECTED_SHA}"
    )
    if expected_receipt not in positive.stdout.splitlines():
        failures.append(
            "caught:remote-deploy-receipt-missing "
            f"expected={expected_receipt!r} stdout={positive.stdout.strip()!r}"
        )
    if positive.stdout.splitlines()[-2:] != [TOPOLOGY_RECEIPT, expected_receipt]:
        failures.append(
            "caught:topology-and-deploy-receipts-not-terminal "
            f"tail={positive.stdout.splitlines()[-2:]!r}"
        )

    compose_preflight_cases = (
        "missing-provider",
        "extra-postgres-network",
        "missing-alias",
        "colliding-alias",
        "other-service",
    )
    for mode in compose_preflight_cases:
        proc, log = run_deploy(script, compose_topology_mode=mode)
        failures.extend(
            assert_invoked(log, "compose config --format json", f"compose-{mode}")
        )
        if proc.returncode == 0:
            failures.append(f"caught:compose-topology-{mode}-accepted exit=0")
        if "compose build" in log:
            failures.append(f"caught:compose-topology-{mode}-reached-build")

    network_preflight_cases = (
        "inspect-fail",
        "wrong-driver",
        "wrong-scope",
        "internal",
        "ipv4-disabled",
        "unsafe-egress",
        "icc-disabled",
        "inhibit-ipv4",
        "routed-gateway",
        "isolated-gateway",
        "compose-owned",
        "unexpected-endpoint",
    )
    for mode in network_preflight_cases:
        proc, log = run_deploy(script, network_pre_mode=mode)
        failures.extend(
            assert_invoked(log, "network-inspect phase=1", f"network-{mode}")
        )
        if proc.returncode == 0:
            failures.append(f"caught:network-preflight-{mode}-accepted exit=0")
        if "compose build" in log:
            failures.append(f"caught:network-preflight-{mode}-reached-build")

    dns_collision, dns_collision_log = run_deploy(
        script, trader_pre_dns_mode="collision"
    )
    failures.extend(
        assert_invoked(
            dns_collision_log,
            "network-inspect phase=1",
            "network-dns-name-collision",
        )
    )
    if dns_collision.returncode == 0:
        failures.append("caught:network-preflight-dns-name-collision-accepted exit=0")
    if "compose build" in dns_collision_log:
        failures.append("caught:network-preflight-dns-name-collision-reached-build")

    for mode in ("missing", "malformed"):
        proc, log = run_deploy(script, trader_pre_dns_mode=mode)
        failures.extend(
            assert_invoked(log, "network-inspect phase=1", f"network-dns-names-{mode}")
        )
        if proc.returncode == 0:
            failures.append(f"caught:network-preflight-dns-names-{mode}-accepted exit=0")
        if "compose build" in log:
            failures.append(f"caught:network-preflight-dns-names-{mode}-reached-build")

    first_cutover, first_cutover_log = run_deploy(
        script, network_pre_mode="empty", network_post_mode="postgres-only"
    )
    failures.extend(
        assert_invoked(
            first_cutover_log,
            "network-inspect phase=1 mode=empty",
            "first-cutover-empty-network",
        )
    )
    failures.extend(
        assert_invoked(
            first_cutover_log,
            "network-inspect phase=2 mode=postgres-only",
            "first-cutover-post-state",
        )
    )
    if first_cutover.returncode != 0:
        failures.append(
            "caught:first-cutover-empty-to-postgres-only-rejected "
            f"exit={first_cutover.returncode} stderr={first_cutover.stderr.strip()!r}"
        )

    postflight_cases = (
        (
            "postgres-missing-internal",
            {"postgres_live_mode": "missing-internal"},
        ),
        (
            "postgres-missing-provider",
            {"postgres_live_mode": "missing-provider"},
        ),
        (
            "postgres-missing-alias",
            {"postgres_live_mode": "missing-alias"},
        ),
        (
            "postgres-missing-dns-name",
            {"postgres_live_mode": "missing-dns-name"},
        ),
        (
            "postgres-malformed-dns-names",
            {"postgres_live_mode": "malformed-dns-names"},
        ),
        (
            "postgres-extra-network",
            {"postgres_live_mode": "extra-network"},
        ),
        (
            "postgres-endpoint-missing",
            {"network_post_mode": "missing-postgres"},
        ),
        (
            "live-dns-name-collision",
            {"trader_dns_mode": "collision"},
        ),
    )
    for name, kwargs in postflight_cases:
        proc, log = run_deploy(script, **kwargs)
        failures.extend(
            assert_invoked(log, "network-inspect phase=2", f"postflight-{name}")
        )
        if proc.returncode == 0:
            failures.append(f"caught:postflight-{name}-accepted exit=0")

    false_ready, false_ready_log = run_deploy(
        script, backend_ready_mode="http-fail"
    )
    failures.extend(
        assert_invoked(false_ready_log, "probe backend-health", "false-ready-health")
    )
    failures.extend(
        assert_invoked(false_ready_log, "probe backend-ready", "false-ready-readyz")
    )
    if false_ready.returncode == 0:
        failures.append("caught:healthz-success-readyz-failure-accepted exit=0")
    if TOPOLOGY_RECEIPT in false_ready.stdout:
        failures.append("caught:false-ready-emitted-topology-receipt")

    cases = (
        (
            "checked-out-sha-mismatch-accepted",
            {"checked_out_sha": "4" * 40},
            "rev-parse HEAD",
        ),
        (
            "backend-build-sha-mismatch-accepted",
            {"backend_sha": "2" * 40},
            "probe backend",
        ),
        ("mcp-build-sha-mismatch-accepted", {"mcp_sha": "3" * 40}, "probe mcp"),
        ("backend-dev-sha-accepted", {"backend_sha": "dev"}, "probe backend"),
        ("mcp-missing-sha-accepted", {"mcp_mode": "missing"}, "probe mcp"),
        ("backend-non-ok-status-accepted", {"backend_mode": "bad-status"}, "probe backend"),
        ("backend-malformed-health-accepted", {"backend_mode": "malformed"}, "probe backend"),
    )
    for name, kwargs, marker in cases:
        proc, log = run_deploy(script, **kwargs)
        failures.extend(assert_invoked(log, marker, name))
        if proc.returncode == 0:
            failures.append(f"caught:{name} exit=0")

    return failures


def main() -> int:
    config, failures = render_compose_config()
    if config is not None:
        failures.extend(check_compose_build_args(config))
        failures.extend(check_compose_topology_mutations(config))
    failures.extend(check_commit_object_entrypoint())
    failures.extend(check_deploy_script())
    failures.extend(check_deploy_receipt())
    if failures:
        for failure in failures:
            print(failure)
        return 1

    print("PASS: backend and MCP consume and report the exact CI-approved SHA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
