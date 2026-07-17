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


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
COMPOSE = ROOT / "docker-compose.yml"
DEPLOY_ENTRYPOINT = ROOT / "scripts/deploy-production.sh"
EXPECTED_SHA = "1111111111111111111111111111111111111111"


class ContractFailure(RuntimeError):
    """A deploy identity invariant was not satisfied."""


def extract_ssh_script(path: Path) -> str:
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
    return script.replace("${{ github.sha }}", EXPECTED_SHA) + "\n"


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


def check_compose_build_args() -> list[str]:
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
        return [
            "caught:compose-config-failed "
            f"exit={proc.returncode} stderr={proc.stderr.strip()}"
        ]

    try:
        config = json.loads(proc.stdout)
    except json.JSONDecodeError as err:
        return [f"caught:compose-config-invalid-json error={err}"]

    failures: list[str] = []
    for service in ("backend", "mcp"):
        build = config.get("services", {}).get(service, {}).get("build") or {}
        actual = (build.get("args") or {}).get("BUILD_SHA")
        if actual != EXPECTED_SHA:
            failures.append(
                f"caught:{service}-build-sha-not-propagated "
                f"expected={EXPECTED_SHA} actual={actual!r}"
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
        if [[ "${1:-}" == "rev-parse" && "${2:-}" == "HEAD" ]]; then
          printf '%s\n' "$CHECKED_OUT_SHA"
        fi
        ''',
    )
    write_executable(
        bin_dir / "docker",
        r'''
        #!/usr/bin/env bash
        set -eu
        printf 'docker BUILD_SHA=%s %s\n' "${BUILD_SHA:-}" "$*" >> "$HARNESS_LOG"

        if [[ "${1:-}" == "compose" && "${2:-}" == "up" ]]; then
          exit 0
        fi
        if [[ "${1:-}" == "compose" && "${2:-}" == "build" ]]; then
          exit 0
        fi
        if [[ "${1:-}" == "compose" && "${2:-}" == "config" ]]; then
          config_sha="${COMPOSE_CONFIG_SHA:-${BUILD_SHA:-dev}}"
          printf '{"services":{"backend":{"build":{"args":{"BUILD_SHA":"%s"}}},"mcp":{"build":{"args":{"BUILD_SHA":"%s"}}}}}\n' \
            "$config_sha" "$config_sha"
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
          printf 'probe %s\n' "$service" >> "$HARNESS_LOG"
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
    checked_out_sha: str = EXPECTED_SHA,
    grafana_env: str = "GRAFANA_ADMIN_PASSWORD=test-password\n",
    ambient_build_sha: str | None = None,
    compose_config_sha: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], str]:
    with tempfile.TemporaryDirectory(prefix="koopa-deploy-identity-") as raw_tmp:
        tmp = Path(raw_tmp)
        home = tmp / "home"
        repo = home / "koopa0.dev"
        observability = home / "server/observability"
        bin_dir = tmp / "bin"
        repo.mkdir(parents=True)
        observability.mkdir(parents=True)
        bin_dir.mkdir()
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
            }
        )
        if ambient_build_sha is not None:
            env["BUILD_SHA"] = ambient_build_sha
        if compose_config_sha is not None:
            env["COMPOSE_CONFIG_SHA"] = compose_config_sha
        proc = subprocess.run(
            ["bash", str(script_path)],
            cwd=repo,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        log = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
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
    positive = run_receipt_verifier(verifier, f"build output\n{expected}\n")
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
    )
    for name, stdout in cases:
        proc = run_receipt_verifier(verifier, stdout)
        if proc.returncode == 0:
            failures.append(f"caught:{name} exit=0")
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
            'exec /bin/bash --noprofile --norc scripts/deploy-production.sh '
            '"$DEPLOY_SHA"'
        )
        if required_outer not in script:
            failures.append(
                "caught:explicit-deploy-shell-missing "
                f"needle={required_outer!r}"
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
    if positive.returncode != 0:
        failures.append(
            "caught:matching-runtime-sha-rejected "
            f"exit={positive.returncode} stderr={positive.stderr.strip()!r}"
        )

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

    config_pos = deploy_script.find("docker compose config --format json")
    build_pos = deploy_script.find("docker compose build --build-arg")
    health_pos = deploy_script.find("# Post-deploy health check")
    prune_pos = deploy_script.find("docker image prune -f")
    receipt_pos = deploy_script.find("DEPLOY_RECEIPT sha=")
    if min(config_pos, build_pos, health_pos, prune_pos, receipt_pos) < 0 or not (
        config_pos < build_pos < health_pos < prune_pos < receipt_pos
    ):
        failures.append(
            "caught:deploy-receipt-order-invalid "
            f"config={config_pos} build={build_pos} health={health_pos} "
            f"prune={prune_pos} receipt={receipt_pos}"
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
    failures = check_compose_build_args()
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
