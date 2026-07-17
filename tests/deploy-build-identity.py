#!/usr/bin/env python3
"""Verify the CI-approved SHA reaches both running service identities.

The test has two independent oracles:

1. Docker Compose must resolve BUILD_SHA into both image build arguments.
2. The real SSH script extracted from ci.yml must reject any runtime health
   response whose build SHA differs from the push SHA.

No production commands run. External commands in the extracted deploy script
are replaced with deterministic boundary stubs inside a temporary HOME.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
COMPOSE = ROOT / "docker-compose.yml"
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
        printf 'git %s\n' "$*" >> "$HARNESS_LOG"
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
        printf 'curl %s\n' "$*" >> "$HARNESS_LOG"
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
        (observability / ".env").write_text(
            "GRAFANA_ADMIN_PASSWORD=test-password\n", encoding="utf-8"
        )
        install_boundary_stubs(bin_dir)

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


def check_deploy_script() -> list[str]:
    try:
        script = extract_ssh_script(WORKFLOW)
    except ContractFailure as err:
        return [str(err)]

    failures: list[str] = []
    positive, positive_log = run_deploy(script)
    failures.extend(
        assert_invoked(positive_log, "git reset --hard " + EXPECTED_SHA, "sha-reset")
    )
    failures.extend(
        assert_invoked(positive_log, "git rev-parse HEAD", "sha-readback")
    )
    failures.extend(
        assert_invoked(
            positive_log,
            "docker BUILD_SHA=" + EXPECTED_SHA + " compose up -d --build",
            "sha-build",
        )
    )
    failures.extend(assert_invoked(positive_log, "probe backend", "backend-health"))
    failures.extend(assert_invoked(positive_log, "probe mcp", "mcp-health"))
    if positive.returncode != 0:
        failures.append(
            "caught:matching-runtime-sha-rejected "
            f"exit={positive.returncode} stderr={positive.stderr.strip()!r}"
        )

    cases = (
        (
            "checked-out-sha-mismatch-accepted",
            {"checked_out_sha": "4" * 40},
            "git rev-parse HEAD",
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
    if failures:
        for failure in failures:
            print(failure)
        return 1

    print("PASS: backend and MCP consume and report the exact CI-approved SHA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
