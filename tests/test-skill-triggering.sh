#!/usr/bin/env bash
# Skill-triggering eval runner — ADVISORY, NOT part of verify-spec / CI.
#
# VALIDITY ENVELOPE (measured 2026-06-11, 40-case baseline run):
# Headless `claude -p --max-turns 1` answers a terse question directly from
# base knowledge and rarely invokes a Skill — so this harness CANNOT measure
# positive triggering of knowledge/reference skills (go-types, go-interfaces,
# error-patterns, etc.); in the real driver, those load via the always-loaded
# using-go-spec router mid-task, not from a cold one-shot prompt. What it CAN
# measure reliably is the BOUNDARY: that a skill does NOT fire when it must
# not (e.g. a build error must not trigger /debug). The baseline run showed
# zero mis-fires (boundary clean) and near-zero positive fires (expected,
# not a regression). So:
#   - BOUNDARY assertions (reject must-not-fire / expect=none) — reliable, gating.
#   - ROUTING assertions (expect should-fire) — advisory only; a 0 here in
#     headless mode is the environment, not a broken skill. Validate positive
#     routing in a real session, not here.
#
# Costs real tokens: each case is one headless `claude -p` invocation. Run
# deliberately, not habitually:
#
#   bash tests/test-skill-triggering.sh                          # all pairs, 1 run each
#   bash tests/test-skill-triggering.sh debug-vs-build-errors    # one pair
#   RUNS=3 bash tests/test-skill-triggering.sh                   # variance check
#
# DETECTION (experimental): parses stream-json for Skill tool_use events.
# If NO skill fires in ANY run, the stream-json shape may have changed —
# flagged as DETECTION SUSPECT rather than reported as a real 0% rate.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVALS_DIR="$PROJECT_ROOT/tests/skill-evals"
RUNS="${RUNS:-1}"
FILTER="${1:-}"

command -v claude >/dev/null || { echo "claude CLI required"; exit 1; }
command -v jq >/dev/null || { echo "jq required"; exit 1; }

bold()   { printf "\033[1m%s\033[0m\n" "$1"; }
red()    { printf "\033[31m%s\033[0m\n" "$1"; }
green()  { printf "\033[32m%s\033[0m\n" "$1"; }
yellow() { printf "\033[33m%s\033[0m\n" "$1"; }

# Returns the list of skills invoked for a query (one per line).
invoked_skills() {
    local query="$1"
    claude -p "$query" \
        --output-format stream-json --verbose --max-turns 1 2>/dev/null \
      | jq -r '
          select(.type == "assistant")
          | .message.content[]?
          | select(.type == "tool_use" and .name == "Skill")
          | .input.skill // empty
        ' 2>/dev/null | sort -u
}

total_cases=0
boundary_ok=0
boundary_fail=0
routing_fired=0
routing_silent=0
any_skill_seen=0

for f in "$EVALS_DIR"/*.json; do
    pair=$(jq -r '.pair' "$f")
    [[ -n "$FILTER" && "$pair" != "$FILTER" ]] && continue
    bold "=== $pair (runs per case: $RUNS) ==="

    case_count=$(jq '.cases | length' "$f")
    for i in $(seq 0 $((case_count - 1))); do
        query=$(jq -r ".cases[$i].query" "$f")
        expect=$(jq -r ".cases[$i].expect" "$f")
        reject=$(jq -r ".cases[$i].reject" "$f")

        for run in $(seq 1 "$RUNS"); do
            total_cases=$((total_cases + 1))
            skills=$(invoked_skills "$query" || true)
            [[ -n "$skills" ]] && any_skill_seen=1
            got=$(tr '\n' ',' <<<"$skills")

            # BOUNDARY (reliable, gating): the reject skill must NOT fire.
            if [[ -n "$reject" ]] && grep -qx "$reject" <<<"$skills"; then
                boundary_fail=$((boundary_fail + 1))
                red "  BOUNDARY VIOLATION: [$reject fired, must not] $query"
            else
                boundary_ok=$((boundary_ok + 1))
            fi

            # ROUTING (advisory only): did the expected skill fire? Not
            # reproducible for knowledge skills in headless one-shot mode.
            if [[ "$expect" != "none" ]]; then
                if grep -qx "$expect" <<<"$skills"; then
                    routing_fired=$((routing_fired + 1))
                    green "  ROUTED: [$expect] $query"
                else
                    routing_silent=$((routing_silent + 1))
                    yellow "  silent: [want $expect, got ${got:-none}] $query"
                fi
            fi
        done
    done
done

bold ""
bold "=== Results ==="
echo "BOUNDARY (gating): $boundary_ok ok, $boundary_fail violations"
echo "ROUTING (advisory): $routing_fired fired, $routing_silent silent (headless one-shot under-fires knowledge skills by design)"
if [[ "$any_skill_seen" == "0" && "$routing_silent" -gt 0 ]]; then
    yellow "DETECTION SUSPECT: no Skill fired in ANY run — stream-json shape may"
    yellow "have changed. Validate invoked_skills() before trusting routing numbers."
    exit 2
fi
if [[ "$boundary_fail" -gt 0 ]]; then
    red "FAILED: $boundary_fail boundary violation(s) — a skill fired when it must not."
    exit 1
fi
green "Boundaries clean. Routing silences are advisory — validate positive routing in a real session."
exit 0
