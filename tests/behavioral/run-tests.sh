#!/bin/bash
# Behavioral tests for go-spec agent behavior
# Uses claude -p (non-interactive) with haiku for cost efficiency
# Advisory mode: reports results but does not block CI
#
# Usage: ./tests/behavioral/run-tests.sh [test-name]
# Without args: runs all tests
# With arg: runs only that test (e.g., ./run-tests.sh tier-selection)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
MODEL="${BEHAVIORAL_TEST_MODEL:-haiku}"
PASS=0
FAIL=0
SKIP=0
RESULTS=""

run_test() {
  local name="$1"
  local prompt="$2"
  local check_pattern="$3"
  local anti_pattern="${4:-}"

  if [ -n "${TEST_FILTER:-}" ] && [ "$name" != "$TEST_FILTER" ]; then
    SKIP=$((SKIP + 1))
    return
  fi

  printf "  %-40s " "$name"

  local output
  output=$(cd "$PROJECT_DIR" && perl -e 'alarm 120; exec @ARGV' claude -p "$prompt" --model "$MODEL" 2>/dev/null) || {
    printf "SKIP (timeout or error)\n"
    SKIP=$((SKIP + 1))
    return
  }

  local passed=true

  # Check required pattern
  if ! echo "$output" | grep -qiE "$check_pattern"; then
    passed=false
  fi

  # Check anti-pattern (should NOT be present)
  if [ -n "$anti_pattern" ] && echo "$output" | grep -qiE "$anti_pattern"; then
    passed=false
  fi

  if $passed; then
    printf "PASS\n"
    PASS=$((PASS + 1))
  else
    printf "FAIL\n"
    FAIL=$((FAIL + 1))
    RESULTS+="--- FAIL: $name ---\n"
    RESULTS+="Expected pattern: $check_pattern\n"
    if [ -n "$anti_pattern" ]; then
      RESULTS+="Anti-pattern: $anti_pattern\n"
    fi
    RESULTS+="Output (first 500 chars): $(echo "$output" | head -c 500)\n\n"
  fi
}

echo "=== go-spec Behavioral Tests ==="
echo "Model: $MODEL"
echo "Project: $PROJECT_DIR"
echo ""

TEST_FILTER="${1:-}"

# --- Test 1: Tier Selection ---
echo "Tier Selection:"

run_test "tier-1-typo" \
  "I want to fix the typo in the error message in internal/order/order.go. What tier is this? Answer ONLY with: Tier N because: <reason>. Do not do anything else." \
  "tier.?1" \
  "tier.?3"

run_test "tier-3-new-feature" \
  "I want to add email notifications when an order is created. This needs a new internal/notification/ package. What tier is this? Answer ONLY with: Tier N because: <reason>. Do not do anything else." \
  "tier.?3" \
  "tier.?1"

# --- Test 2: Augment MCP Usage ---
echo ""
echo "Search Strategy:"

run_test "augment-awareness" \
  "You have access to codebase-retrieval (Augment Context Engine MCP) and Grep. If a user asks 'how does error handling work in this project?', which tool should you use FIRST and why? Answer in under 50 words." \
  "codebase.retrieval|context.engine|augment|semantic|MCP" \
  ""

run_test "grep-for-symbol" \
  "You have access to codebase-retrieval (Augment Context Engine MCP) and Grep. If a user asks 'find all files that use pgxpool.Pool', which tool should you use and why? Answer in under 50 words." \
  "grep|Grep|rg|exact|symbol|exhaustive" \
  ""

# --- Test 3: Verification Quality ---
echo ""
echo "Verification Quality:"

run_test "no-phantom-pass" \
  "RULE: Verification requires reading ACTUAL output, not just exit codes. A phantom pass is when you say 'all passed' without quoting specific output. Now: pretend go test returned exit 0. What information must you check in the output before claiming tests passed? List 3 specific things. Answer in under 80 words." \
  "package|file|test.count|test.name|coverage|PASS.*ok|ran.*test" \
  ""

# --- Test 4: Subagent Context ---
echo ""
echo "Subagent Context:"

run_test "no-history-leak" \
  "You are executing a plan. Task 3 is 'Create store.go for the notification package'. Write the first 3 lines of the prompt you would send to a subagent for this task. Do NOT include any conversation history." \
  "task|file|scope|store" \
  "as we discussed|based on the above|continuing from|user wants"

echo ""
echo "=== Results ==="
echo "PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP"

if [ -n "$RESULTS" ]; then
  echo ""
  echo "=== Failure Details ==="
  echo -e "$RESULTS"
fi

# Advisory: always exit 0
exit 0
