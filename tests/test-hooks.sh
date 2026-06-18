#!/usr/bin/env bash
# Automated tests for Claude Code hooks.
# Run from project root: bash tests/test-hooks.sh
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOOK_DIR="$PROJECT_ROOT/.claude/hooks"
PASS=0
FAIL=0
TOTAL=0

red()   { printf "\033[31m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

assert_exit() {
    local description="$1"
    local expected_exit="$2"
    local actual_exit="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "$actual_exit" == "$expected_exit" ]]; then
        green "  PASS: $description"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $description (expected exit $expected_exit, got $actual_exit)"
        FAIL=$((FAIL + 1))
    fi
}

assert_output_contains() {
    local description="$1"
    local expected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "$actual" == *"$expected"* ]]; then
        green "  PASS: $description"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $description (expected output containing '$expected')"
        FAIL=$((FAIL + 1))
    fi
}

assert_output_not_contains() {
    local description="$1"
    local unexpected="$2"
    local actual="$3"
    TOTAL=$((TOTAL + 1))
    if [[ "$actual" != *"$unexpected"* ]]; then
        green "  PASS: $description"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $description (output must NOT contain '$unexpected')"
        FAIL=$((FAIL + 1))
    fi
}

# ============================================================
bold "=== check-anti-patterns.sh ==="
# ============================================================

HOOK="$HOOK_DIR/check-anti-patterns.sh"

# --- Should ALLOW ---

bold "  Allowed paths:"

for path in \
    "internal/order/store.go" \
    "internal/order/handler.go" \
    "internal/auth/middleware.go" \
    "cmd/app/main.go" \
    ".claude/rules/database.md" \
    "migrations/001_init.up.sql" \
    "sqlc.yaml" \
    "Makefile" \
    "internal/db/query.sql.go" \
    "$PROJECT_ROOT/internal/order/store.go"
do
    output=$(echo "{\"tool_input\":{\"file_path\":\"$path\"}}" | "$HOOK" 2>&1) || true
    exit_code=$(echo "{\"tool_input\":{\"file_path\":\"$path\"}}" | "$HOOK" 2>/dev/null; echo $?)
    # Re-run to capture actual exit code
    set +e
    echo "{\"tool_input\":{\"file_path\":\"$path\"}}" | "$HOOK" > /dev/null 2>&1
    actual=$?
    set -e
    assert_exit "allow: $path" 0 "$actual"
done

# --- Should BLOCK ---

bold "  Blocked paths:"

blocked_paths=(
    "internal/services/order.go:services"
    "internal/service/order.go:service"
    "internal/repositories/order.go:repositories"
    "internal/repository/order.go:repository"
    "internal/handlers/order.go:handlers"
    "internal/handler/order.go:handler"
    "internal/controllers/order.go:controllers"
    "internal/controller/order.go:controller"
    "internal/models/order.go:models"
    "internal/model/order.go:model"
    "internal/entities/order.go:entities"
    "internal/entity/order.go:entity"
    "internal/dto/order.go:dto"
    "internal/dtos/order.go:dtos"
    "internal/mappers/order.go:mappers"
    "internal/mapper/order.go:mapper"
    "internal/factory/order.go:factory"
    "internal/factories/order.go:factories"
    "internal/domain/order.go:domain"
    "internal/infrastructure/order.go:infrastructure"
    "internal/application/order.go:application"
    "internal/presentation/order.go:presentation"
    "internal/util/order.go:util"
    "internal/utils/order.go:utils"
    "internal/helper/order.go:helper"
    "internal/helpers/order.go:helpers"
    "internal/common/order.go:common"
    "internal/shared/order.go:shared"
    "internal/base/order.go:base"
    "internal/types/order.go:types"
    "internal/src/order.go:src"
    "internal/pkg/order.go:pkg"
)

for entry in "${blocked_paths[@]}"; do
    path="${entry%%:*}"
    dirname="${entry##*:}"
    set +e
    output=$(echo "{\"tool_input\":{\"file_path\":\"$path\"}}" | "$HOOK" 2>&1)
    actual=$?
    set -e
    assert_exit "block: $path" 2 "$actual"
    assert_output_contains "block message mentions '$dirname'" "$dirname" "$output"
done

# --- Edge cases ---

bold "  Edge cases:"

# No file_path in input
set +e
echo '{"tool_input":{"content":"hello"}}' | "$HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "no file_path → allow" 0 "$actual"

# Empty input
set +e
echo '{}' | "$HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "empty JSON → allow" 0 "$actual"

# Absolute path with GOPATH /src/ (the bug we fixed)
set +e
echo "{\"tool_input\":{\"file_path\":\"$PROJECT_ROOT/.claude/rules/database.md\"}}" | "$HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "absolute GOPATH path → allow (no /src/ false positive)" 0 "$actual"

# Absolute path with forbidden dir
set +e
echo "{\"tool_input\":{\"file_path\":\"$PROJECT_ROOT/internal/services/foo.go\"}}" | "$HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "absolute path with forbidden dir → block" 2 "$actual"

# ============================================================
bold "=== format-go.sh ==="
# ============================================================

FORMAT_HOOK="$HOOK_DIR/format-go.sh"

bold "  Format behavior:"

# Non-.go file should be skipped
set +e
echo '{"tool_input":{"file_path":"README.md"}}' | "$FORMAT_HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "non-.go file → skip (exit 0)" 0 "$actual"

# Nonexistent .go file should be skipped
set +e
echo '{"tool_input":{"file_path":"nonexistent.go"}}' | "$FORMAT_HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "nonexistent .go file → skip (exit 0)" 0 "$actual"

# Existing .go file should be formatted
set +e
echo "{\"tool_input\":{\"file_path\":\"$PROJECT_ROOT/cmd/app/main.go\"}}" | "$FORMAT_HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "existing .go file → format (exit 0)" 0 "$actual"

# Empty input
set +e
echo '{}' | "$FORMAT_HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "empty input → skip (exit 0)" 0 "$actual"

# ============================================================
bold "=== check-anti-patterns.sh (mock codegen) ==="
# ============================================================

bold "  Mock generation blocking:"

set +e
output=$(echo '{"tool_input":{"file_path":"internal/order/store_test.go","content":"package order\n\n//go:generate mockgen -source=store.go -destination=mock_store.go\n"}}' | "$HOOK" 2>&1)
actual=$?
set -e
assert_exit "//go:generate mockgen → block" 2 "$actual"
assert_output_contains "mock block message cites Test Doubles" "Test Doubles" "$output"

set +e
echo '{"tool_input":{"file_path":"internal/order/mock_store.go","content":"// Code generated by MockGen. DO NOT EDIT.\npackage order\n"}}' | "$HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "committed MockGen output → block" 2 "$actual"

set +e
echo '{"tool_input":{"file_path":"internal/order/store.go","content":"package order\n\n//go:generate sqlc generate\n"}}' | "$HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "non-mock go:generate → allow" 0 "$actual"

set +e
echo '{"tool_input":{"file_path":"docs/notes.md","content":"mockgen is forbidden here"}}' | "$HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "non-.go file mentioning mockgen → allow" 0 "$actual"

# ============================================================
bold "=== check-naming-conventions.sh (integration tests) ==="
# ============================================================

NAMING_HOOK="$HOOK_DIR/check-naming-conventions.sh"
nm_tmp=$(mktemp -d)

bold "  Integration test file convention:"

cat > "$nm_tmp/order_integration_test.go" <<'GOF'
//go:build integration

package order_test
GOF
set +e
output=$(echo "{\"tool_input\":{\"file_path\":\"$nm_tmp/order_integration_test.go\"}}" | "$NAMING_HOOK" 2>&1)
actual=$?
set -e
assert_exit "tagged file, wrong name → advisory exit 0" 0 "$actual"
assert_output_contains "tagged file, wrong name → warn" "integration_test.go" "$output"

cat > "$nm_tmp/integration_test.go" <<'GOF'
//go:build integration

package order_test
GOF
set +e
output=$(echo "{\"tool_input\":{\"file_path\":\"$nm_tmp/integration_test.go\"}}" | "$NAMING_HOOK" 2>&1)
set -e
assert_output_not_contains "integration_test.go with tag → silent" "NAMING" "$output"

cat > "$nm_tmp/integration_test.go" <<'GOF'
package order_test
GOF
set +e
output=$(echo "{\"tool_input\":{\"file_path\":\"$nm_tmp/integration_test.go\"}}" | "$NAMING_HOOK" 2>&1)
set -e
assert_output_contains "integration_test.go without tag → warn" "go:build integration" "$output"

cat > "$nm_tmp/order_test.go" <<'GOF'
package order
GOF
set +e
output=$(echo "{\"tool_input\":{\"file_path\":\"$nm_tmp/order_test.go\"}}" | "$NAMING_HOOK" 2>&1)
set -e
assert_output_not_contains "plain unit test file → silent" "NAMING" "$output"
rm -rf "$nm_tmp"

# ============================================================
bold "=== check-test-interface.sh ==="
# ============================================================

TI_HOOK="$HOOK_DIR/check-test-interface.sh"
ti_tmp=$(mktemp -d)

bold "  Test-file interface detection:"

cat > "$ti_tmp/order_test.go" <<'GOF'
package order

type fakeStore interface {
	Order(id string) (*Order, error)
}
GOF
set +e
output=$(echo "{\"tool_input\":{\"file_path\":\"$ti_tmp/order_test.go\"}}" | "$TI_HOOK" 2>&1)
actual=$?
set -e
assert_exit "test interface → advisory exit 0" 0 "$actual"
assert_output_contains "unexported test interface → warn (was missed pre-audit)" "fakeStore" "$output"
assert_output_contains "citation points to real rule file" "rules/interfaces.md" "$output"
assert_output_not_contains "phantom citation removed" "interface-golden-rule" "$output"

cat > "$ti_tmp/clean_test.go" <<'GOF'
package order

type payload struct {
	Data interface{}
}
GOF
set +e
output=$(echo "{\"tool_input\":{\"file_path\":\"$ti_tmp/clean_test.go\"}}" | "$TI_HOOK" 2>&1)
set -e
assert_output_not_contains "interface{} field → no false positive" "WARNING" "$output"
rm -rf "$ti_tmp"

# ============================================================
bold "=== check-interface-creation.sh ==="
# ============================================================

IC_HOOK="$HOOK_DIR/check-interface-creation.sh"
ic_tmp=$(mktemp -d)

bold "  Interface definition detection:"

cat > "$ic_tmp/notifier.go" <<'GOF'
package notification

type orderReader interface {
	Order(id string) (*Order, error)
}
GOF
set +e
output=$(echo "{\"tool_input\":{\"file_path\":\"$ic_tmp/notifier.go\"}}" | "$IC_HOOK" 2>&1)
actual=$?
set -e
assert_exit "interface check → advisory exit 0" 0 "$actual"
assert_output_contains "unexported interface → caught (was missed pre-audit)" "orderReader" "$output"
assert_output_contains "message includes discovery exception" "consumer-boundary" "$output"

cat > "$ic_tmp/grouped.go" <<'GOF'
package order

type (
	Validator interface {
		Validate() error
	}
)
GOF
set +e
output=$(echo "{\"tool_input\":{\"file_path\":\"$ic_tmp/grouped.go\"}}" | "$IC_HOOK" 2>&1)
set -e
assert_output_contains "grouped type block interface → caught" "Validator" "$output"

cat > "$ic_tmp/clean.go" <<'GOF'
package order

func decode(data map[string]interface{}) error {
	return nil
}
GOF
set +e
output=$(echo "{\"tool_input\":{\"file_path\":\"$ic_tmp/clean.go\"}}" | "$IC_HOOK" 2>&1)
set -e
assert_output_not_contains "interface{} usage → no false positive" "INTERFACE CHECK" "$output"
rm -rf "$ic_tmp"

# ============================================================
bold "=== on-error-handler.sh (PostToolUseFailure) ==="
# ============================================================

ERR_HOOK="$HOOK_DIR/on-error-handler.sh"

bold "  Error classification:"

set +e
output=$(echo '{"tool_response":{"exit_code":2,"stderr":"./main.go:10:2: undefined: foo","stdout":""}}' | "$ERR_HOOK" 2>&1)
actual=$?
set -e
assert_exit "build error → exit 0 (non-blocking)" 0 "$actual"
assert_output_contains "build error → suggests build-resolver" "build-resolver" "$output"

set +e
output=$(echo '{"tool_response":{"exit_code":1,"stderr":"","stdout":"--- FAIL: TestOrder (0.00s)"}}' | "$ERR_HOOK" 2>&1)
set -e
assert_output_contains "test failure → suggests test-writer" "test-writer" "$output"

set +e
output=$(echo '{"tool_response":{"exit_code":0,"stderr":"","stdout":"ok"}}' | "$ERR_HOOK" 2>&1)
set -e
assert_output_not_contains "zero exit on failure event → silent" "[Error]" "$output"

# ============================================================
bold "=== on-user-prompt.sh (autonomous skill surfacing) ==="
# ============================================================

UP_HOOK="$HOOK_DIR/on-user-prompt.sh"

bold "  Skill surfacing on clear signals:"

set +e
out=$(echo '{"prompt":"am I over-engineering this auth layer?"}' | "$UP_HOOK" 2>&1)
set -e
assert_output_contains "over-engineering → surfaces devil-advocate" "devil-advocate" "$out"

set +e
out=$(echo '{"prompt":"does this package structure make sense?"}' | "$UP_HOOK" 2>&1)
set -e
assert_output_contains "design-quality question → surfaces design-review" "design-review" "$out"

set +e
out=$(echo '{"prompt":"add a notification feature backed by NATS"}' | "$UP_HOOK" 2>&1)
set -e
assert_output_contains "new-feature request → reinforces comprehend FIRST" "comprehend" "$out"

set +e
out=$(echo '{"prompt":"add a status field to the order struct"}' | "$UP_HOOK" 2>&1)
set -e
assert_output_not_contains "trivial edit → no comprehend noise" "comprehend" "$out"
assert_output_not_contains "trivial edit → no skill noise" "SKILL SUGGESTION" "$out"

set +e
echo '{"prompt":"add a status field"}' | "$UP_HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "ordinary request → exit 0" 0 "$actual"

# ============================================================
bold "=== check-before-stop.sh (reflect nudge) ==="
# ============================================================

STOP_HOOK="$HOOK_DIR/check-before-stop.sh"
LEARN_LOG="$PROJECT_ROOT/.claude/session-learnings.log"

bold "  /reflect nudge when learnings captured:"

# back up any real log, then test with a synthetic entry
had_log=0; [ -f "$LEARN_LOG" ] && { cp "$LEARN_LOG" "$LEARN_LOG.testbak"; had_log=1; }
printf 'candidate-target: rule:testing\nlesson: synthetic test entry\n' > "$LEARN_LOG"
set +e
out=$( cd "$PROJECT_ROOT" && "$STOP_HOOK" 2>&1 )
set -e
assert_output_contains "non-empty learnings log → /reflect reminder" "/reflect" "$out"
assert_output_not_contains "no stale koopa0 save_session_note reminder" "save_session_note" "$out"

# empty log → no reflect nudge
: > "$LEARN_LOG"
set +e
out=$( cd "$PROJECT_ROOT" && "$STOP_HOOK" 2>&1 )
set -e
assert_output_not_contains "empty learnings log → no reflect nudge" "run /reflect" "$out"
# restore
if [ "$had_log" = 1 ]; then mv "$LEARN_LOG.testbak" "$LEARN_LOG"; else rm -f "$LEARN_LOG"; fi

# ============================================================
bold "=== log-instructions-loaded.sh ==="
# ============================================================

IL_HOOK="$HOOK_DIR/log-instructions-loaded.sh"
IL_LOG="$PROJECT_ROOT/.claude/rule-load.log"

bold "  Rule-load audit logging:"

il_before=$(wc -l < "$IL_LOG" 2>/dev/null || echo 0)
set +e
echo '{"file_path":"/x/.claude/rules/database.md","memory_type":"Project","load_reason":"path_glob_match","globs":["**/*store*.go"],"trigger_file_path":"/x/internal/order/store.go"}' | "$IL_HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "instructions-loaded → exit 0 (observe-only)" 0 "$actual"
il_after=$(wc -l < "$IL_LOG" 2>/dev/null || echo 0)
ok=0; [ "$il_after" -gt "$il_before" ] || ok=1
assert_exit "appends a JSONL line to rule-load.log" 0 "$ok"
last=$(tail -1 "$IL_LOG" 2>/dev/null)
assert_output_contains "logged line records load_reason" "path_glob_match" "$last"
assert_output_contains "logged line records the rule file" "database.md" "$last"

# empty input must not crash
set +e
echo '{}' | "$IL_HOOK" > /dev/null 2>&1
actual=$?
set -e
assert_exit "empty input → exit 0" 0 "$actual"

# ============================================================
bold "=== session-start.sh ==="
# ============================================================

SESSION_HOOK="$HOOK_DIR/session-start.sh"

bold "  Toolchain warnings:"

# Normal run in project root: exits 0
set +e
( cd "$PROJECT_ROOT" && "$SESSION_HOOK" > /dev/null 2>&1 )
actual=$?
set -e
assert_exit "project root → exit 0" 0 "$actual"

# Stale v1 golangci-lint binary in PATH → version warning
fakebin=$(mktemp -d)
cat > "$fakebin/golangci-lint" <<'FAKE'
#!/bin/bash
echo "golangci-lint has version v1.64.8 built with go1.26.3"
FAKE
chmod +x "$fakebin/golangci-lint"
set +e
output=$( cd "$PROJECT_ROOT" && PATH="$fakebin:$PATH" "$SESSION_HOOK" 2>&1 )
set -e
assert_output_contains "v1 binary in PATH → not-v2 warning" "not v2" "$output"
rm -rf "$fakebin"

# v2 golangci-lint (real env) → no not-v2 warning
set +e
output=$( cd "$PROJECT_ROOT" && "$SESSION_HOOK" 2>&1 )
set -e
assert_output_not_contains "v2 binary → no not-v2 warning" "not v2" "$output"

# benchstat / govulncheck missing from PATH → install hints
set +e
output=$( cd "$PROJECT_ROOT" && PATH="/usr/bin:/bin" "$SESSION_HOOK" 2>&1 )
set -e
assert_output_contains "missing benchstat → warning with install cmd" "benchstat" "$output"
assert_output_contains "missing govulncheck → warning with install cmd" "govulncheck" "$output"

bold "  settings.json declarative gates:"

SETTINGS="$PROJECT_ROOT/.claude/settings.json"

ok=0; jq -e '[.hooks.PostToolUse[] | select(.matcher == "Bash") | .hooks[] | select(.command | contains("verify-commit-message")) | .if] | any(. != null and startswith("Bash(git commit"))' "$SETTINGS" > /dev/null 2>&1 || ok=1
assert_exit "verify-commit-message has if: Bash(git commit *)" 0 "$ok"

ok=0; jq -e '.permissions.ask | length >= 8' "$SETTINGS" > /dev/null 2>&1 || ok=1
assert_exit "permissions.ask guards harness config files" 0 "$ok"

ok=0; jq -e '.permissions.ask | map(select(contains(".claude/rules"))) | length >= 1' "$SETTINGS" > /dev/null 2>&1 || ok=1
assert_exit "ask rules cover .claude/rules" 0 "$ok"

bold "  Go version floor (synctest):"

floor_tmp=$(mktemp -d)
printf 'module floortest\n\ngo 1.24\n' > "$floor_tmp/go.mod"
set +e
output=$( cd "$floor_tmp" && "$SESSION_HOOK" 2>&1 )
actual=$?
set -e
assert_exit "go 1.24 → still exit 0 (warning only)" 0 "$actual"
assert_output_contains "go 1.24 → synctest floor warning" "synctest" "$output"

printf 'module floortest\n\ngo 1.26.1\n' > "$floor_tmp/go.mod"
set +e
output=$( cd "$floor_tmp" && "$SESSION_HOOK" 2>&1 )
set -e
assert_output_not_contains "go 1.26.1 → no floor warning" "<1.25" "$output"

printf 'module floortest\n\ngo 1.25\n' > "$floor_tmp/go.mod"
set +e
output=$( cd "$floor_tmp" && "$SESSION_HOOK" 2>&1 )
set -e
assert_output_not_contains "go 1.25 exactly → no floor warning" "<1.25" "$output"
rm -rf "$floor_tmp"

# ============================================================
bold "=== check-secrets.sh (PreToolUse secret blocking) ==="
# ============================================================

SEC_HOOK="$HOOK_DIR/check-secrets.sh"

run_sec() { # file_path, content -> exit code
    set +e
    printf '{"tool_input":{"file_path":%s,"content":%s}}' "$(jq -Rn --arg v "$1" '$v')" "$(jq -Rn --arg v "$2" '$v')" | "$SEC_HOOK" >/dev/null 2>&1
    local rc=$?
    set -e
    echo "$rc"
}

bold "  Allowed (exit 0):"
assert_exit "benign Go file"               0 "$(run_sec 'internal/order/store.go' 'const tableName = "orders"')"
assert_exit ".env.example placeholder"     0 "$(run_sec '.env.example' 'DATABASE_URL=postgres://user:password@localhost/db')"
assert_exit "placeholder DSN in code"      0 "$(run_sec 'internal/order/store.go' 'dsn := "postgres://user:password@localhost:5432/app"')"
assert_exit "fake secret under fixtures"   0 "$(run_sec 'tests/fixtures/x/seed.go' 'k := "AKIAIOSFODNN7EXAMPLE"')"
assert_exit "fake secret in *_test.go"      0 "$(run_sec 'internal/order/order_test.go' 'tok := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"')"
assert_exit ".env still blocked under tests" 2 "$(run_sec 'tests/.env' 'X=1')"

bold "  Blocked (exit 2):"
assert_exit ".env by filename"             2 "$(run_sec '.env' 'X=1')"
assert_exit ".pem by extension"            2 "$(run_sec 'deploy/prod.pem' 'data')"
assert_exit "private key in content"       2 "$(run_sec 'internal/k/keys.go' '-----BEGIN RSA PRIVATE KEY-----')"
assert_exit "AWS access key in content"    2 "$(run_sec 'internal/aws/c.go' 'id := "AKIAIOSFODNN7EXAMPLE"')"
assert_exit "GitHub token in content"      2 "$(run_sec 'internal/gh/t.go' 'tok := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"')"
assert_exit "real-password DSN in content" 2 "$(run_sec 'internal/db/conn.go' 'dsn := "postgres://admin:hunter2hunterX@prod-db:5432/app"')"

# ============================================================
bold "=== check-before-stop.sh (loop guard + clean-tree nudge) ==="
# ============================================================

bold "  Loop guard:"
set +e
printf '{"stop_hook_active":true}' | "$STOP_HOOK" >/dev/null 2>&1
actual=$?
set -e
assert_exit "stop_hook_active=true → exit 0 without re-running gate" 0 "$actual"

bold "  /reflect nudge fires on a CLEAN tree (regression guard):"
# A clean working tree must NOT suppress the reflect nudge. Run the hook from a
# clean temp git repo while the (real) learnings log has content.
had_log2=0; [ -f "$LEARN_LOG" ] && { cp "$LEARN_LOG" "$LEARN_LOG.cleanbak"; had_log2=1; }
printf 'candidate-target: rule:testing\nlesson: clean-tree entry\n' > "$LEARN_LOG"
clean_repo=$(mktemp -d)
( cd "$clean_repo" && git init -q && git commit -q --allow-empty -m init )
set +e
out=$( cd "$clean_repo" && printf '{}' | "$STOP_HOOK" 2>&1 )
set -e
assert_output_contains "clean tree + learnings → still nudges /reflect" "/reflect" "$out"
rm -rf "$clean_repo"
if [ "$had_log2" = 1 ]; then mv "$LEARN_LOG.cleanbak" "$LEARN_LOG"; else rm -f "$LEARN_LOG"; fi

# ============================================================
bold ""
bold "=== Results ==="
# ============================================================

echo "Total: $TOTAL  Pass: $PASS  Fail: $FAIL"

if [[ "$FAIL" -gt 0 ]]; then
    red "FAILED"
    exit 1
else
    green "ALL PASSED"
    exit 0
fi
