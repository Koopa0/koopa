#!/usr/bin/env bash
# Lint-config regression guard — ADVISORY, NOT part of verify-spec / CI.
#
# go-spec ships a strict golangci-lint config (depguard, forbidigo, ~18 extra
# linters, SA1019) but has no feature code of its own — only a 107-line wiring
# main.go. So the config can silently start rejecting CONFORMANT code (e.g.
# govet fieldalignment fighting the readable-struct + table-driven conventions,
# found 2026-06-11) and nothing would catch it until a consumer's first feature.
#
# This materializes a known-conformant feature (tests/fixtures/conformant-order:
# types+sentinels, pgx store with errors.AsType, consumer-interface handler,
# table-driven go-cmp tests, hand-written fake, b.Loop benchmark) into a temp
# module, applies the shipped .golangci.yml, and asserts ZERO lint issues. A
# failure means a linter is rejecting code that follows the harness's own rules
# — fix the config, not the fixture.
#
# Needs network (go get pgx + go-cmp) — hence advisory, not CI. Run before
# shipping any .golangci.yml change:
#   bash tests/test-lint-fixture.sh
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$PROJECT_ROOT/tests/fixtures/conformant-order"
MOD="example.com/shop"

command -v golangci-lint >/dev/null || { echo "golangci-lint required"; exit 1; }
golangci-lint version 2>/dev/null | grep -q 'version 2\.' || { echo "golangci-lint v2 required"; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/internal/order"

( cd "$work" && go mod init "$MOD" >/dev/null 2>&1 )
for f in order store handler order_test; do
    cp "$FIX/$f.go.txt" "$work/internal/order/$f.go"
done
# ship config with the consumer module path swapped in
sed "s#github.com/koopa0/go-spec#$MOD#" "$PROJECT_ROOT/.golangci.yml" > "$work/.golangci.yml"

( cd "$work" && go get github.com/jackc/pgx/v5@latest github.com/google/go-cmp/cmp@latest >/dev/null 2>&1 && go mod tidy >/dev/null 2>&1 )

echo "=== building + linting a conformant feature against the shipped config ==="
fail=0
( cd "$work" && go build ./... ) && echo "build: PASS" || { echo "build: FAIL"; fail=1; }
( cd "$work" && go vet ./... ) && echo "vet: PASS"   || { echo "vet: FAIL"; fail=1; }
( cd "$work" && go test ./... >/dev/null 2>&1 ) && echo "test: PASS" || { echo "test: FAIL"; fail=1; }

lint_out="$( cd "$work" && golangci-lint run ./... 2>&1 )" && lint_rc=0 || lint_rc=$?
if [[ "$lint_rc" == 0 ]]; then
    echo "lint: PASS (0 issues on conformant code)"
else
    echo "lint: FAIL — the strict config rejected conformant code:"
    echo "$lint_out" | sed 's/^/    /'
    fail=1
fi

echo ""
if [[ "$fail" == 0 ]]; then
    printf "\033[32mALL PASS — the shipped gate accepts harness-conformant code.\033[0m\n"
    exit 0
else
    printf "\033[31mFAILED — fix the config/rules, not the fixture.\033[0m\n"
    exit 1
fi
