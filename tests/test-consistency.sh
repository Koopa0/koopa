#!/usr/bin/env bash
# Rule consistency checker: validates cross-references, file existence, and structural integrity.
# Run from project root: bash tests/test-consistency.sh
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

PASS=0
FAIL=0
TOTAL=0

red()   { printf "\033[31m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }
bold()  { printf "\033[1m%s\033[0m\n" "$1"; }

check() {
    local description="$1"
    local condition="$2"  # "pass" or "fail"
    TOTAL=$((TOTAL + 1))
    if [[ "$condition" == "pass" ]]; then
        green "  PASS: $description"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $description"
        FAIL=$((FAIL + 1))
    fi
}

# ============================================================
bold "=== File Structure ==="
# ============================================================

# Required directories
for dir in cmd/app internal migrations .claude/rules .claude/agents .claude/hooks .claude/skills; do
    if [[ -d "$dir" ]]; then
        check "directory exists: $dir" "pass"
    else
        check "directory exists: $dir" "fail"
    fi
done

# Required files
for file in go.mod sqlc.yaml Makefile Dockerfile .gitignore .golangci.yml .dockerignore CLAUDE.md cmd/app/main.go .claude/QUICKSTART.md .claude/agent-memory/README.md; do
    if [[ -f "$file" ]]; then
        check "file exists: $file" "pass"
    else
        check "file exists: $file" "fail"
    fi
done

# Hooks are executable
for hook in .claude/hooks/check-anti-patterns.sh .claude/hooks/format-go.sh; do
    if [[ -x "$hook" ]]; then
        check "hook executable: $hook" "pass"
    else
        check "hook executable: $hook" "fail"
    fi
done

# ============================================================
bold "=== Agent ↔ CLAUDE.md Consistency ==="
# ============================================================

# Every agent file referenced in CLAUDE.md should exist
for agent in comprehend planner scaffold go-reviewer test-writer build-resolver db-reviewer security-reviewer refactor perf-reviewer; do
    if [[ -f ".claude/agents/$agent.md" ]]; then
        check "agent file exists: $agent.md" "pass"
    else
        check "agent file exists: $agent.md" "fail"
    fi
done

# Every agent file should have required frontmatter fields
for agent_file in .claude/agents/*.md; do
    name=$(basename "$agent_file" .md)
    if grep -q "^name:" "$agent_file"; then
        check "agent $name has 'name' frontmatter" "pass"
    else
        check "agent $name has 'name' frontmatter" "fail"
    fi
    if grep -q "^tools:" "$agent_file"; then
        check "agent $name has 'tools' frontmatter" "pass"
    else
        check "agent $name has 'tools' frontmatter" "fail"
    fi
done

# ============================================================
bold "=== Skill ↔ CLAUDE.md Consistency ==="
# ============================================================

for skill in verify checkpoint pgx-patterns sqlc-guide testcontainers postgres-patterns otel-guide http-server migrations genkit-go ristretto nats; do
    if [[ -f ".claude/skills/$skill/SKILL.md" ]]; then
        check "skill exists: $skill" "pass"
    else
        check "skill exists: $skill" "fail"
    fi
done

# ============================================================
bold "=== Shared Skills (.agents/skills/) ==="
# ============================================================

# Portable skills should have symlinks in .agents/skills/
for skill in pgx-patterns sqlc-guide testcontainers postgres-patterns otel-guide http-server migrations genkit-go ristretto nats go-project-init; do
    if [[ -L ".agents/skills/$skill" && -f ".agents/skills/$skill/SKILL.md" ]]; then
        check "shared skill symlink valid: $skill" "pass"
    else
        check "shared skill symlink valid: $skill" "fail"
    fi
done

# Claude-only skills should NOT be in .agents/skills/
for skill in verify checkpoint; do
    if [[ ! -e ".agents/skills/$skill" ]]; then
        check "claude-only skill excluded: $skill" "pass"
    else
        check "claude-only skill excluded: $skill" "fail"
    fi
done

# AGENTS.md should exist
if [[ -f "AGENTS.md" ]]; then
    check "AGENTS.md exists" "pass"
else
    check "AGENTS.md exists" "fail"
fi

# .gemini/settings.json should exist
if [[ -f ".gemini/settings.json" ]]; then
    check ".gemini/settings.json exists" "pass"
else
    check ".gemini/settings.json exists" "fail"
fi

# GEMINI.md should exist
if [[ -f "GEMINI.md" ]]; then
    check "GEMINI.md exists" "pass"
else
    check "GEMINI.md exists" "fail"
fi

# ============================================================
bold "=== Rule Cross-References ==="
# ============================================================

# Find all "see <name>.md" or "(see <name>.md)" references in rule files
while IFS= read -r line; do
    source_file=$(echo "$line" | cut -d: -f1)
    # Extract "see something.md" references (case-insensitive)
    ref_file=$(echo "$line" | sed -n 's/.*[Ss]ee [`"]*\([a-z_-]*\.md\).*/\1/p' || true)
    if [[ -n "$ref_file" ]]; then
        if [[ -f ".claude/rules/$ref_file" ]]; then
            check "cross-ref from $(basename "$source_file"): $ref_file exists" "pass"
        else
            check "cross-ref from $(basename "$source_file"): $ref_file exists" "fail"
        fi
    fi
done < <(grep -rn 'see .*\.md\|See .*\.md' .claude/rules/ 2>/dev/null || true)

# ============================================================
bold "=== settings.json Consistency ==="
# ============================================================

# Hooks referenced in settings.json should exist
if grep -q "check-anti-patterns.sh" .claude/settings.json; then
    check "settings.json references check-anti-patterns.sh" "pass"
else
    check "settings.json references check-anti-patterns.sh" "fail"
fi

if grep -q "format-go.sh" .claude/settings.json; then
    check "settings.json references format-go.sh" "pass"
else
    check "settings.json references format-go.sh" "fail"
fi

# PreToolUse matcher should be Write|Edit
if grep -A5 "PreToolUse" .claude/settings.json | grep -q 'Write|Edit'; then
    check "PreToolUse matcher is Write|Edit" "pass"
else
    check "PreToolUse matcher is Write|Edit" "fail"
fi

# PostToolUse matcher should be Write|Edit
if grep -A5 "PostToolUse" .claude/settings.json | grep -q 'Write|Edit'; then
    check "PostToolUse matcher is Write|Edit" "pass"
else
    check "PostToolUse matcher is Write|Edit" "fail"
fi

# ============================================================
bold "=== sqlc.yaml Consistency ==="
# ============================================================

# Schema directory exists
schema_dir=$(grep "schema:" sqlc.yaml | awk '{print $2}' | tr -d '"')
if [[ -d "$schema_dir" ]]; then
    check "sqlc schema dir exists: $schema_dir" "pass"
else
    check "sqlc schema dir exists: $schema_dir" "fail"
fi

# Queries path: must be a RECURSIVE glob (package-by-feature puts query.sql in
# internal/<feature>/, so a literal "internal/" does not recurse — see the
# 2026-06 sqlc-path fix) and its base directory must exist.
queries_pat=$(grep "queries:" sqlc.yaml | awk '{print $2}' | tr -d '"')
if [[ "$queries_pat" == *'**'* ]]; then
    check "sqlc queries path is a recursive glob: $queries_pat" "pass"
else
    check "sqlc queries path is a recursive glob: $queries_pat (literal dir does not recurse into internal/<feature>/)" "fail"
fi
queries_base="${queries_pat%%\**}"   # strip from first '*' → e.g. internal/
queries_base="${queries_base%/}"      # trim trailing slash
if [[ -d "$queries_base" ]]; then
    check "sqlc queries base dir exists: $queries_base" "pass"
else
    check "sqlc queries base dir exists: $queries_base" "fail"
fi

# Engine is postgresql
if grep -q 'engine: "postgresql"' sqlc.yaml; then
    check "sqlc engine is postgresql" "pass"
else
    check "sqlc engine is postgresql" "fail"
fi

# sql_package is pgx/v5
if grep -q 'sql_package: "pgx/v5"' sqlc.yaml; then
    check "sqlc sql_package is pgx/v5" "pass"
else
    check "sqlc sql_package is pgx/v5" "fail"
fi

# ============================================================
bold "=== Makefile Targets ==="
# ============================================================

# All targets documented in CLAUDE.md should exist in Makefile
for target in build run test test-integration test-all lint fmt vet sqlc bench fuzz docker-build clean coverage sqlc-check; do
    if grep -q "^${target}:" Makefile; then
        check "Makefile has target: $target" "pass"
    else
        check "Makefile has target: $target" "fail"
    fi
done

# ============================================================
bold "=== Go Build Verification ==="
# ============================================================

if go build ./... 2>/dev/null; then
    check "go build ./..." "pass"
else
    check "go build ./..." "fail"
fi

if go vet ./... 2>/dev/null; then
    check "go vet ./..." "pass"
else
    check "go vet ./..." "fail"
fi

# ============================================================
bold "=== Rule Content Checks (SMOKE-ONLY) ==="
# SMOKE-ONLY: these `grep -q "keyword"` checks prove a string EXISTS in a rule
# file — NOT that the rule is correct, effective, or followed. They catch a rule
# file being deleted, renamed, or gutted; they do NOT validate behavior. A typo'd
# rule still passes. For real behavioral validation see tests/test-hooks.sh and
# tests/behavioral/.
# ============================================================

# database.md should mention db.DBTX
if grep -q "db.DBTX" .claude/rules/database.md; then
    check "database.md documents db.DBTX pattern" "pass"
else
    check "database.md documents db.DBTX pattern" "fail"
fi

# database.md should mention WithTx
if grep -q "WithTx" .claude/rules/database.md; then
    check "database.md documents WithTx pattern" "pass"
else
    check "database.md documents WithTx pattern" "fail"
fi

# database.md should reference skills (constraint-only structure)
if grep -q "/pgx-patterns" .claude/rules/database.md; then
    check "database.md references /pgx-patterns skill" "pass"
else
    check "database.md references /pgx-patterns skill" "fail"
fi

# json-api.md should have MUST/NEVER constraints (constraint-only structure)
if grep -q "MUST.*json.NewDecoder\|NEVER.*json.Unmarshal" .claude/rules/json-api.md; then
    check "json-api.md has decoder constraints" "pass"
else
    check "json-api.md has decoder constraints" "fail"
fi

# http-server.md should mention middleware ordering
if grep -q "Recovery.*RequestID" .claude/rules/http-server.md; then
    check "http-server.md documents middleware ordering" "pass"
else
    check "http-server.md documents middleware ordering" "fail"
fi

# http-server.md should mention healthz
if grep -q "healthz" .claude/rules/http-server.md; then
    check "http-server.md documents /healthz" "pass"
else
    check "http-server.md documents /healthz" "fail"
fi

# http-server.md should reference skills (constraint-only structure)
if grep -q "/http-server.*skill" .claude/rules/http-server.md; then
    check "http-server.md references skill for implementation" "pass"
else
    check "http-server.md references skill for implementation" "fail"
fi

# security.md should reference security-reviewer agent
if grep -q "security-reviewer" .claude/rules/security.md; then
    check "security.md references security-reviewer agent" "pass"
else
    check "security.md references security-reviewer agent" "fail"
fi

# go-philosophy.md should reference otel-guide skill (observability merged in)
if grep -q "otel-guide" .claude/rules/go-philosophy.md; then
    check "go-philosophy.md references /otel-guide skill" "pass"
else
    check "go-philosophy.md references /otel-guide skill" "fail"
fi

# testing.md should mention httptest
if grep -q "httptest" .claude/rules/testing.md; then
    check "testing.md documents httptest pattern" "pass"
else
    check "testing.md documents httptest pattern" "fail"
fi

# testing.md should mention SetPathValue
if grep -q "SetPathValue" .claude/rules/testing.md; then
    check "testing.md documents SetPathValue" "pass"
else
    check "testing.md documents SetPathValue" "fail"
fi

# concurrency.md should mention context values
if grep -q "requestIDKey" .claude/rules/concurrency.md; then
    check "concurrency.md documents context key pattern" "pass"
else
    check "concurrency.md documents context key pattern" "fail"
fi

# development-lifecycle.md should have tier system
if grep -q "Tier Selection" .claude/rules/development-lifecycle.md; then
    check "development-lifecycle.md has tier system" "pass"
else
    check "development-lifecycle.md has tier system" "fail"
fi

# schema-design.md should mention COMMENT ON COLUMN
if grep -q "COMMENT ON COLUMN" .claude/rules/schema-design.md; then
    check "schema-design.md documents column comments" "pass"
else
    check "schema-design.md documents column comments" "fail"
fi

# genkit.md should mention DefineFlow
if grep -q "DefineFlow" .claude/rules/genkit.md; then
    check "genkit.md documents flow constraints" "pass"
else
    check "genkit.md documents flow constraints" "fail"
fi

# concurrency.md should mention decision framework
if grep -q "Concurrency Decision Framework" .claude/rules/concurrency.md; then
    check "concurrency.md has decision framework" "pass"
else
    check "concurrency.md has decision framework" "fail"
fi

# scaffold agent should reference db.DBTX
if grep -q "db.DBTX" .claude/agents/scaffold.md; then
    check "scaffold.md uses db.DBTX pattern" "pass"
else
    check "scaffold.md uses db.DBTX pattern" "fail"
fi

# go-reviewer should mention skipping internal/db/
if grep -q "internal/db" .claude/agents/go-reviewer.md; then
    check "go-reviewer.md skips internal/db/" "pass"
else
    check "go-reviewer.md skips internal/db/" "fail"
fi

# main.go should have config struct
if grep -q "type config struct" cmd/app/main.go; then
    check "main.go has config struct" "pass"
else
    check "main.go has config struct" "fail"
fi

# main.go should have getEnv (not envOr)
if grep -q "func getEnv" cmd/app/main.go; then
    check "main.go uses getEnv (matches go-philosophy.md)" "pass"
else
    check "main.go uses getEnv (matches go-philosophy.md)" "fail"
fi

# main.go should have /healthz (not /health)
if grep -q "healthz" cmd/app/main.go; then
    check "main.go uses /healthz endpoint" "pass"
else
    check "main.go uses /healthz endpoint" "fail"
fi

# ============================================================
bold ""
bold "=== Results ==="
# ============================================================

echo "Total: $TOTAL  Pass: $PASS  Fail: $FAIL"

if [[ "$FAIL" -gt 0 ]]; then
    red "FAILED — review the failures above"
    exit 1
else
    green "ALL PASSED"
    exit 0
fi
