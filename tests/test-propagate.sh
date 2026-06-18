#!/usr/bin/env bash
# Safety tests for bin/propagate-spec.sh — proves it never clobbers a consumer's
# divergent or waiver-carrying files and only auto-adds MISSING ones.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL="$PROJECT_ROOT/scripts/propagate-spec.sh"
PASS=0; FAIL=0; TOTAL=0
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
green() { printf "\033[32m%s\033[0m\n" "$1"; }
ok()    { TOTAL=$((TOTAL+1)); if eval "$2"; then green "  PASS: $1"; PASS=$((PASS+1)); else red "  FAIL: $1"; FAIL=$((FAIL+1)); fi; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
C="$work/consumer"
mkdir -p "$C/.claude/rules" "$C/.claude/hooks"
( cd "$C" && git init -q && git config user.email t@t && git config user.name t )

# in-sync: identical to source
cp "$PROJECT_ROOT/.claude/hooks/parse-hook-input.sh" "$C/.claude/hooks/parse-hook-input.sh"
# DIFFERS (no waiver token)
printf '# Testing\nCONSUMER_STUB_MARKER old content\n' > "$C/.claude/rules/testing.md"
# WAIVER-protected (carries SA1019, differs from source)
printf '# Go Version\nCONSUMER_WAIVER_MARKER\nlinters: SA1019 disabled locally\n' > "$C/.claude/rules/go-version.md"
( cd "$C" && git add -A && git commit -q -m seed )

# --- dry-run writes nothing ---
out="$("$TOOL" "$C" 2>&1)"
ok "dry-run reports GOSPEC-AHEAD files"        '[[ "$out" == *GOSPEC-AHEAD* ]]'
ok "dry-run classifies the DIFFERS file"        'echo "$out" | grep -q "testing.md"'
ok "dry-run flags the WAIVER file as protected" '[[ "$out" == *PROTECTED* ]] && echo "$out" | grep -q "go-version.md"'
ok "dry-run does NOT add check-secrets.sh"      '[[ ! -e "$C/.claude/hooks/check-secrets.sh" ]]'
ok "dry-run leaves DIFFERS file untouched"      'grep -q CONSUMER_STUB_MARKER "$C/.claude/rules/testing.md"'

# --- apply adds MISSING only, never overwrites ---
"$TOOL" --apply "$C" >/dev/null 2>&1
ok "apply ADDED the missing check-secrets.sh"   '[[ -e "$C/.claude/hooks/check-secrets.sh" ]]'
ok "apply did NOT overwrite the DIFFERS file"   'grep -q CONSUMER_STUB_MARKER "$C/.claude/rules/testing.md"'
ok "apply did NOT overwrite the WAIVER file"    'grep -q CONSUMER_WAIVER_MARKER "$C/.claude/rules/go-version.md"'
ok "apply made a revertable commit"             '[[ "$(cd "$C" && git log --oneline | wc -l | tr -d " ")" -ge 2 ]]'
ok "apply committed under the checkpoint type"  '(cd "$C" && git log -1 --pretty=%s | grep -q "^checkpoint: spec-sync")'

# --- path-scoped commit: unrelated unstaged WIP is never committed ---
# Fresh consumer where a MISSING file exists alongside an unstaged dirty file.
C2="$work/consumer2"
mkdir -p "$C2/.claude/hooks"
( cd "$C2" && git init -q && git config user.email t@t && git config user.name t )
echo "tracked" > "$C2/app.txt"
( cd "$C2" && git add -A && git commit -q -m seed )
echo "WIP" >> "$C2/app.txt"                       # unstaged dirty, unrelated to the sync
"$TOOL" --apply "$C2" >/dev/null 2>&1
ok "apply proceeds despite unrelated dirty WIP"  '[[ -e "$C2/.claude/hooks/check-secrets.sh" ]]'
ok "apply did NOT commit the unrelated WIP"      '(cd "$C2" && ! git diff --quiet -- app.txt)'
ok "apply commit is path-scoped to spec files"   '(cd "$C2" && ! git show --stat HEAD | grep -q "app.txt")'

# --- gitignored .claude: copy untracked, no fake commit, rollback list ---
C3="$work/consumer3"
mkdir -p "$C3/.claude/hooks"
( cd "$C3" && git init -q && git config user.email t@t && git config user.name t )
printf '.claude/\ntests/\n' > "$C3/.gitignore"
( cd "$C3" && git add .gitignore && git commit -q -m seed )
head3="$(cd "$C3" && git rev-parse HEAD)"
out3="$("$TOOL" --apply "$C3" 2>&1)"
ok "gitignored .claude: files still copied"      '[[ -e "$C3/.claude/hooks/check-secrets.sh" ]]'
ok "gitignored .claude: makes NO commit"         '[[ "$(cd "$C3" && git rev-parse HEAD)" == "$head3" ]]'
ok "gitignored .claude: writes a rollback list"  '[[ -s "$C3/.claude/.spec-sync-rollback.txt" ]]'
ok "gitignored .claude: reports UNTRACKED"        '[[ "$out3" == *UNTRACKED* ]]'

echo ""
echo "Total: $TOTAL  Pass: $PASS  Fail: $FAIL"
[[ "$FAIL" -eq 0 ]] && { green "ALL PASSED"; exit 0; } || { red "FAILED"; exit 1; }
