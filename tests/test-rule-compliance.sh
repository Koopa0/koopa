#!/usr/bin/env bash
# Rule-compliance probe — ADVISORY, NOT part of verify-spec / CI.
#
# Answers "is generated code actually following our rules?" with evidence,
# not assumption. Runs a few code-generation prompts through headless
# `claude -p` IN this project (so the path-scoped rules + CLAUDE.md load and
# shape output) and greps the output for rule adherence and violations.
#
# What it measures (RELIABLE): does generated Go obey the always-loaded
# governance — pgx not database/sql, errors.AsType not errors.As, table-driven
# tests, no testify, and active push-back when asked to mock the store.
# What it does NOT measure: deep-skill marginal value (see the validity note
# in test-skill-triggering.sh) — a paired with/without-skill delta would, but
# its pruning purpose is moot after the skillOverrides name-only split, and
# this probe already answers the compliance question.
#
# Costs real tokens (each probe is a full `claude -p`). Run deliberately:
#   bash tests/test-rule-compliance.sh
#
# Caveat: this is NOT how the harness is normally driven (real work goes
# scaffold -> reviewers). A raw one-shot bypasses agents, so a miss here is a
# "rules-in-context alone" signal — the agent/reviewer backstop catches more.
set -euo pipefail

command -v claude >/dev/null || { echo "claude CLI required"; exit 1; }

bold()   { printf "\033[1m%s\033[0m\n" "$1"; }
green()  { printf "\033[32m%s\033[0m\n" "$1"; }
red()    { printf "\033[31m%s\033[0m\n" "$1"; }
yellow() { printf "\033[33m%s\033[0m\n" "$1"; }

PASS=0; FAIL=0
ask() { claude -p "$1" 2>/dev/null; }

# want: rubric token that SHOULD appear; avoid: violation that must NOT.
# args: description, output, want-regex (|-sep), avoid-regex (|-sep, "" to skip)
grade() {
    local desc="$1" out="$2" want="$3" avoid="$4" ok=1
    if [[ -n "$want" ]] && ! grep -qiE "$want" <<<"$out"; then ok=0; fi
    if [[ -n "$avoid" ]] && grep -qiE "$avoid" <<<"$out"; then ok=0; fi
    if [[ "$ok" == 1 ]]; then green "  PASS: $desc"; PASS=$((PASS+1));
    else red "  FAIL: $desc"; FAIL=$((FAIL+1)); fi
}

bold "=== Probe 1: store method (pgx stack, ErrNotFound mapping) ==="
o1=$(ask "Show me Go code for a store method that fetches an order by ID using this project's database stack. Just the code.")
grade "uses pgx, not database/sql" "$o1" "pgx" "database/sql|gorm\.|sqlx"
grade "maps not-found to ErrNotFound" "$o1" "ErrNotFound" ""
grade "no errors.As (Go 1.26 wants errors.AsType)" "$o1" "" "errors\.As\("

bold "=== Probe 2: unit test (table-driven, no testify) ==="
o2=$(ask "Write a quick unit test for a ParseStatus(string) function in this project. Just the code.")
grade "table-driven (tests := []struct + t.Run)" "$o2" "t\.Run" "assert\.|require\.|suite\."
grade "no testify import" "$o2" "" "stretchr/testify"

bold "=== Probe 3 (KILLER): pushes back on mocking the store ==="
o3=$(ask "I want to extract an interface for the order Store so I can mock it in my unit tests. Show me how.")
grade "steers to testcontainers / real deps" "$o3" "testcontainer" ""
# Naming mockery/gomock to FORBID them is correct — so check for the
# steer-away signal (hand-written fake / not in the stack), not mere mention.
grade "steers to hand-written fake over a mock framework" "$o3" "hand-written|fake|not in the stack|no.{0,8}mock" ""
grade "invokes discovery/consumer-interface doctrine" "$o3" "consumer|discover|never mock|push back|real" ""

bold ""
bold "=== Results ==="
echo "Pass: $PASS  Fail: $FAIL"
if [[ "$FAIL" -gt 0 ]]; then
    yellow "Failures = generated code drifted from governance in a raw one-shot."
    yellow "Check: did the rule load? (.claude/rule-load.log via InstructionsLoaded)"
    yellow "Real workflow adds the scaffold + reviewer backstop on top of this."
    exit 1
fi
green "Generated code follows governance in a raw one-shot (strongest layer + 3 backstops)."
exit 0
