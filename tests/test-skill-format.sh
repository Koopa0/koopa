#!/usr/bin/env bash
# Mechanical format/spec checks for skills and agents.
# Run from project root: bash tests/test-skill-format.sh
# Guards against the drift classes found in the 2026-06 audit:
# phantom citations, router desync, ghost table entries, frontmatter rot.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SKILLS="$PROJECT_ROOT/.claude/skills"
AGENTS="$PROJECT_ROOT/.claude/agents"
RULES="$PROJECT_ROOT/.claude/rules"
ROUTER="$SKILLS/using-go-spec/SKILL.md"
PASS=0
FAIL=0
WARN=0
TOTAL=0

red()    { printf "\033[31m%s\033[0m\n" "$1"; }
green()  { printf "\033[32m%s\033[0m\n" "$1"; }
yellow() { printf "\033[33m%s\033[0m\n" "$1"; }
bold()   { printf "\033[1m%s\033[0m\n" "$1"; }

check() { # description, condition-exit-code
    local description="$1" ok="$2"
    TOTAL=$((TOTAL + 1))
    if [[ "$ok" == "0" ]]; then
        green "  PASS: $description"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $description"
        FAIL=$((FAIL + 1))
    fi
}

# Meta/workflow skills intentionally absent from the task-routing tables
# (the router routes coding tasks; these are session/process entry points).
ROUTER_EXEMPT="using-go-spec verify checkpoint lifecycle-phases claude-code-advanced"

# Built-in slash commands — legitimate `/name` references that are not skills.
BUILTIN_CMDS="loop batch btw diff context branch effort security-review stats insights voice remote-control simplify goal code-review fast workflows clear help config remember"

router_exempt() { [[ " $ROUTER_EXEMPT " == *" $1 "* ]]; }
builtin_cmd()   { [[ " $BUILTIN_CMDS " == *" $1 "* ]]; }

# ============================================================
bold "=== Skill frontmatter ==="
# ============================================================

for dir in "$SKILLS"/*/; do
    skill=$(basename "$dir")
    s="$dir/SKILL.md"
    if [[ ! -f "$s" ]]; then
        check "$skill has SKILL.md" 1
        continue
    fi
    ok=0; head -1 "$s" | grep -q '^---$' || ok=1
    check "$skill: frontmatter present" $ok
    fm_name=$(awk '/^---$/{c++; next} c==1 && /^name:/{print $2; exit}' "$s")
    ok=0; [[ "$fm_name" == "$skill" ]] || ok=1
    check "$skill: name matches directory" $ok
    ok=0; awk '/^---$/{c++; next} c==1' "$s" | grep -q '^description:' || ok=1
    check "$skill: description present" $ok
done

# ============================================================
bold "=== Router sync (using-go-spec) ==="
# ============================================================

for dir in "$SKILLS"/*/; do
    skill=$(basename "$dir")
    router_exempt "$skill" && continue
    ok=0; grep -q "/$skill\`" "$ROUTER" || ok=1
    check "router lists /$skill" $ok
done

# ============================================================
bold "=== Citation integrity ==="
# ============================================================

# Rule citations in skills and agents must resolve to real files
dead_rules=0
while read -r f; do
    if [[ ! -f "$RULES/$f" ]]; then
        red "  DEAD RULE REF: $f"
        dead_rules=1
    fi
done < <(grep -rhoE '(rules|\.claude/rules)/[a-z-]+\.md' "$SKILLS"/*/SKILL.md "$AGENTS"/*.md 2>/dev/null | sed 's|.*/||' | sort -u)
check "no dead rule citations in skills/agents" $dead_rules

# `/name` skill references (only the explicit "`/name` skill" linkage pattern)
dead_skills=0
while read -r s; do
    if [[ ! -d "$SKILLS/$s" ]] && ! builtin_cmd "$s"; then
        red "  DEAD SKILL REF: /$s"
        dead_skills=1
    fi
done < <(grep -rhoE '`/[a-z][a-z0-9-]+` skill' "$SKILLS"/*/SKILL.md "$AGENTS"/*.md "$RULES"/*.md 2>/dev/null | sed -E 's/`\/([a-z0-9-]+)` skill/\1/' | sort -u)
check "no dead /skill citations" $dead_skills

# ============================================================
bold "=== AGENTS.md table sync ==="
# ============================================================

ghost=0
while read -r s; do
    if [[ ! -d "$SKILLS/$s" ]]; then
        red "  GHOST ENTRY in AGENTS.md: $s"
        ghost=1
    fi
done < <(awk '/## Shared Skills/,/## Cross-Agent Setup/' "$PROJECT_ROOT/AGENTS.md" | grep -oE '^\| `[a-z0-9-]+`' | tr -d '|` ' | sort -u)
check "AGENTS.md skill table has no ghost entries" $ghost

# ============================================================
bold "=== Agent frontmatter ==="
# ============================================================

for a in "$AGENTS"/*.md; do
    agentname=$(basename "$a" .md)
    ok=0; head -1 "$a" | grep -q '^---$' || ok=1
    check "agent $agentname: frontmatter present" $ok
    ok=0; awk '/^---$/{c++; next} c==1' "$a" | grep -q '^description:' || ok=1
    check "agent $agentname: description present" $ok
    ok=0; awk '/^---$/{c++; next} c==1' "$a" | grep -q '^model:' || ok=1
    check "agent $agentname: model declared" $ok
done

# CLAUDE.md agent table ↔ agents dir (CLAUDE.md is the source of truth)
tbl_missing=0
while read -r a; do
    if [[ ! -f "$AGENTS/$a.md" ]]; then
        red "  CLAUDE.md lists nonexistent agent: $a"
        tbl_missing=1
    fi
done < <(awk '/## Available Agents/,/## Available Skills/' "$PROJECT_ROOT/CLAUDE.md" | grep -oE '^\| `[a-z0-9-]+`' | tr -d '|` ' | sort -u)
check "CLAUDE.md agent table entries all exist" $tbl_missing

dir_missing=0
for a in "$AGENTS"/*.md; do
    agentname=$(basename "$a" .md)
    if ! grep -q "\`$agentname\`" "$PROJECT_ROOT/CLAUDE.md"; then
        red "  agent not in CLAUDE.md table: $agentname"
        dir_missing=1
    fi
done
check "all agents appear in CLAUDE.md" $dir_missing

# ============================================================
bold "=== Listing budget (description + when_to_use) ==="
# ============================================================
# Official semantics (code.claude.com/docs/en/skills.md): description +
# when_to_use are shown combined in the skill listing, truncated at 1,536
# chars; the listing shares ~1% of context, least-used skills drop first.

budget_fail=0
while IFS=$'\t' read -r skill blen has_wtu; do
    if [[ "$blen" == "YAML_ERROR" ]]; then
        red "  YAML ERROR in frontmatter: $skill"
        budget_fail=1
        continue
    fi
    if [[ "$has_wtu" != "True" ]]; then
        red "  NO when_to_use: $skill"
        budget_fail=1
    fi
    if [[ "$blen" -gt 1536 ]]; then
        red "  OVER LISTING BUDGET ($blen > 1536): $skill"
        budget_fail=1
    fi
done < <(python3 - "$SKILLS" <<'PYEOF'
import sys, os, yaml
root = sys.argv[1]
for d in sorted(os.listdir(root)):
    p = os.path.join(root, d, 'SKILL.md')
    if not os.path.isfile(p):
        continue
    text = open(p).read()
    if not text.startswith('---'):
        continue
    fm = text.split('---', 2)[1]
    try:
        meta = yaml.safe_load(fm) or {}
    except yaml.YAMLError:
        print(f"{d}\tYAML_ERROR\tFalse")
        continue
    desc = str(meta.get('description', '') or '')
    wtu = meta.get('when_to_use', None)
    combined = len(desc) + len(str(wtu or ''))
    print(f"{d}\t{combined}\t{wtu is not None}")
PYEOF
)
check "all skills: when_to_use present, combined listing <= 1536 chars" $budget_fail

# Aggregate listing budget (ADVISORY): the per-turn skill listing shares ~1%
# of the model's context. skillOverrides name-only/off/user-invocable-only
# collapse a skill to its name, freeing budget (full body still loads on
# invoke + via agent skills: preload). Report on-skill aggregate vs the
# 200k-context (consumer) and 1M-context (author) 1% budgets.
agg=$(python3 - "$SKILLS" "$PROJECT_ROOT/.claude/settings.json" <<'PYEOF'
import sys, os, json, yaml
root, settings = sys.argv[1], sys.argv[2]
ov = {}
try:
    ov = (json.load(open(settings)) or {}).get('skillOverrides', {})
except Exception:
    pass
on_total = name_only_total = 0
on_n = collapsed_n = 0
for d in sorted(os.listdir(root)):
    p = os.path.join(root, d, 'SKILL.md')
    if not os.path.isfile(p):
        continue
    t = open(p).read()
    if not t.startswith('---'):
        continue
    try:
        m = yaml.safe_load(t.split('---', 2)[1]) or {}
    except yaml.YAMLError:
        continue
    listing = len(str(m.get('description', '') or '')) + len(str(m.get('when_to_use', '') or ''))
    state = ov.get(d, 'on')
    if state == 'on':
        on_total += listing; on_n += 1
    else:
        name_only_total += len(d); collapsed_n += 1
print(f"{on_total}\t{on_n}\t{collapsed_n}\t{name_only_total}")
PYEOF
)
on_total=$(echo "$agg" | cut -f1); on_n=$(echo "$agg" | cut -f2)
collapsed_n=$(echo "$agg" | cut -f3)
on_tok=$(( on_total / 4 ))
yellow "  ADVISORY: aggregate listing ~${on_total} chars (~${on_tok} tok) across ${on_n} 'on' skills; ${collapsed_n} collapsed via skillOverrides."
yellow "  200k-ctx 1% budget = ~2000 tok; 1M-ctx = ~10000 tok. Over budget => runtime truncates least-used (see /doctor)."

# ============================================================
bold "=== Progressive disclosure (SKILL.md line budget) ==="
# ============================================================
# Official guidance: SKILL.md under 500 lines, deep material in references/.
# Auto-compaction re-attaches only the first ~5,000 tokens of a skill, so
# content past that silently vanishes in long sessions. Hard fail: move the
# overflow into references/<topic>.md and add a navigation pointer.

for dir in "$SKILLS"/*/; do
    skill=$(basename "$dir")
    n=$(wc -l < "$dir/SKILL.md" 2>/dev/null || echo 0)
    ok=0; [[ "$n" -gt 500 ]] && ok=1
    check "$skill: SKILL.md <= 500 lines (is $n)" $ok
done

# ============================================================
bold ""
bold "=== Results ==="
# ============================================================

echo "Total: $TOTAL  Pass: $PASS  Fail: $FAIL  Advisory: $WARN"

if [[ "$FAIL" -gt 0 ]]; then
    red "FAILED"
    exit 1
else
    green "ALL PASSED"
    exit 0
fi
