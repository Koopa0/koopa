#!/usr/bin/env bash
# sync-agents.sh
#
# 從 .claude/rules/ 和 .claude/skills/（source of truth）同步到所有 AI agent 平台：
#
#   Rules 同步：
#     1. .claude/skills/angular-rules/references/  （npx skills add 用）
#     2. .gemini/rules/                            （Gemini CLI 規則）
#     3. .cursor/rules/                            （Cursor AI 規則，.mdc 格式）
#
#   Skills 同步：
#     4. .agents/skills/                           （Codex 原生 skills）
#     5. .gemini/skills/                           （Gemini CLI 原生 skills）
#
#   Entry 入口檔案：
#     6. GEMINI.md                                 （Gemini CLI 入口，內嵌 rules，skills 指向原生目錄）
#     7. AGENTS.md                                 （OpenAI Codex 入口，內嵌 rules，skills 指向原生目錄）
#
# 用法：
#   ./scripts/sync-agents.sh
#
# Source of truth:
#   - .claude/rules/*.md       （13 個規範檔案）
#   - .claude/skills/*/SKILL.md（22 個技能檔案）
#
# 修改 rules 或 skills 後執行此腳本即可同步所有平台。

set -euo pipefail

RULES_DIR=".claude/rules"
SKILLS_DIR=".claude/skills"
REFS_DIR=".claude/skills/angular-rules/references"
GEMINI_RULES_DIR=".gemini/rules"
GEMINI_SKILLS_DIR=".gemini/skills"
AGENTS_SKILLS_DIR=".agents/skills"
CURSOR_RULES_DIR=".cursor/rules"
TEMPLATES_DIR="scripts/templates"

# ── Rules 定義 ──

# 定義 rules 的合併順序（按主題重要性排序）
RULE_ORDER=(
  "angular-conventions.md"
  "coding-style.md"
  "ui-components.md"
  "tailwind-patterns.md"
  "state-management.md"
  "http-patterns.md"
  "routing.md"
  "testing.md"
  "error-handling.md"
  "performance.md"
  "security.md"
  "git-workflow.md"
  "development-lifecycle.md"
  "agents.md"
)

# Rules 顯示名稱對應
declare -A RULE_TITLES
RULE_TITLES=(
  ["angular-conventions.md"]="Angular 21 Conventions"
  ["coding-style.md"]="Coding Style"
  ["ui-components.md"]="UI Components Strategy"
  ["tailwind-patterns.md"]="Tailwind CSS Patterns"
  ["state-management.md"]="State Management"
  ["http-patterns.md"]="HTTP Patterns"
  ["routing.md"]="Routing"
  ["testing.md"]="Testing"
  ["error-handling.md"]="Error Handling"
  ["performance.md"]="Performance"
  ["security.md"]="Security"
  ["git-workflow.md"]="Git Workflow"
  ["development-lifecycle.md"]="Development Lifecycle"
  ["agents.md"]="Agent Coordination"
)

# Cursor .mdc frontmatter 定義
declare -A CURSOR_DESCRIPTIONS
CURSOR_DESCRIPTIONS=(
  ["angular-conventions.md"]="Angular 21 mandatory patterns — standalone components, signals, inject(), control flow, OnPush"
  ["coding-style.md"]="TypeScript and Angular coding style — naming, formatting, imports, type system rules"
  ["ui-components.md"]="UI component strategy — three-tier architecture, Catalyst UI Kit, CDK, PrimeNG decision tree"
  ["tailwind-patterns.md"]="Tailwind CSS v4 patterns — v3-to-v4 migration, dark mode, color system, spacing"
  ["state-management.md"]="State management — signals, NgRx Signals Store, computed, linkedSignal patterns"
  ["http-patterns.md"]="HTTP patterns — functional interceptors, CRUD services, error handling, caching"
  ["routing.md"]="Routing — lazy loading, functional guards, resolvers, SSR render modes"
  ["testing.md"]="Testing — Vitest TDD workflow, signal testing, component testing, coverage rules"
  ["error-handling.md"]="Error handling — global ErrorHandler, HTTP interceptor errors, ErrorBoundary, form validation"
  ["performance.md"]="Performance — OnPush, lazy loading, @defer, virtual scrolling, bundle budgets, Web Vitals"
  ["security.md"]="Security — XSS prevention, token storage, CSRF, CSP, input validation, OWASP top 10"
  ["git-workflow.md"]="Git workflow — Conventional Commits, PR process, pre-commit hooks"
  ["development-lifecycle.md"]="Development lifecycle — tier system, phase gates, verification chain, plan change protocol"
  ["agents.md"]="Agent coordination — task delegation, model selection, execution flow"
)

declare -A CURSOR_GLOBS
CURSOR_GLOBS=(
  ["angular-conventions.md"]=""
  ["coding-style.md"]=""
  ["ui-components.md"]="src/app/shared/components/**"
  ["tailwind-patterns.md"]="**/*.html,**/*.scss,**/*.css"
  ["state-management.md"]="**/*.store.ts,**/*.component.ts"
  ["http-patterns.md"]="**/*.interceptor.ts,**/*.service.ts"
  ["routing.md"]="**/*.routes.ts,**/*.guard.ts"
  ["testing.md"]="**/*.spec.ts"
  ["error-handling.md"]="**/*.interceptor.ts,**/*.component.ts"
  ["performance.md"]=""
  ["security.md"]=""
  ["git-workflow.md"]=""
  ["development-lifecycle.md"]=""
  ["agents.md"]=""
)

declare -A CURSOR_ALWAYS_APPLY
CURSOR_ALWAYS_APPLY=(
  ["angular-conventions.md"]="true"
  ["coding-style.md"]="true"
  ["ui-components.md"]="false"
  ["tailwind-patterns.md"]="false"
  ["state-management.md"]="false"
  ["http-patterns.md"]="false"
  ["routing.md"]="false"
  ["testing.md"]="false"
  ["error-handling.md"]="false"
  ["performance.md"]="false"
  ["security.md"]="false"
  ["git-workflow.md"]="true"
  ["development-lifecycle.md"]="true"
  ["agents.md"]="false"
)

# ── Skills 定義 ──

# 定義 skills 的合併順序（核心 → 元件 → 功能 → 工具）
SKILL_ORDER=(
  "angular-component"
  "angular-signals"
  "angular-forms"
  "angular-routing"
  "angular-http"
  "angular-service"
  "angular-feature"
  "angular-cdk"
  "angular-ssr"
  "angular-refactor"
  "angular-testing"
  "angular-e2e"
  "component-catalog"
  "page-layout"
  "tailwind-styling"
  "dark-mode"
  "accessibility"
  "performance"
  "security"
  "i18n"
  "ai-compliance-test"
  "go-compliance-test"
  "code-review"
  "angular-verify"
  "skills-map"
  "angular-rules"
)

# Skills 顯示名稱對應
declare -A SKILL_TITLES
SKILL_TITLES=(
  ["angular-component"]="Angular Component Creation"
  ["angular-signals"]="Angular Signal Primitives"
  ["angular-forms"]="Angular Reactive Forms"
  ["angular-routing"]="Angular Routing"
  ["angular-http"]="Angular HTTP & Interceptors"
  ["angular-service"]="Angular Service Creation"
  ["angular-feature"]="Angular Feature Module"
  ["angular-cdk"]="Angular CDK Patterns"
  ["angular-ssr"]="Angular SSR/SSG"
  ["angular-refactor"]="Angular Migration/Refactor"
  ["angular-testing"]="Vitest Testing"
  ["angular-e2e"]="Playwright E2E Testing"
  ["component-catalog"]="Component Catalog (35+ Components)"
  ["page-layout"]="Page Layout Guide"
  ["tailwind-styling"]="Tailwind CSS v4 Styling"
  ["dark-mode"]="Dark/Light Mode"
  ["accessibility"]="WCAG Accessibility"
  ["performance"]="Performance Optimization"
  ["security"]="Security Patterns"
  ["i18n"]="Internationalization"
  ["ai-compliance-test"]="AI Compliance Test"
  ["go-compliance-test"]="Go AI Compliance Test"
  ["code-review"]="Cross-Stack Code Review"
  ["angular-verify"]="Angular Verification Chain"
  ["skills-map"]="Skills Dependency Map"
  ["angular-rules"]="Rules Index"
)

echo "=== Syncing AI Agent Rules & Skills ==="
echo "Source: $RULES_DIR/ + $SKILLS_DIR/"
echo ""

# ── Step 1: Sync rules to angular-rules/references/ ──
echo "1. angular-rules/references/"
mkdir -p "$REFS_DIR"
cp "$RULES_DIR"/*.md "$REFS_DIR/"
echo "   ✅ Copied $(ls "$REFS_DIR"/*.md | wc -l | tr -d ' ') rule files"

# ── Step 2: Sync rules to .gemini/rules/ ──
echo "2. .gemini/rules/"
mkdir -p "$GEMINI_RULES_DIR"
cp "$RULES_DIR"/*.md "$GEMINI_RULES_DIR/"
echo "   ✅ Copied $(ls "$GEMINI_RULES_DIR"/*.md | wc -l | tr -d ' ') rule files"

# ── Step 3: Sync skills to .gemini/skills/ ──
echo "3. .gemini/skills/"
mkdir -p "$GEMINI_SKILLS_DIR"
skill_sync_count=0
for skill in "${SKILL_ORDER[@]}"; do
  skill_file="$SKILLS_DIR/$skill/SKILL.md"
  if [ -f "$skill_file" ]; then
    mkdir -p "$GEMINI_SKILLS_DIR/$skill"
    cp "$skill_file" "$GEMINI_SKILLS_DIR/$skill/SKILL.md"
    skill_sync_count=$((skill_sync_count + 1))
  else
    echo "   ⚠️  Warning: $skill_file not found" >&2
  fi
done
echo "   ✅ Copied $skill_sync_count skill files"

# ── Step 4: Sync skills to .agents/skills/ ──
echo "4. .agents/skills/"
mkdir -p "$AGENTS_SKILLS_DIR"
agents_skill_count=0
for skill in "${SKILL_ORDER[@]}"; do
  skill_file="$SKILLS_DIR/$skill/SKILL.md"
  if [ -f "$skill_file" ]; then
    mkdir -p "$AGENTS_SKILLS_DIR/$skill"
    cp "$skill_file" "$AGENTS_SKILLS_DIR/$skill/SKILL.md"
    agents_skill_count=$((agents_skill_count + 1))
  else
    echo "   ⚠️  Warning: $skill_file not found" >&2
  fi
done
echo "   ✅ Copied $agents_skill_count skill files"

# ── Step 5: Generate .cursor/rules/*.mdc ──
echo "5. .cursor/rules/"
mkdir -p "$CURSOR_RULES_DIR"
cursor_count=0
for rule in "${RULE_ORDER[@]}"; do
  rule_file="$RULES_DIR/$rule"
  if [ -f "$rule_file" ]; then
    mdc_file="$CURSOR_RULES_DIR/${rule%.md}.mdc"
    desc="${CURSOR_DESCRIPTIONS[$rule]:-}"
    globs="${CURSOR_GLOBS[$rule]:-}"
    always="${CURSOR_ALWAYS_APPLY[$rule]:-false}"

    {
      echo "---"
      echo "description: \"$desc\""
      if [ -n "$globs" ]; then
        echo "globs: \"$globs\""
      fi
      echo "alwaysApply: $always"
      echo "---"
      echo ""
      cat "$rule_file"
    } > "$mdc_file"
    cursor_count=$((cursor_count + 1))
  else
    echo "   ⚠️  Warning: $rule_file not found" >&2
  fi
done
echo "   ✅ Generated $cursor_count .mdc files"

# ── Step 6: Generate GEMINI.md ──
echo "6. GEMINI.md"
{
  cat "$TEMPLATES_DIR/gemini-header.md"

  # 嵌入 Rules
  for rule in "${RULE_ORDER[@]}"; do
    rule_file="$RULES_DIR/$rule"
    if [ -f "$rule_file" ]; then
      title="${RULE_TITLES[$rule]:-$rule}"
      echo ""
      echo "---"
      echo ""
      echo "<!-- Source: .claude/rules/$rule -->"
      echo "## Rule: $title"
      echo ""
      cat "$rule_file"
    else
      echo "⚠️  Warning: $rule_file not found" >&2
    fi
  done

  # Skills 指引（不再內嵌，改為指向原生目錄）
  echo ""
  echo "---"
  echo ""
  echo "# Skills Reference"
  echo ""
  echo "Skills are available as native SKILL.md files in \`.gemini/skills/\`."
  echo "Gemini CLI will load them automatically based on task context."
  echo ""
  echo "## Available Skills (${#SKILL_ORDER[@]})"
  echo ""
  echo "| Skill | Description |"
  echo "|-------|-------------|"
  for skill in "${SKILL_ORDER[@]}"; do
    title="${SKILL_TITLES[$skill]:-$skill}"
    echo "| \`$skill\` | $title |"
  done
  echo ""
  echo "To use a skill, Gemini CLI reads \`.gemini/skills/{name}/SKILL.md\` on demand."
} > GEMINI.md
gemini_lines=$(wc -l < GEMINI.md | tr -d ' ')
echo "   ✅ Generated ($gemini_lines lines, ${#RULE_ORDER[@]} rules inline + ${#SKILL_ORDER[@]} skills native)"

# ── Step 7: Generate AGENTS.md ──
echo "7. AGENTS.md"
{
  cat "$TEMPLATES_DIR/agents-header.md"

  # 嵌入 Rules
  for rule in "${RULE_ORDER[@]}"; do
    rule_file="$RULES_DIR/$rule"
    if [ -f "$rule_file" ]; then
      title="${RULE_TITLES[$rule]:-$rule}"
      echo ""
      echo "---"
      echo ""
      echo "<!-- Source: .claude/rules/$rule -->"
      echo "## Rule: $title"
      echo ""
      cat "$rule_file"
    else
      echo "⚠️  Warning: $rule_file not found" >&2
    fi
  done

  # Skills 指引（不再內嵌，改為指向原生目錄）
  echo ""
  echo "---"
  echo ""
  echo "# Skills Reference"
  echo ""
  echo "Skills are available as native SKILL.md files in \`.agents/skills/\`."
  echo "Codex CLI will load them automatically based on task context."
  echo ""
  echo "## Available Skills (${#SKILL_ORDER[@]})"
  echo ""
  echo "| Skill | Description |"
  echo "|-------|-------------|"
  for skill in "${SKILL_ORDER[@]}"; do
    title="${SKILL_TITLES[$skill]:-$skill}"
    echo "| \`$skill\` | $title |"
  done
  echo ""
  echo "To use a skill, Codex CLI reads \`.agents/skills/{name}/SKILL.md\` on demand."
} > AGENTS.md
agents_lines=$(wc -l < AGENTS.md | tr -d ' ')
echo "   ✅ Generated ($agents_lines lines, ${#RULE_ORDER[@]} rules inline + ${#SKILL_ORDER[@]} skills native)"

# ── Summary ──
rule_count=$(ls "$RULES_DIR"/*.md | wc -l | tr -d ' ')
skill_count=${#SKILL_ORDER[@]}
echo ""
echo "=== Sync Complete ==="
echo ""
echo "  Platform              | Rules                               | Skills                          | Status"
echo "  ----------------------|-------------------------------------|---------------------------------|-------"
echo "  Claude Code           | .claude/rules/ (source of truth)    | .claude/skills/ (source of truth)| ✅"
echo "  Claude Code (skills)  | .claude/skills/angular-rules/refs/  | (same as above)                 | ✅"
echo "  Gemini CLI            | .gemini/rules/                      | .gemini/skills/                 | ✅"
echo "  Gemini CLI (entry)    | GEMINI.md ($gemini_lines lines)     | (skills table only)             | ✅"
echo "  OpenAI Codex          | (via AGENTS.md)                     | .agents/skills/                 | ✅"
echo "  OpenAI Codex (entry)  | AGENTS.md ($agents_lines lines)     | (skills table only)             | ✅"
echo "  Cursor AI             | .cursor/rules/ ($cursor_count .mdc) | (via rules only)                | ✅"
echo "  Augment (auggie)      | (reads .claude/ directly)           | (reads .claude/ directly)       | ✅"
echo ""
echo "Content: $rule_count rules + $skill_count skills"
echo "Source of truth: .claude/rules/ + .claude/skills/"
