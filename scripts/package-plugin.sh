#!/bin/bash
# Package a spec project as a Claude Code plugin for personal use
# Usage: ./scripts/package-plugin.sh <spec-dir> <output-dir>
#
# Example:
#   ./scripts/package-plugin.sh /path/to/go-spec /path/to/output
#   -> Creates go-spec-plugin/ with plugin.json, skills/, agents/, hooks/
#
# Install locally:
#   claude --plugin-dir ./go-spec-plugin
#
# Or add as local marketplace:
#   claude /plugin marketplace add /path/to/my-plugins

set -euo pipefail

SPEC_DIR="${1:-.}"
OUTPUT_DIR="${2:-./plugin-output}"
SPEC_NAME=$(basename "$SPEC_DIR" | sed 's/-spec$//')

PLUGIN_DIR="$OUTPUT_DIR/${SPEC_NAME}-spec-plugin"

echo "Packaging $SPEC_NAME-spec as Claude Code plugin..."

# Clean and create
rm -rf "$PLUGIN_DIR"
mkdir -p "$PLUGIN_DIR/.claude-plugin"
mkdir -p "$PLUGIN_DIR/skills"
mkdir -p "$PLUGIN_DIR/agents"
mkdir -p "$PLUGIN_DIR/hooks"

# --- plugin.json ---
cat > "$PLUGIN_DIR/.claude-plugin/plugin.json" <<EOF
{
  "name": "${SPEC_NAME}-spec",
  "description": "${SPEC_NAME} development spec — agents, skills, hooks for Claude Code",
  "version": "2.0.0",
  "author": "koopa0",
  "repository": "https://github.com/koopa0/${SPEC_NAME}-spec"
}
EOF

# --- Copy skills ---
if [ -d "$SPEC_DIR/.claude/skills" ]; then
  for skill_dir in "$SPEC_DIR/.claude/skills"/*/; do
    skill_name=$(basename "$skill_dir")
    if [ -f "$skill_dir/SKILL.md" ]; then
      mkdir -p "$PLUGIN_DIR/skills/$skill_name"
      cp "$skill_dir/SKILL.md" "$PLUGIN_DIR/skills/$skill_name/"
      # Copy any supporting files
      for f in "$skill_dir"/*; do
        [ "$(basename "$f")" != "SKILL.md" ] && [ -f "$f" ] && cp "$f" "$PLUGIN_DIR/skills/$skill_name/"
      done
    fi
  done
  skill_count=$(find "$PLUGIN_DIR/skills" -name "SKILL.md" | wc -l | tr -d ' ')
  echo "  Skills: $skill_count"
fi

# --- Copy agents ---
if [ -d "$SPEC_DIR/.claude/agents" ]; then
  cp "$SPEC_DIR/.claude/agents"/*.md "$PLUGIN_DIR/agents/" 2>/dev/null || true
  agent_count=$(find "$PLUGIN_DIR/agents" -name "*.md" | wc -l | tr -d ' ')
  echo "  Agents: $agent_count"
fi

# --- Extract hooks config ---
if [ -f "$SPEC_DIR/.claude/settings.json" ]; then
  # Extract hooks section from settings.json
  if command -v jq >/dev/null 2>&1; then
    jq '{ hooks: .hooks }' "$SPEC_DIR/.claude/settings.json" > "$PLUGIN_DIR/hooks/hooks.json"
  else
    echo "  WARNING: jq not found, skipping hooks.json extraction"
  fi

  # Copy hook scripts
  hook_dir="$SPEC_DIR/.claude/hooks"
  [ ! -d "$hook_dir" ] && hook_dir="$SPEC_DIR/.claude/scripts/hooks"
  if [ -d "$hook_dir" ]; then
    cp "$hook_dir"/* "$PLUGIN_DIR/hooks/" 2>/dev/null || true
    hook_count=$(find "$PLUGIN_DIR/hooks" -type f | wc -l | tr -d ' ')
    echo "  Hooks: $hook_count files"
  fi
fi

# --- Copy rules as reference (not auto-loaded by plugins) ---
if [ -d "$SPEC_DIR/.claude/rules" ]; then
  mkdir -p "$PLUGIN_DIR/rules"
  cp "$SPEC_DIR/.claude/rules"/*.md "$PLUGIN_DIR/rules/" 2>/dev/null || true
  rule_count=$(find "$PLUGIN_DIR/rules" -name "*.md" | wc -l | tr -d ' ')
  echo "  Rules: $rule_count (reference only — copy to .claude/rules/ to activate)"
fi

# --- Summary ---
total=$(find "$PLUGIN_DIR" -type f | wc -l | tr -d ' ')
size=$(du -sh "$PLUGIN_DIR" | awk '{print $1}')
echo ""
echo "Plugin packaged: $PLUGIN_DIR"
echo "  Total files: $total"
echo "  Size: $size"
echo ""
echo "Usage:"
echo "  # Test locally:"
echo "  claude --plugin-dir $PLUGIN_DIR"
echo ""
echo "  # Install to a project:"
echo "  cp -r $PLUGIN_DIR /path/to/your-project/.claude-plugins/${SPEC_NAME}-spec/"
echo ""
echo "  # Or symlink for auto-updates:"
echo "  ln -s $PLUGIN_DIR /path/to/your-project/.claude-plugins/${SPEC_NAME}-spec"
