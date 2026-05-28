#!/usr/bin/env bash
# Frontend quality gates — minimal automated subset of
# frontend/docs/frontend/frontend-quality-protocol.md. Exit non-zero on any
# failure. See the protocol doc for which gates are covered here and which
# remain manual.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PAGES_DIR="$FRONTEND_ROOT/src/app/pages"
ROUTES_FILE="$FRONTEND_ROOT/src/app/app.routes.ts"
SERVER_ROUTES_FILE="$FRONTEND_ROOT/src/app/app.routes.server.ts"

FAIL_COUNT=0
PASS_COUNT=0

report_pass() {
  echo "PASS  $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

report_fail() {
  echo "FAIL  $1"
  if [ -n "${2:-}" ]; then
    printf '%s\n' "$2" | sed 's/^/        /'
  fi
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

run_grep_check() {
  local desc="$1" pattern="$2" path="$3"
  local hits
  hits=$(grep -rnE "$pattern" "$path" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    report_fail "$desc" "$hits"
  else
    report_pass "$desc"
  fi
}

require_file() {
  if [ ! -f "$1" ]; then
    echo "ERROR  expected file not found: $1" >&2
    exit 2
  fi
}

require_dir() {
  if [ ! -d "$1" ]; then
    echo "ERROR  expected directory not found: $1" >&2
    exit 2
  fi
}

require_dir "$PAGES_DIR"
require_file "$ROUTES_FILE"
require_file "$SERVER_ROUTES_FILE"

echo "Frontend quality checks (see docs/frontend/frontend-quality-protocol.md)"
echo "Root: $FRONTEND_ROOT"
echo "----------------------------------------------------------------------"

# ---- Gate 2: public/private boundary ----

# pages/ must not import from admin/. Matches relative imports (./admin/, ../admin/,
# nested) and absolute-style imports (src/app/admin/). TS path aliases pointing to
# admin/ would slip through — none are configured today; protocol doc lists this
# as a known limitation.
run_grep_check \
  "Gate 2 — pages/ must not import from admin/" \
  "from[[:space:]]+['\"][^'\"]*/admin(/|['\"])" \
  "$PAGES_DIR"

# pages/ must not call admin APIs. Catches URL string literals and HttpClient
# usage that hardcodes /api/admin.
run_grep_check \
  "Gate 2 — pages/ must not reference /api/admin" \
  "/api/admin" \
  "$PAGES_DIR"

# ---- Gates 1 + 2: public templates must not link to /admin ----

# Two-stage filter: lines mentioning routerLink or href, restricted to those
# whose value starts with /admin (preceded by a quote, single or double).
admin_link_hits=$(grep -rnE "(routerLink|href)" "$PAGES_DIR" 2>/dev/null \
                  | grep -E "['\"]/admin" || true)
if [ -n "$admin_link_hits" ]; then
  report_fail "Gates 1+2 — pages/ must not link to /admin via routerLink/href" \
    "$admin_link_hits"
else
  report_pass "Gates 1+2 — pages/ must not link to /admin via routerLink/href"
fi

# ---- Gate 1: tag route removal hygiene ----

# The /tags/:tag route was removed on 2026-05-28 (see
# docs/frontend/tag-route-owner-decision.md). pages/ must contain no /tags/
# string — covers routerLink, href, hardcoded URLs, and stale comments.
run_grep_check \
  "Gate 1 — pages/ must not contain /tags/ (route removed 2026-05-28)" \
  "/tags/" \
  "$PAGES_DIR"

# ---- Gate 1: routes-file hygiene ----

if grep -q "tags/:tag" "$ROUTES_FILE"; then
  report_fail "Gate 1 — app.routes.ts must not contain tags/:tag" \
    "$(grep -n 'tags/:tag' "$ROUTES_FILE")"
else
  report_pass "Gate 1 — app.routes.ts must not contain tags/:tag"
fi

if grep -q "tags/:tag" "$SERVER_ROUTES_FILE"; then
  report_fail "Gate 1 — app.routes.server.ts must not contain tags/:tag" \
    "$(grep -n 'tags/:tag' "$SERVER_ROUTES_FILE")"
else
  report_pass "Gate 1 — app.routes.server.ts must not contain tags/:tag"
fi

# ---- Gate 2: admin SSR boundary ----

# Inside app.routes.server.ts, any block whose `path:` starts with 'admin' must
# carry `renderMode: RenderMode.Client`. The awk program tracks whether we are
# inside an admin block (set on admin path, cleared on any other path) and
# flags any RenderMode.Server / RenderMode.Prerender encountered while inside.
non_client_admin=$(awk "
/path: ['\"]admin/ { in_admin=1; next }
/path: / { in_admin=0; next }
in_admin && /renderMode: RenderMode\\.(Server|Prerender)/ {
  print FILENAME\":\"NR\": \"\$0
}
" "$SERVER_ROUTES_FILE" 2>/dev/null || true)

if [ -n "$non_client_admin" ]; then
  report_fail "Gate 2 — admin routes in app.routes.server.ts must use RenderMode.Client" \
    "$non_client_admin"
else
  report_pass "Gate 2 — admin routes in app.routes.server.ts must use RenderMode.Client"
fi

echo "----------------------------------------------------------------------"
echo "Summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"

if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
exit 0
