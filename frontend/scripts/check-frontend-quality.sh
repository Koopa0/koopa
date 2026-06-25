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

# ---- Gate 1: public link/navigation must target a known route ----
#
# Scan src/app/** outside src/app/admin/** for static link and navigation
# references and verify the first path segment exists in app.routes.ts.
# Caught regressions:
#   - templates linking to /notes when no /notes public route exists
#   - command palette navigating to /uses before the route was registered
# Supported reference forms (all string-literal, leading-/ only):
#   - routerLink="/foo"
#   - [routerLink]="['/foo', …]"  /  [routerLink]="'/foo'"  /  [routerLink]="'/foo/' + x"
#   - href="/foo"  (absolute internal URLs only; anchors and external schemes skipped)
#   - navigate(['/foo', …])  /  navigate('/foo')
#   - navigateByUrl('/foo')
# Out of scope (intentionally not detected — see protocol "Known limitations"):
#   - template literals (`/foo/${id}`)
#   - variable / method-call arguments (navigate(entry.path), [routerLink]="fn(x)")
#   - strings assembled at runtime
#
# Keep PUBLIC_ROOT_ALLOWLIST in sync with the top-level paths declared in
# src/app/app.routes.ts. "admin" is allowed here so authenticated shortcuts
# (e.g. app.html "Admin dashboard" link, palette admin entries) don't false-fire;
# the existing Gates 1+2 check above already keeps pages/ free of /admin links.
# "essays" and "home" survive as redirect routes into the consolidated
# /articles index; "preview" is the chrome-less reading column the admin
# publish-preview iframes; "feed.xml" is served by server.ts (RSS).
# "resume" is deliberately NOT allowlisted: the /resume route survives only as
# an inbound redirect to /about for old external links — internal links and
# navigation must target /about directly.
# "til" and "build-logs" are likewise NOT allowlisted: their standalone routes
# are permanently retired (they 404). Every content type is folded into the
# /articles index, narrowed by the optional ?type= query param.
PUBLIC_ROOT_ALLOWLIST="articles essays projects topics search preview about uses home privacy terms login error admin feed.xml"

# Emit `file:line:/path` records by stripping the surrounding ref form from each
# match. Each grep -oE captures the smallest substring containing the path
# literal so a following sed can pull out just the path while preserving the
# file:line prefix added by -nH.
collect_public_paths() {
  local scan_root="$FRONTEND_ROOT/src/app"

  # grep -nH output: "file:line:matched-substring". The sed below captures the
  # "file:line:" prefix as \1 and the absolute path as \2 to avoid the trap
  # where a leading ".*" silently swallows the prefix.
  local prefix='^([^:]+:[0-9]+:)'

  # routerLink="/foo"
  grep -rnHoE 'routerLink="/[^"]*"' "$scan_root" \
    --include="*.html" --include="*.ts" --exclude-dir=admin 2>/dev/null \
    | sed -E "s|${prefix}routerLink=\"(/[^\"]*)\"|\\1\\2|"

  # [routerLink]="['/foo'…" or [routerLink]="'/foo'…"
  grep -rnHoE "\[routerLink\]=\"\[?'/[^']+'" "$scan_root" \
    --include="*.html" --include="*.ts" --exclude-dir=admin 2>/dev/null \
    | sed -E "s|${prefix}\\[routerLink\\]=\"\\[?'(/[^']+)'.*|\\1\\2|"

  # href="/foo" — internal absolute URLs only. Reject leading '#' (anchor) and
  # ':' (would-be scheme). External hrefs do not start with '/'.
  grep -rnHoE 'href="/[^"#:][^"]*"' "$scan_root" \
    --include="*.html" --include="*.ts" --exclude-dir=admin 2>/dev/null \
    | sed -E "s|${prefix}href=\"(/[^\"]*)\"|\\1\\2|"

  # navigate(['/foo'…) or navigate('/foo'…)
  grep -rnHoE "navigate\(\[?'/[^']+'" "$scan_root" \
    --include="*.ts" --exclude-dir=admin 2>/dev/null \
    | sed -E "s|${prefix}navigate\\(\\[?'(/[^']+)'.*|\\1\\2|"

  # navigateByUrl('/foo'…)
  grep -rnHoE "navigateByUrl\('/[^']+'" "$scan_root" \
    --include="*.ts" --exclude-dir=admin 2>/dev/null \
    | sed -E "s|${prefix}navigateByUrl\\('(/[^']+)'.*|\\1\\2|"
}

bad_public_paths=$(collect_public_paths | awk -v allow="$PUBLIC_ROOT_ALLOWLIST" '
  BEGIN { split(allow, A, " "); for (i in A) allowed[A[i]] = 1 }
  {
    # Input lines are "file:line:/path". File path has no ":" (POSIX) and the
    # line number is purely digits, so the first two ":" split cleanly.
    p1 = index($0, ":");                 if (p1 == 0) next
    rest = substr($0, p1 + 1)
    p2 = index(rest, ":");               if (p2 == 0) next
    file = substr($0, 1, p1 - 1)
    line = substr(rest, 1, p2 - 1)
    path = substr(rest, p2 + 1)
    if (substr(path, 1, 1) != "/") next
    seg = substr(path, 2)
    s = index(seg, "/"); if (s > 0) seg = substr(seg, 1, s - 1)
    # Drop any query string or fragment on the first segment ("/x?y" → "x").
    s = index(seg, "?"); if (s > 0) seg = substr(seg, 1, s - 1)
    s = index(seg, "#"); if (s > 0) seg = substr(seg, 1, s - 1)
    if (seg == "") next                  # "/" — home root, always allowed
    if (seg in allowed) next
    printf("%s:%s  %s  (unknown segment: %s)\n", file, line, path, seg)
  }
')

if [ -n "$bad_public_paths" ]; then
  report_fail "Gate 1 — public link/navigation must target a known public route" \
    "$bad_public_paths"
else
  report_pass "Gate 1 — public link/navigation must target a known public route"
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

# ---- Gate 3: stale false-negative availability copy ----
#
# Each admin surface below backs a LIVE backend route (cmd/app/routes.go) with
# a matching frontend service. Copy claiming the route/endpoint "is not live
# yet" / "Endpoint not yet available" / "Endpoints pending" is a false negative
# that misleads operators and future agents about the real product state. This
# gate guards the files cleaned in the stale-availability-copy task against
# regression.
#
# It intentionally does NOT forbid legitimate copy where a backend route exists
# but the UI feature is deferred — e.g. "edit UI is not built yet"
# (bookmark edit panel), "not yet wired" (feed-triage quick-create dialog), or
# the "Coming soon" route placeholder. Only phrases that falsely deny a live
# route are listed.
STALE_COPY_FILES=(
  "src/app/admin/commitment/todos/gtd.page.html"
  "src/app/admin/commitment/todos/gtd.page.ts"
  "src/app/admin/system/agents/profile/agent-profile.page.html"
  "src/app/admin/system/agents/profile/agent-profile.page.ts"
  "src/app/admin/knowledge/content/editor/content-editor.page.ts"
  "src/app/admin/knowledge/notes/editor/note-editor.page.html"
  "src/app/admin/knowledge/notes/editor/note-editor.page.ts"
  "src/app/admin/knowledge/notes/list/notes-list.page.html"
  "src/app/admin/knowledge/notes/list/notes-list.page.ts"
  "src/app/admin/learning/concepts/list/concepts-list.page.html"
  "src/app/admin/learning/concepts/profile/concept-profile.page.html"
  "src/app/admin/learning/dashboard/learning-dashboard.page.html"
  "src/app/admin/learning/dashboard/learning-dashboard.page.ts"
  "src/app/admin/learning/hypotheses/profile/hypothesis-profile.page.html"
  "src/app/admin/learning/hypotheses/profile/hypothesis-profile.page.ts"
  "src/app/admin/learning/plans/timeline/plan-timeline.page.html"
  "src/app/admin/learning/sessions/timeline/session-timeline.page.html"
)

# Phrases that falsely claim a known-live route/endpoint is unavailable.
STALE_COPY_PATTERN='not live yet|is not live|[Ee]ndpoint[s]? not yet available|[Ee]ndpoints pending|once the (endpoint|backend) (ships|wraps)|(Notes|Lineage) pending'

stale_copy_hits=""
for rel in "${STALE_COPY_FILES[@]}"; do
  f="$FRONTEND_ROOT/$rel"
  if [ ! -f "$f" ]; then
    echo "ERROR  Gate 3 references missing file: $rel" >&2
    exit 2
  fi
  hit=$(grep -nE "$STALE_COPY_PATTERN" "$f" 2>/dev/null || true)
  if [ -n "$hit" ]; then
    stale_copy_hits+="$rel"$'\n'"$hit"$'\n'
  fi
done

if [ -n "$stale_copy_hits" ]; then
  report_fail "Gate 3 — changed admin surfaces must not claim a live route is 'not live'" \
    "$stale_copy_hits"
else
  report_pass "Gate 3 — changed admin surfaces must not claim a live route is 'not live'"
fi

echo "----------------------------------------------------------------------"
echo "Summary: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"

if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
exit 0
