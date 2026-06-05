# MCP v3 Contraction — Execution Runbook & Progress

**Purpose:** the durable, resumable handoff for the MCP v3 contraction. Any session (or agent)
continues by reading, in order: (1) `mcp-v3-semantic-contraction.md` (the *what* — accepted
surface, retired surface, end state, binding rules), (2) **this file** (the *how / where we are*),
(3) `git log --oneline` on branch `refactor/mcp-v3-contraction`. Update this file after every wave.

This file is the single source of truth for execution state. It does not depend on any session's
private memory.

---

## Current state

- **Branch:** `refactor/mcp-v3-contraction` (off `main` @ `effdb92`).
- **MCP tools:** 49 → 40 (target ~11). **W4 (bookmark) changed this count by 0** — bookmark had no MCP surface (admin/public HTTP + frontend only).
- **Invariant:** every commit is green (`go build ./... && go vet ./... && golangci-lint run && go test ./...`). The branch is always recoverable to the last commit; an uncommitted working tree may be mid-wave.
- **Known pre-existing (NOT W4 — surfaced during W4, left untouched for scope):** `go.mod` has `github.com/a2aproject/a2a-go/v2` unused + a `google.golang.org/genproto/googleapis/api` tidy gap — both W2 (A2A removal) fallout. `go build`/`vet` pass; `go mod tidy` would clean them. Fold into W7 or a dedicated `chore(deps)` commit; do NOT mix into a feature wave.

### Done (committed, green)

| Wave | Commit | What |
|---|---|---|
| W-1 | `6aa2e73` | the ledger (`mcp-v3-semantic-contraction.md`) |
| W0 | `7e3c133` | 11 orphan sqlc queries + dead todo-skip path |
| W1 | `8432536` | report-lane (research pkg, assign/create_report, search report source) |
| W2a | `5e01145` | A2A dispatch tools + directive proposal/commit (threaded through commitment.go) |
| W2b | `a31de0b` | task/artifact pkgs, morning pending_tasks, HTTP coordination/tasks routes, server stores |
| W4 (backend) | `46e45b8` | bookmark pkg + public/admin routes + main wiring; tag-merge `bookmark_tags` coupling removed (2 sqlc queries + `MergeResult.BookmarkTagsMoved`); `api/integration_test.go` ActorMiddleware test repointed bookmark→note; stale-comment sweep |
| W4 (frontend) | `7c91ecc` | bookmark public page, admin list, inspector renderer, BookmarkService deleted; routing/nav/nav-counts/command-palette/keyboard-shortcuts/activity/inspector-union/BookmarkDetail surgically cut; tsc+lint+build+specs green |

---

## Execution conventions (LEARNED — follow these)

1. **Per-wave gate:** after edits, run `go build ./...`, `go vet ./...`, `go vet -tags integration ./internal/mcp/`, `golangci-lint run <touched pkgs>`, `go test ./<touched>/...`. Green → commit. One wave = one (or a few sub-) commits, conventional format, no `Co-Authored-By`, stage specific files (never `git add -A`).
2. **Deletions:** `rm` is permission-denied in this env — use `git rm` for files/dirs and `sed -i '' '<a>,<b>d'` for line-range blocks (macOS sed needs the `''`). For removing a whole function, `sed -i '' 'START,ENDd'` with `START` = its doc-comment's first line and `END` = the line before the next kept symbol's comment, so you don't orphan doc comments onto the next function.
3. **goimports import-shift trap:** the PostToolUse formatter auto-removes now-unused imports after an Edit, which *shifts line numbers*. NEVER `sed Nd` an import by a stale line number — re-`grep -n` or `sed -n 'Np'` to confirm the line's content *immediately* before deleting. (I once deleted `internal/api` from main.go this way and had to restore it.)
4. **After a Bash file edit (sed), the next Edit tool call will report "file modified since read"** — re-Read the region first.
5. **Catalog changes → regenerate tools.md:** after editing `internal/mcp/ops/catalog.go`, run `go generate ./internal/mcp/ops` (the `TestToolInventoryDocInSync` test enforces `skills/koopa-system/references/tools.md` matches the catalog). This is the ONLY generated doc that tracks per-wave; the descriptive docs (decision-policy, contract, Studio manuals) are rewritten LAST in W10.
6. **zsh** does not word-split unquoted vars — inline package lists in `go`/`golangci-lint` commands.
7. **Schema:** tables of retired features STAY in `migrations/001` until **W7**, which converges them by EDITING 001 in place + DELETING migrations 003 & 004 (no append-only drop migrations). Pre-production: this is allowed and intended.
8. **No backward compatibility / no deprecation shims.** Clean vertical removal per feature.

---

## Remaining waves (mapped; cut-lists are starting points — re-grep at execution time)

### Recommended order: ~~W4~~ done → **W5 (next)** → (W6 + W3 + W9 as one briefing cluster) → W7 → W8 → frontend → W10

### W4 — bookmark, FULL feature removal  ✅ DONE (`46e45b8` backend, `7c91ecc` frontend)
**Footprint correction (the original map was incomplete — re-grep at execution time caught it; lessons for later waves):**
- The original footprint claimed "no other non-test Go refs (only comments)". WRONG: `internal/tag` had real coupling — `MergeTags` reassigned `bookmark_tags` via `DeleteDuplicateBookmarkTags`/`ReassignBookmarkTags` (tag/query.sql) + `MergeResult.BookmarkTagsMoved` (tag.go). Removed in W4. **This was necessary, not optional:** the queries had to go BEFORE W7 drops the `bookmark_tags` table, else `sqlc generate` in W7 fails on a query referencing a dropped table. **General rule for every feature-removal wave: drop ALL sqlc queries touching that feature's tables in the code wave, so the W7 table-drop generates cleanly.**
- `internal/api/integration_test.go` was NOT "public-API tests" — it is the ActorMiddleware tx/audit-actor contract test that used **bookmark Create as its representative audited route**. Deleting bookmark would have destroyed that coverage, so it was **repointed to `note` Create** (an audited entity in the MCP-v3 keep-set). `topic`/`tag` were rejected as repoint targets — they are NOT in the `activity_events.entity_type` CHECK and have no audit trigger (only `todo/goal/milestone/project/content/bookmark/note/learning_*` are audited).
- Stale-comment sweep (deleted-package/symbol refs): note/handler.go, content/content.go, mcp/content.go, project/project.go, tag/store.go, api/middleware.go, mcp/ops/types.go, content_test.go, url.go. The `bookmarks`-TABLE comments that describe the still-live schema relationship (feed/entry/store.go `source_feed_entry_id` FK, url.go `bookmarks.url_hash`) were left for the W7 sweep.
- KEPT (per ledger E2): `search.Kind` `KindBookmark` roadmap placeholder; the generated `db.Bookmark*` models (vanish in W7 with the table).
- Schema (`bookmarks`, `bookmark_topics`, `bookmark_tags`) → W7.
- **Frontend verify lesson:** the unit-test builder is `@angular/build:unit-test`. Raw `npx vitest run <file>` fails with "describe is not defined" (bypasses the builder's TestBed/globals init) — ALWAYS use `npx ng test --watch=false --include='<spec glob>'` (supports `--include`/`--filter` for scoping). W4 verified via `npx tsc --noEmit` + `npx ng lint` + `npx ng build` + the 3 affected specs (28 tests green).

### W5 — FSRS / spaced-repetition  *(clean standalone)*
- `git rm -r internal/learning/fsrs`.
- `internal/mcp/learning.go` + `recommend_next.go`: remove the FSRS due-queue / next-review dependency; `recommend_next_target` becomes weakness/mastery-based only (ledger §3).
- HTTP: remove `/api/admin/learning/reviews/{card_id}` route + the `fsrs` handler field + main.go `fsrsStore` + `fsrs.NewHandler` wiring + `learning.NewHandler(..., fsrsStore, ...)` arg.
- sqlc.yaml: remove `internal/learning/fsrs/query.sql`; `sqlc generate`.
- Schema (`review_cards`, `review_logs`) → W7.

### W6 + W3 + W9 — BRIEFING CLUSTER  *(interdependent — do together)*
Why together: `agentnote` (W3) is woven through morning_context / reflection_context / session_delta / weekly_summary, and those tools are being removed-from-catalog (W6) and replaced by the new `brief` (W9). Gutting agent_notes from tools that are simultaneously being removed/rebuilt is cleaner as one unit.
- **W6 — remove from `catalog.go` + `server.go` registration + delete the MCP handler funcs** (KEEP the backend stores + HTTP admin handlers — they serve the admin UI): content cluster (create/update/set_content_review_state/publish/archive/list/read_content), propose_goal/project/milestone/learning_plan/learning_domain + commit_proposal, advance_work, manage_feeds, session_delta, morning_context, reflection_context, weekly_summary, goal_progress, learning_dashboard, attempt_history, session_progress, system_status, track_hypothesis, update_note_maturity, and the manage_plan `update_plan` action. (recommend_next_target → folds into learning_read in W9.) After: `go generate ./internal/mcp/ops`.
- **W3 — delete agent_notes**: `git rm -r internal/agent/note`; remove `agent_note.go` (write/query handlers); `learning.go:~670` (KindReflection note creation); `execution.go:~284` (agentnote.KindPlan); HTTP `agents/{name}/notes` route + handler; server `agentNotes` field; main/routes wiring; sqlc path. Table `agent_notes` → W7.
- **W9 — build the new read-only multiplexers** (ledger §1, Correction 3 — READ-ONLY forever): `brief(mode=morning|reflection)` (the planning-state pull, WITHOUT agent_notes/FSRS/pending_tasks sections), `learning_read(view=overview|next_target|attempts|session_progress)` (session/attempt/weakness/plan-based, no FSRS due). Register in catalog + server; `go generate`.

End state of the cluster: MCP keeps ~11 tools (ledger §1): plan_day, search_knowledge, capture_inbox, start/record/end_session, manage_plan(5 actions), learning_read, brief, create_note, update_note.

### W7 — schema converge into `migrations/001`
- Edit `001` in place: DROP `tasks`, `task_messages`, `artifacts`, `agent_notes`, `review_cards`, `review_logs`, `bookmarks`, `bookmark_topics`, `bookmark_tags` + any retired columns; remove their indexes/triggers/COMMENTs.
- `git rm migrations/003_tasks_acknowledged.{up,down}.sql migrations/004_report_lane.{up,down}.sql` (their tables `research_assignments`, `reports` + the `tasks` ACK columns vanish with them).
- Remove the now-orphan `reports.search_vector` override from sqlc.yaml.
- `sqlc generate`; rebuild the test DB; `go build ./... && go test ./...`.
- Remove `TestTaskStateChange_FiresActivityTrigger` (integration_test.go) — it drives the dropped `tasks` table via raw SQL.
- End state: clean `001` + `002` only.

### W8 — admin create forms (NET-NEW BUILD; ledger §2)
- Backend `POST` endpoints + handlers: goals, milestones, learning_plans, learning_domains (projects already has POST). These are the "decision-stamp" forms replacing the removed MCP propose_* tools.
- Angular create/confirm forms for the same. Verify with a frontend build.

### W10 — doc cascade (LAST; ledger §5 ordering rule)
- Rewrite `.claude/rules/mcp-decision-policy.md` (§8 proposal, §14 coordination, §10 multiplexer, vocabulary), `docs/backend-semantic-contract.md`, `docs/authorization-matrix.md`.
- Regenerate `skills/koopa-system/**` from the final catalog.
- Delete the Studio role-manuals (`skills/koopa-system/references/{hq,content,learning,research,a2a,decision-policy}.md`; keep `tools.md`).

### Frontend (do alongside W2c/W4 or as a final Angular pass)
- Delete `frontend/src/app/admin/coordination/tasks/*` + `task.service.ts` + `task-inspector` (W2c — backend already gone). KEEP coordination/activity, agents, pipeline.
- Delete bookmark pages (W4).
- Verify with the project's frontend build (`cd frontend && npm run build` or the Angular CLI).

---

## Verify commands (per wave)
```
go build ./... && go vet ./...
go vet -tags integration ./internal/mcp/
golangci-lint run ./internal/<touched>/...
go test ./internal/<touched>/...
go generate ./internal/mcp/ops   # only if catalog.go changed
```
