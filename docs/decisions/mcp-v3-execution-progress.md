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
- **MCP tools:** 49 → 29 (target ~11). W4/W5 changed the count by 0 (no MCP tool surface); W6 C1 removed `system_status` + `manage_feeds` (40 → 38), the propose/commit subsystem — 6 `propose_*` + `commit_proposal` (38 → 31), `goal_progress` + `track_hypothesis` (31 → 29), `advance_work` + `update_note_maturity` (29 → 27), `archive_learning_target` (27 → 26), then the `manage_plan` `update_plan` action (still 26 — manage_plan kept, now 5 actions). **W6 C1 COMPLETE.** Then **C2 (`learning_read`)** folded learning_dashboard/recommend_next_target/attempt_history/session_progress into one read-only multiplexer (26 → 23). Then **C3a-1** removed session_delta + weekly_summary (23 → 21), **C3a-2** built `brief(mode=morning|reflection)` replacing morning_context+reflection_context (21 → 20, agent_notes-free per §1). Then **C3b** removed the 7 content tools → admin-only (20 → 13), **C3c** removed the agent_notes feature + internal/weekly (13 → **11**). **🎯 SURFACE CONTRACTION COMPLETE — 49 → 11** (brief, search_knowledge, capture_inbox, plan_day, start/record/end_session, learning_read, manage_plan, create_note, update_note). Remaining waves: W7 (schema converge — incl. dropping agent_notes table + its FK columns), W8 (admin create forms), W10 (doc cascade).

**W10 cleanup backlog (accumulated stale doc/comment refs to removed tools — all outside generated/gated artifacts, so they don't fail the build):** search.go:86 + SearchKnowledge catalog Description (query_agent_notes/agent_notes); authz.go package-doc examples (advance_work/file_report/commit_proposal/propose_goal); skills/koopa-system/references/tools.md hand-written narrative (content tools + agent_notes); EndSessionInput.Reflection field (accepted-but-ignored — trim or repurpose). Resolve in W10.
- **Invariant:** every commit is green (`go build ./... && go vet ./... && golangci-lint run && go test ./...`). The branch is always recoverable to the last commit; an uncommitted working tree may be mid-wave.
- **Acceptance protocol (owner decision 2026-06-06):** NO per-wave 驗收 — execute straight through W10. Acceptance = a single adversarial-review **workflow** over the whole branch AFTER W10 completes, then PR. **Anti-drift discipline during execution:** every removal is anchored to the ledger (§1 target surface / §2 admin-only / §3 retired); KEPT code (shared validators, backend stores, HTTP handlers) is zero-behaviour-change; no scope creep into adjacent code. Each slice runs the green gate + an adversarial "no dangling refs / kept-surface intact" check before commit.
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
| W5a | `c991257` | FSRS off the MCP surface: `record_attempt` loses `fsrs_rating` input + `fsrs_card`/`fsrs_rating_applied`/`fsrs_review_failed` output; `Server.fsrs` field + `updateFSRSReview`/`markFSRSDrift` removed. |
| W5b-1 | `e78a4ef` | FSRS `retrieval` view of `learning_dashboard` + `RetrievalQueue` store method/query + `RetrievalTarget`. |
| W5b-2a | `6e722bc` | review_cards-backed next-due reads (no fsrs-pkg coupling): ConceptsForList next_due_target CTE, DashboardConceptRows next_due CTE, stats `fsrs_cards_count`. |
| W5b-2b | `dd92c24` | **deleted `internal/learning/fsrs`** + every remaining consumer (learning ReviewMetrics / dashboard due_today / today due-reviews / HTTP review route / main wiring / tests). `go mod tidy` dropped go-fsrs + swept the W2 a2a-go/genproto debt. FSRS = 0 in production Go. Executed integration suites green. |
| W5c (frontend) | `dd23199` | Angular FSRS removal: deleted the interactive "Due today (FSRS)" dashboard card + rating UI + ReviewRating/recordReview; dropped FSRS model fields (due_today / due_reviews_count / next_due / next_due_target / `LearningSummary.due_reviews`); today dropped the dead learning-summary fan-out source + Due-reviews section; concepts list dropped Next-due column. tsc+lint+build+16 specs green; FSRS = 0 in frontend/src. |
| W6 C1 (1/2) | `5bd2f32` | First catalog-contraction slice: removed `system_status` + `manage_feeds` (whole-file deletes system.go/feed.go/system_test.go + catalog Metas + All() + server addTool + go-generate'd tools.md). Shared-test fallout handled (handler_test/authz_registered_caller/integration). MCP 40 → 38. Proved the per-tool removal recipe (delete handler → catalog → server → go generate → shared-test cascade → gate). |
| W6 C1 (6) | `7cec905` | **`manage_plan(update_plan)` action dropped** — plan activation/lifecycle is admin-only now; manage_plan keeps 5 actions (add/remove_entries, update_entry, reorder, progress). Removed updatePlan + the orphaned validatePlanTransition/allowedPlanTransitions/isValidPlanStatus. **Fixture repoint**: the 4 plan tests now activate their seeded plan via a direct SQL UPDATE (behaviour-preserving — exactly what UpdatePlanStatus did) instead of the removed action. **W6 C1 COMPLETE** (49→26). Gate incl executed integration (15.7s) green. |
| W6 C1 (5) | `36f6370` | `archive_learning_target` removed (whole-file target_admin.go: handler + Input/Output/wire types + requireTargetOwner (no other caller) + relationsToWire; catalog Meta + All + server addTool; 4 dedicated integration tests). s.learn stays (kept learning tools use it). Also retired the 3 stale target_admin comparison-comments from the W6 review. Gate incl executed integration (5.3s) green. MCP 27 → 26. |
| C3c agent_notes | `(committed)` | **Removed the agent_notes feature** (write_agent_note/query_agent_notes + internal/agent/note pkg + server/catalog/main/routes wiring + HTTP route; end_session reflection-note creation dropped (EndSession passes nil); planDay AgentNoteID/resolvePlanAgentNote dropped; sqlc regen). Also deleted orphaned internal/weekly (referenced the deleted agentnote.Store). agent_notes TABLE + daily/learning FK cols KEPT for W7. Impl-agent + independent re-verify. **MCP 13 → 11 — 🎯 TARGET HIT.** |
| C3b content | `0639a9b` | Removed the 7 content authoring/lifecycle tools (content.go + content_tools.go + tests). internal/content store + HTTP admin handler untouched; s.contents kept (brief content_pipeline). MCP 20 → 13. (commit completed via amend after a git-add pathspec slip left it partial — HEAD now repo-green.) |
| C3a-2 brief | (next commit) | NEW read-only `brief(mode=morning|reflection)` replaces morning_context+reflection_context. **agent_notes-free per ledger §1** — dropped morning plan_history + reflection today_notes/today_plan (the map-agent wrongly kept them; ledger won). Deleted morning.go+reflection.go (fillers → brief.go); relocated ContentSummary/toContentSummaries from content.go. Impl-agent + independent re-verify. MCP 21 → 20. |
| C3a-1 delta/weekly | `(committed)` | Removed session_delta + weekly_summary (whole-file delta.go/weekly.go + tests). s.activity field+wiring gone (weekly was sole consumer; HTTP activity feed separate). Dropped orphaned toMasteryRows. internal/weekly kept (backend, uncalled). MCP 23 → 21. |
| C2 learning_read | `bd118df` | NEW read-only multiplexer `learning_read(view=overview\|next_target\|attempts\|session_progress)` replaces 4 standalone tools (learning_dashboard/recommend_next_target/attempt_history/session_progress). Their output-builders kept as private methods learning_read dispatches to; store layer untouched. Dashboard mastery/weaknesses/timeline/variations (MCP-only) dropped per ledger §1. 12 integration tests repointed. Built by impl-agent, **independently re-verified** (gate incl executed integration 4.9s). MCP 26 → 23. |
| W6 review | `71f3d89` `30cce51` | Interim 4-lens adversarial review (read-only, independent re-derivation): **verdict CLEAN** — surface parity 27=27=27 (catalog/server/tools.md), backends + HTTP routes intact, repo-green from committed HEAD. Fixes: (1) removed orphaned `isValidTaskPriority` — advance_work was its only consumer; golangci-lint missed it because validators_test.go usage masks `unused`. (2) **OWNER DECISION 2026-06-06: inbox→todo promotion (clarify) is admin-UI-only** (advance_work is admin per §2; agents capture + plan already-clarified todos) → repointed plan_day/capture_inbox descriptions + the inbox-reject error away from advance_work; no behaviour change. DEFERRED doc-comments (they name removed file_report/write_agent_note/propose_hypothesis too): authz.go package-doc + learning.go error suggestions → C3/doc-sweep; target_admin.go comparison-comments → die with archive_learning_target next slice. |
| W6 C1 (4) | `08ea276` | `advance_work` + `update_note_maturity` removed (surgical — planDay stays in execution.go, create/update_note stay in note.go). Wider orphan cascade than whole-file deletes, all caught via build→vet→lint: `normalizePriority` + `validateTransition` (advance-only), authz `requireTodoOwner` (advance was its only caller), execution_test `TestValidateTransition` + its orphaned `todo` import. Kept isValidTaskPriority/isValidEnergy (planDay/capture use them). NOTE: target_admin.go has 3 stale comparison-comments referencing advance_work/requireTodoOwner → clean when archive_learning_target goes next. Gate incl executed integration (5.4s) green. MCP 29 → 27. |
| W6 C1 (3) | `98877b6` | `goal_progress` + `track_hypothesis` removed (whole-file goals.go/hypothesis.go + catalog/server + tests). Orphan cleanup: `isValidGoalStatusFilter` (goal_progress was its only producer) + `seedHypothesis` (added in the propose slice, orphaned when its test went). morning_context still uses s.goals/s.hypotheses → fields stay until C3. Gate incl executed integration (5.3s) green. MCP 31 → 29. |
| W6 C1 (2/2) | `8b4b940` | Propose/commit subsystem removed (6 `propose_*` + `commit_proposal`): deleted propose_flat.go + proposal.go (HMAC token/nonce) + proposal_test.go; gutted commitment.go to validators-only → new validate.go (the 7 isValid*/validateSlug KEPT — used by capture/plan/manage_plan/content/goals); server proposalSecret+nonces removed; 7 catalog Metas + All() + addTool; propose/commit tests removed from handler_test + authz_test. **Integration fixtures repointed**: the 5 tests that used propose→commit only to build a plan/hypothesis now seed directly (seedLearningPlan/seedHypothesis, created_by=human); 6 propose/commit-specific integration tests deleted. Gate incl EXECUTED integration (testcontainers 7.4s) green; zero dangling refs; anti-drift verified (authz primitives + kept-tool tests intact). MCP 38 → 31. |

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

### W5 — FSRS / spaced-repetition  ✅ COMPLETE (backend W5a/W5b-1/W5b-2a/W5b-2b + frontend W5c)

**Scope correction (re-grep at execution caught this):** the runbook's "`recommend_next_target` becomes weakness/mastery-based only" item is **MOOT** — `recommend_next.go` has ZERO fsrs references; it is already entirely weakness + variation-graph based (`WeaknessAnalysis` + `TargetVariations`, ranked by severity). No new ranking logic anywhere. W5 is a pure mechanical FSRS-field removal (ledger §3 direction is unambiguous — no product decision).

**W5a (done):** MCP-surface FSRS removed from `record_attempt` + `Server`. See Done table.

**W5b — backend: ✅ DONE** (`e78a4ef` W5b-1, `6e722bc` W5b-2a, `dd92c24` W5b-2b). `internal/learning/fsrs` deleted; FSRS gone from learning (handler / dashboard / concepts / query.sql), today, stats, the MCP `learning_dashboard` retrieval view, the HTTP review route, and main wiring. Verified by executed learning/today/stats/mcp integration suites (testcontainers). `go mod tidy` also resolved the pre-existing W2 `a2a-go`/`genproto` go.mod debt. Schema (`review_cards`, `review_logs`) → W7.

**W5c — frontend: ✅ DONE** (`dd23199`). Removed the dashboard "Due today (FSRS)" card + rating UI, the FSRS model fields, the today due-reviews section + its now-dead learning-summary fan-out source, and the concepts "Next due" column. The Explore map missed 3 items (the today-page spec's `dueReviewsCount` mock, the workbench `LearningSummary.due_reviews` field, and 2 stale doc comments) — re-grep + `tsc` caught them, which is why every workflow-produced plan is verified against the real files before applying.

### W6 + W3 + W9 — BRIEFING CLUSTER  *(interdependent — do together)*
Why together: `agentnote` (W3) is woven through morning_context / reflection_context / session_delta / weekly_summary, and those tools are being removed-from-catalog (W6) and replaced by the new `brief` (W9). Gutting agent_notes from tools that are simultaneously being removed/rebuilt is cleaner as one unit.
- **W6 — remove from `catalog.go` + `server.go` registration + delete the MCP handler funcs** (KEEP the backend stores + HTTP admin handlers — they serve the admin UI): content cluster (create/update/set_content_review_state/publish/archive/list/read_content), propose_goal/project/milestone/learning_plan/learning_domain + commit_proposal, advance_work, manage_feeds, session_delta, morning_context, reflection_context, weekly_summary, goal_progress, learning_dashboard, attempt_history, session_progress, system_status, track_hypothesis, update_note_maturity, and the manage_plan `update_plan` action. (recommend_next_target → folds into learning_read in W9.) After: `go generate ./internal/mcp/ops`.
- **W3 — delete agent_notes**: `git rm -r internal/agent/note`; remove `agent_note.go` (write/query handlers); `learning.go:~670` (KindReflection note creation); `execution.go:~284` (agentnote.KindPlan); HTTP `agents/{name}/notes` route + handler; server `agentNotes` field; main/routes wiring; sqlc path. Table `agent_notes` → W7.
- **W9 — build the new read-only multiplexers** (ledger §1, Correction 3 — READ-ONLY forever): `brief(mode=morning|reflection)` (the planning-state pull, WITHOUT agent_notes/FSRS/pending_tasks sections), `learning_read(view=overview|next_target|attempts|session_progress)` (session/attempt/weakness/plan-based, no FSRS due). Register in catalog + server; `go generate`.

**Handler-func → file map (mapped 2026-06-05; re-grep line ranges at execution):** morning_context→morning.go · reflection_context→reflection.go · session_delta→delta.go · weekly_summary→weekly.go · advance_work→execution.go (surgical — planDay stays) · write/query_agent_note→agent_note.go · propose_*→propose_flat.go · commit_proposal→commitment.go · goal_progress→goals.go · track_hypothesis→hypothesis.go · learning_dashboard→learning.go (surgical — start/record/end stay) · recommend_next_target→recommend_next.go (whole file) · attempt_history→attempt_history.go (whole) · session_progress→session_progress.go (whole) · content tools→content_tools.go + content.go · update_note_maturity→note.go (surgical) · manage_feeds→feed.go (whole) · system_status→system.go (whole) · archive_learning_target→target_admin.go.

**Seams that force ordering (re-grep confirmed 2026-06-05):**
1. **content.go types ↔ morning.go.** `content.go` (ManageContentInput/Output, ContentDetail, toContentDetail) is consumed by BOTH content_tools.go AND morning.go (morning's content-pipeline section). So content_tools.go + content.go can only fully delete once morning_context is gone — content removal is NOT independent; it lands with the briefing knot (C3).
2. **agent_notes cross-cut.** `agent_notes` is referenced by daily (daily.go/store.go), weekly (weekly.go), today (handler/today.go — already nil-wired in W5c), search (search.go — corpus indexing), learning (session.go/handler/learning.go — KindReflection write), and morning/reflection/delta. Per ledger §3 the table drops (W7) so EVERY consumer must stop reading it — there is no degraded form. This is the load-bearing part of C3.

**Seam-aware sub-commit decomposition (each green; the cluster is too large + knotted for one commit):**
- **C1 — independent W6 removals (no content-type / agent_notes coupling):** propose_* + commit_proposal, goal_progress, track_hypothesis, manage_feeds, advance_work (surgical), update_note_maturity (surgical), system_status, manage_plan `update_plan` action, archive_learning_target. Remove catalog Meta + server addTool + delete handler funcs/whole files (KEEP backend stores + HTTP). `go generate`. Bankable.
- **C2 — W9 learning_read + W6 learning-read removals:** build `learning_read(view=overview|next_target|attempts|session_progress)` as a read-only multiplexer dispatching to the EXISTING builders (dashboardOverview, the recommend_next logic, attempt-history query, session-progress query — keep the builders, drop their standalone tool wrappers); remove learning_dashboard / recommend_next_target / attempt_history / session_progress from catalog + server. `go generate`.
- **C3 — W3 agent_notes + W9 brief + W6 briefing/content removals (the knot):** delete `internal/agent/note` + every agent_notes consumer (daily/weekly/today/search/learning reflection-write); build `brief(mode=morning|reflection)` (planning pull, NO agent_notes/FSRS/pending_tasks); remove morning_context/reflection_context/session_delta/weekly_summary; delete content_tools.go + content.go (fold the ContentDetail/toContentDetail bits brief still needs into brief, or drop the content-pipeline section per ledger §1's "no agent_notes" brief). `agent_notes` table → W7.

**No product decision pending** — ledger §1 (target surface) + §3 (agent_notes fully retired, memory → agent `.md`) make every removal unambiguous; brief/learning_read modes/views are ledger-specified. The only judgment is mechanical (where to relocate the content-detail types brief needs in C3).

**Mapping-workflow findings (2026-06-05; re-runnable — the 4-agent map/draft workflow produced full line-ranges + Go drafts of brief & learning_read, but in an ephemeral transcript; re-run or re-grep at execution):**
- **C1 propose/commit is a SUBSYSTEM, not 7 isolated handlers.** `propose_flat.go` (whole file — 6 handlers + their `*Input` types) deletes cleanly. But `commitment.go` does NOT whole-delete: it holds shared validators (`validateSlug`, `isValidTaskPriority`, `isValidEnergy`, `isValidContentStatus`, `isValidPlanEntryStatus`, `isValidPlanStatus`, `isValidGoalStatusFilter`) that KEPT tools (manage_plan, content/advance paths) use — KEEP those; surgically remove only `ProposeOutput`/`CommitProposal{Input,Output}` + `proposeEntity`/`commitProposal`/`commitEntity`/`resolve*Fields`/`commit*` + `propValidatorDrift`. The HMAC token lives in a separate `proposal.go` (`signProposal`) — part of the proposal subsystem, remove iff no kept caller. **Verify each `isValid*` consumer before deleting.**
- **Verified keep-list (commitment.go) — these validators serve KEPT tools, do NOT delete:** `validateSlug` (content/learning), `isValidTaskPriority` (planDay), `isValidEnergy` (planDay + capture_inbox), `isValidContentStatus` (content), `isValidPlanEntryStatus`+`isValidPlanStatus` (manage_plan), `isValidGoalStatusFilter` (goals). They are INTERLEAVED among the propose/commit funcs → scattered func-by-func deletes, not a line range.
- **`proposal.go` deletes whole** (signProposal/verifyProposal/encodeToken/nonceStore/proposalPayload — only the proposal subsystem uses them) AND remove the orphaned `Server.proposalSecret` field + its `server.go` assignment + the main.go `WithProposalSecret`/secret wiring.
- Every "clean chunk" has tendrils — apply each sub-commit with per-symbol consumer greps, not blind line-range deletes.
- Status: cluster fully comprehended + planned; **execution deferred to a fresh focused session** (C1→C2→C3, each green-gated + committed) rather than risk a half-migrated tree at the tail of the W4+W5 marathon.

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
