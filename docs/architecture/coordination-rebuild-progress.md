# Coordination Rebuild — PR1 Progress Checklist

> Working doc. Delete when PR1 merges. Target: `docs/architecture/coordination-layer-target.md`.
> Strategy: single big-bang PR (Path A). All stages complete as of this commit.
> Plus a second sweep for naming/architecture issues found during review.

## Naming + architecture sweep (post-review)

Triggered by user audit questions. All complete.

- [x] `internal/note` → `internal/obsidian/note` (Obsidian vault files)
- [x] `internal/agent_note` → `internal/agent/note` (agent narrative log)
  - When both needed in one file: `agentnote` / `obsidiannote` aliases
- [x] **Deleted entirely**: `internal/synthesis/`, `internal/consolidation/`, `syntheses` table, ConsolidateWeekly + ReflectHistoryWeekly endpoints
- [x] **Created** `internal/weekly/` — pure Compute function, no DB, mirrors `internal/daily` philosophy
- [x] `internal/mcp/weekly.go` rewired to call `weekly.Compute`
- [x] Learning naming sweep: `items`, `item_concepts`, `item_relations`, `sessions`, `attempts`, `attempt_observations`, `plans`, `plan_items` all prefixed with `learning_`
- [x] Generated db types: `LearningItem`, `LearningSession`, `LearningPlan`, etc.
- [x] `review_queue` → `editorial_queue` (disambiguates from FSRS `review_cards`/`review_logs`)
- [x] `content_type` enum: dropped `bookmark` (split into bookmarks table) and `note` (collided with vault notes / agent notes)
- [x] `internal/mcp/content.go::mcBookmarkRSS` stubbed with TODO — needs rewire to bookmark.Store
- [x] `hypotheses.hypothesis` column → `hypotheses.claim` (avoid stutter)
- [x] `sources` table → `sync_sources` (clearer responsibility)
- [x] `reconcile_runs` → `drift_check_runs` (describes what it actually measures)
- [x] All renames verified: `go build ./...` ✅, `go vet ./...` ✅, `go test ./...` ✅

## Schema + bootstrap (done)

- [x] `migrations/001_initial.up.sql` rewritten to target schema
- [x] `migrations/001_initial.down.sql` rewritten
- [x] `migrations/002_seed.up.sql` — participant_schedules seed removed
- [x] `scripts/reset-db.sh` (user runs manually on dev + VPS)
- [x] `internal/agent/` package (agent.go, registry.go, authorize.go, store.go+TODO, sync.go, agent_test.go)
- [x] `internal/directive/` + `internal/report/` deleted
- [x] `internal/task/` → `internal/todo/` — package renamed, types renamed (Task→Item, Status→State, StatusInProgress `"in-progress"`→`"in_progress"`), sqlc query.sql rewritten, store.go rewritten against new sqlc types
- [x] `internal/journal/` → `internal/agent_note/` — package renamed, Entry→Note, metrics kind dropped, sqlc query.sql rewritten
- [x] `internal/insight/` → `internal/hypothesis/` — package renamed, Insight→Record, Status→State, sqlc query.sql rewritten

## sqlc regeneration

- [x] `sqlc.yaml` updated (old paths removed, todo/agent_note/hypothesis added)
- [x] `sqlc generate` clean — new types: TodoItem, TodoState, AgentNote, AgentNoteKind, Hypothesis, HypothesisState, Agent, AgentStatus, Task, TaskState, TaskMessage, MessageRole, Artifact, AgentScheduleRun, DailyPlanItem, TodoSkip
- [x] Stale types removed: Directive, Report, Insight, InsightStatus, TaskStatus, Journal, JournalKind, Participant, ParticipantSchedule

## Store rewrites (post-sqlc)

- [x] `internal/todo/store.go` — rewritten against db.TodoItem + db.TodoState
- [x] `internal/agent_note/store.go` — rewritten against db.AgentNote + db.NullAgentNoteKind
- [x] `internal/hypothesis/store.go` — rewritten against db.Hypothesis + db.HypothesisState
- [x] `internal/daily/daily.go` + `store.go` — TaskID→TodoItemID, JournalID→AgentNoteID, column family Task*→Todo*
- [x] `internal/learning/store.go` + `learning.go` — Session.JournalID→AgentNoteID

## Caller sweeps

### MCP handlers (`internal/mcp/`)
- [x] `capture.go` — todo.Item / todo.CreateParams
- [x] `commitment.go` — commitDirective stubbed with ErrCoordinationRebuildPending, commitInsight → hypothesis.CreateParams
- [x] `delta.go` — todo.CreatedDetail, todo.CompletedDetail, agent_note.Note
- [x] `execution.go` — todo.Item / todo.State / todo.UpdateParams, daily.TodoItemID/AgentNoteID
- [x] `insight.go` — hypothesis.Record / hypothesis.State, handler names preserved
- [x] `ipc.go` — file_report + acknowledge_directive stubbed with ErrCoordinationRebuildPending
- [x] `journal.go` — agent_note.Note / agent_note.Kind
- [x] `learning.go` — agent_note.Note for reflection entries
- [x] `morning.go` — todo.PendingDetail arrays, directives sections stubbed (empty arrays)
- [x] `reflection.go` — agent_note.Note for today journals
- [x] `server.go` — Server struct: todos / agentNotes / hypotheses / registry; WithRegistry option added
- [x] `weekly.go` — todo.CompletedDetail, agent_note.Note
- [x] `handler_test.go` — file_report / acknowledge_directive test cases updated to expect ErrCoordinationRebuildPending
- [x] `execution_test.go` — todo.State table-driven test rewrite

### admin / consolidation / goal / activity
- [x] `admin/studio.go` — replaced with empty-shell TODO stub (directive board gone)
- [x] `admin/admin.go` — Handler struct: todos / notes / hypotheses fields
- [x] `admin/today.go` — todo.PendingDetail, agent_note.ReflectionsForDate, PendingDirectives count zeroed (TODO)
- [x] `admin/reflect.go` — agent_note + hypothesis, endpoint paths kept for frontend stability
- [x] `admin/history.go` — consolidation.NewPrimaryReader(todos, notes, learn)
- [x] `admin/dashboard.go` — todos.CompletedItemsDetailSince, directive health zeroed (TODO)
- [x] `admin/goals.go` — todos.ItemsByProjectGrouped
- [x] `admin/projects.go` — todos.ItemsByProjectGrouped
- [x] `consolidation/consolidation.go` — PrimaryReader.Todos / Notes
- [x] `consolidation/weekly.go` — agent_note.Note fields, todo.CompletedDetail
- [x] `goal/query.sql` — `task_completed` → `todo_completed` event_type, `tasks t` → `todo_items t`
- [x] `activity/query.sql` — `task_completed` / `task_status_change` → `todo_completed` / `todo_state_change`
- [x] `learning/query.sql` — sessions.journal_id → sessions.agent_note_id

## Wiring + verification

- [x] `cmd/app/main.go` — agent.NewBuiltinRegistry + agent.NewStore + agent.SyncToTable with 10s timeout
- [x] `cmd/mcp/main.go` — same wiring, plus mcp.WithRegistry(agentRegistry) on NewServer
- [x] `go build ./...` clean
- [x] `go vet ./...` clean
- [x] `go test ./...` green across all packages
- [x] `golangci-lint run` on touched packages: 0 issues (pre-existing repo-wide issues untouched)

## sqlc conversion sweep (post-review)

Audit found raw SQL outside `internal/db/` in 4 places. All converted.

- [x] `internal/agent/store.go` — Path X debt — wrote `internal/agent/query.sql` with ListAgents/UpsertAgent/RetireAgent, store now uses generated functions
- [x] `internal/mcp/commitment.go` — single area lookup → added `AreaIDBySlugOrName` to `internal/goal/query.sql`, store method, commitment uses `s.goals.AreaIDBySlugOrName`
- [x] `internal/feed/entry/store.go::CollectionStats` — 2 raw queries with optional WHERE → added `CollectionStatsByFeed` and `CollectionStatsGlobal` using `sqlc.narg`
- [x] `internal/stats/store.go` — 25 raw queries → wrote `internal/stats/query.sql` with `Stats*` prefix to avoid name collisions, store fully converted to generated functions, deleted misleading "Raw SQL is required" header comment
- [x] **Bug fix**: `SystemHealth` was counting `tasks` table (post-rebuild this is coordination tasks, not personal todos). Now counts `todo_items`.
- [x] **Final audit**: zero raw SQL outside `internal/db/` and tests

## Remaining TODO(coordination-rebuild) markers in the tree

Grep for `TODO(coordination-rebuild)` to find these — they all point to this rebuild PR and the follow-up:

- `internal/agent/store.go` — sqlc conversion (Task #13 above)
- `internal/admin/studio.go` — empty-shell studio overview until task.Store exists
- `internal/admin/today.go` — PendingDirectives count zeroed
- `internal/admin/reflect.go` — journal endpoint path stays /reflect/journal (should rename to /reflect/notes after frontend catches up); insights path stays /reflect/insights (should rename to /reflect/hypotheses)
- `internal/admin/dashboard.go` — DirectiveHealth zeroed
- `internal/mcp/server.go` — server struct TODO for *task.Store, *message.Store, *artifact.Store
- `internal/mcp/commitment.go` — commitDirective stub
- `internal/mcp/ipc.go` — file_report + acknowledge_directive stubs
- `internal/mcp/morning.go` — directives sections return empty arrays
- `internal/mcp/handler_test.go` — stubbed tool test cases

## Stage 2 (separate PR) — coordination layer implementation

The entire coordination layer (`internal/task/` + `internal/message/` + `internal/artifact/`) lives in Stage 2 which is NOT in this PR. When Stage 2 lands:

1. The schema is already in place (tasks / task_messages / artifacts tables exist)
2. The agent package is already in place (registry + Authorize)
3. The MCP handler surface is already stable (tool names unchanged)
4. Stage 2 only needs to: implement the three packages, inject their stores into Server, and replace the stubbed handlers (file_report, acknowledge_directive, commitDirective) with real calls that use agent.Authorize followed by task.Store / artifact.Store methods.
