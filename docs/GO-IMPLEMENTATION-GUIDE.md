# Schema v2 — Go Implementation Guide

**Date**: 2026-04-04
**Purpose**: Map every schema entity to its Go package, types, store methods, and MCP tool impact. This is the reference for the Go refactoring phase.

---

## Guiding Principles

1. **Package-by-feature** — each table (or table group) maps to `internal/<feature>/`
2. **sqlc generates** — `internal/db/` is auto-generated, never hand-edited
3. **Store accepts `db.DBTX`** — never `*pgxpool.Pool` directly
4. **Feature types live in `<feature>.go`** — store converts from `db.*` generated types
5. **Handlers are closures** — in `handler.go`, return `http.HandlerFunc`

---

## 1. New Tables → New Packages

### `areas` → `internal/area/`

```
internal/area/
  area.go       — Area struct, sentinel errors
  store.go      — CRUD: Area, Areas, CreateArea, UpdateArea
  query.sql     — sqlc queries
  handler.go    — HTTP handlers (admin CRUD)
```

**Types**:
```go
type Area struct {
    ID          uuid.UUID
    Slug        string
    Name        string
    Description string
    Icon        *string
    SortOrder   int
    CreatedAt   time.Time
    UpdatedAt   time.Time
}
```

**MCP impact**: `goal_progress` and `weekly_summary` filter by `area_id` instead of `area` string. Area resolution: slug → UUID lookup needed.

---

### `milestones` → `internal/milestone/`

```
internal/milestone/
  milestone.go  — Milestone struct, MilestoneProgress helper
  store.go      — CRUD + MilestonesByGoalID, CompleteMilestone
  query.sql     — sqlc queries
```

**Types**:
```go
type Milestone struct {
    ID              uuid.UUID
    Title           string
    Description     string
    GoalID          uuid.UUID
    TargetDeadline  *time.Time  // nullable DATE
    CompletedAt     *time.Time  // NULL = not completed
    NotionPageID    *string
    Position        int
    CreatedAt       time.Time
    UpdatedAt       time.Time
}

// Progress computes goal milestone stats.
type Progress struct {
    Total     int
    Completed int
    Percent   float64  // 0.0-1.0
}
```

**MCP impact**:
- `goal_progress` — add milestone progress display (completed/total)
- `weekly_summary` — add milestone deadline on-track/at-risk analysis
- New tool: `complete_milestone(id)` — sets `completed_at = now()`

---

### `daily_plan_items` → `internal/dailyplan/`

```
internal/dailyplan/
  dailyplan.go  — PlanItem struct, Status constants
  store.go      — CRUD + PlanItemsForDate, UpsertPlanItem, DeferIncomplete, PopulateRecurring
  query.sql     — sqlc queries
  handler.go    — HTTP handlers (if needed)
```

**Types**:
```go
type PlanItem struct {
    ID         uuid.UUID
    PlanDate   time.Time  // DATE
    TaskID     uuid.UUID
    SelectedBy string     // participant name
    Position   int
    Reason     *string
    Status     string     // planned | done | deferred | dropped
    CreatedAt  time.Time
}

const (
    StatusPlanned  = "planned"
    StatusDone     = "done"
    StatusDeferred = "deferred"
    StatusDropped  = "dropped"
)
```

**Key store methods**:
```go
// UpsertPlanItem — INSERT ... ON CONFLICT (plan_date, task_id) DO UPDATE
func (s *Store) UpsertPlanItem(ctx context.Context, p *UpsertParams) (*PlanItem, error)

// DeferIncomplete — cron: planned → deferred for yesterday
func (s *Store) DeferIncomplete(ctx context.Context, date time.Time) (int64, error)

// PopulateRecurring — cron: auto-create items for recurring tasks due today
func (s *Store) PopulateRecurring(ctx context.Context, date time.Time) (int64, error)

// MarkDone — called when task.status → done, sync the plan item
func (s *Store) MarkDone(ctx context.Context, taskID uuid.UUID, date time.Time) error
```

**Cron pipeline rewrite** (`cmd/app/cron.go`):
```
OLD 4-step:                          NEW 3-step:
stepLogIncomplete  ← REMOVE         step1: DeferIncomplete(yesterday)
stepClearMyDay     ← REMOVE                + MarkDone for tasks completed yesterday
stepAdvanceOverdue ← KEEP           step2: stepAdvanceOverdue (unchanged)
stepPopulateMyDay  ← REWRITE        step3: PopulateRecurring(today)
```

**MCP tool changes**:
| Old Tool | New Behavior |
|----------|-------------|
| `my_day` (batch set) | → `batch_daily_plan` — UPSERT daily_plan_items |
| `morning_context` | Read `daily_plan_items WHERE plan_date = today` instead of `tasks.my_day` |
| `reflection_context` | Read `daily_plan_items WHERE plan_date = today`, compare status |
| `save_session_note(kind='plan')` | metadata only needs `{reasoning}`, no `committed_task_ids` |

---

## 2. Modified Tables → Package Changes

### `goals` — `internal/goal/`

| Change | Go Impact |
|--------|-----------|
| `area TEXT` → `area_id UUID FK` | `Goal.Area string` → `Goal.AreaID *uuid.UUID` |
| `status` + `on-hold` | Add `StatusOnHold = "on-hold"` constant |
| Notion sync | `SyncFromNotionInput.Area string` → resolve to `area_id` via area store lookup |
| Comment: milestone advisory | No code change — documentation only |

**Notion sync adapter change** (`internal/goal/notion.go`):
```go
// OLD
type SyncFromNotionInput struct {
    Area string  // raw Notion tag name
}

// NEW — resolve area name to area_id
type SyncFromNotionInput struct {
    AreaName string  // raw from Notion, resolved to area_id by sync layer
}
```

The sync layer (`internal/notion/sync.go`) needs to:
1. Read area name from Notion Tag relation
2. Look up `areas` table by slug or name
3. Pass `area_id` to goal upsert

---

### `projects` — `internal/project/`

| Change | Go Impact |
|--------|-----------|
| `area TEXT` → `area_id UUID FK` | `Project.Area string` → `Project.AreaID *uuid.UUID` |
| Notion sync | Same pattern as goals — resolve area name to area_id |

---

### `tasks` — `internal/task/`

| Change | Go Impact |
|--------|-----------|
| `my_day BOOLEAN` removed | Remove `MyDay bool` from Task struct |
| | Remove `UpdateMyDay`, `ClearAllMyDay`, `MyDayTasks`, `MyDayTasksWithNotionPageID`, `MyDayIncompleteTaskIDs`, `DailySummaryHint` store methods |
| | Remove `MyDaySnapshot`, `MyDayNotionTask` types |
| `status` + `inbox`, `someday` | Add constants `StatusInbox = "inbox"`, `StatusSomeday = "someday"` |
| `created_by` added | Add `CreatedBy string` to Task struct |
| Index changes | No Go impact — DB-level only |

**Removed queries** (from `internal/task/query.sql`):
- `UpdateTaskMyDay`
- `ClearAllMyDay`
- `MyDayTasksWithNotionPageID`
- `DailySummaryHint` (rewrite to use daily_plan_items)
- `MyDayTasks`
- `MyDayIncompleteTaskIDs`

---

### `journal` — `internal/journal/` (was `internal/session/`)

| Change | Go Impact |
|--------|-----------|
| `metadata` comment: no more `committed_task_ids` | Remove validation for `committed_task_ids` in plan type |
| | `save_session_note` validation: plan only needs `reasoning` |
| | `reflection_context`: stop reading `committed_task_ids` from journal, read daily_plan_items instead |

---

### `events` — `internal/activity/`

| Change | Go Impact |
|--------|-----------|
| `my_day_incomplete` removed from enum | Remove `stepLogIncomplete` cron step |
| | Remove any references to `"my_day_incomplete"` event type string |

---

## 3. MCP Tool Migration Map

### Removed Tools

| Tool | Replacement |
|------|------------|
| `my_day` (batch set) | New: `batch_daily_plan` using daily_plan_items UPSERT |

### Modified Tools

| Tool | Change |
|------|--------|
| `morning_context` | `my_day_tasks` section → read from `daily_plan_items WHERE plan_date = today` |
| `reflection_context` | `my_day_status` → read from `daily_plan_items WHERE plan_date = today` |
| `goal_progress` | Add milestone progress section (completed/total per goal) |
| `weekly_summary` | Add milestone deadline tracking + area drift uses area_id FK |
| `save_session_note` | Plan type: remove `committed_task_ids` validation |
| `update_goal_status` | Accept `on-hold` as valid status |
| `search_knowledge` | Area filter: string → area_id resolution |

### New Tools (consider)

| Tool | Purpose |
|------|---------|
| `complete_milestone` | Set milestone.completed_at = now() |
| `list_milestones` | Show milestones for a goal with progress |

---

## 4. Cron Pipeline Rewrite

### Old Pipeline (`cmd/app/cron.go`)

```
step① stepLogIncomplete     — log my_day_incomplete events
step② stepClearMyDay         — sync Notion checkbox false + clear flags
step③ stepAdvanceOverdue     — advance recurring task due dates
step④ stepPopulateMyDay      — set my_day=true for recurring tasks due today
```

### New Pipeline

```
step① DeferAndReconcile     — for yesterday's planned items:
                               - task.status = 'done' → plan_item.status = 'done'
                               - else → plan_item.status = 'deferred'
step② stepAdvanceOverdue     — unchanged
step③ PopulateRecurring      — create daily_plan_items for recurring tasks due today
                               (selected_by = 'hq', status = 'planned')
step④ SyncNotionCheckbox     — based on daily_plan_items WHERE plan_date = today
                               (optional, may be deferred)
```

---

## 5. Notion Sync Layer Changes

### Area Resolution

Both goal and project sync need area name → area_id resolution:

```go
// In internal/notion/sync.go
func (s *Syncer) resolveAreaID(ctx context.Context, areaName string) (*uuid.UUID, error) {
    if areaName == "" {
        return nil, nil
    }
    slug := slugify(areaName)  // "Backend" → "backend"
    area, err := s.areaStore.AreaBySlug(ctx, slug)
    if err != nil {
        // Area not found — create it? Or return nil and log?
        return nil, nil
    }
    return &area.ID, nil
}
```

**Decision needed**: auto-create areas from Notion sync, or require manual setup?

### My Day Sync Removal

Remove all Notion "My Day" checkbox sync code:
- `syncMyDayToNotion()` in `internal/mcp/write.go`
- Notion checkbox sync in cron steps
- Replace with daily_plan_items-based sync (if keeping Notion checkbox feature)

---

## 6. Package Dependency Map

```
internal/area/          ← new, no deps
internal/milestone/     ← new, imports goal types only
internal/dailyplan/     ← new, imports task types only
internal/goal/          ← modified: area_id FK, on-hold status
internal/project/       ← modified: area_id FK
internal/task/          ← modified: remove my_day, add inbox/someday/created_by
internal/mcp/           ← modified: all MCP tool changes
cmd/app/cron.go         ← modified: pipeline rewrite
internal/notion/sync.go ← modified: area resolution
```

---

## 7. Learning Analytics — Implementation Context

> **Note**: `internal/learning/` currently exists and may be refactored. This section describes **what the schema expects from Go**, not specific package structure. Refer to `001_initial.up.sql` lines 1151–1644 for the authoritative DDL.

### 7.1 Entity Semantics and Store Operations

#### `concepts` (DDL line ~1174)

**What it is**: Learning ontology — pattern/skill/principle. Independent from `tags`. Optional `tag_id` bridges to content classification.

**Key store operations needed**:
- Lookup by `(domain, slug)` — the unique key (case-insensitive via `idx_concepts_domain_slug`)
- List by domain + kind filter (`idx_concepts_domain_kind`)
- Tree traversal via `parent_id` (single-level for now, recursive CTE if depth grows)
- Upsert: coaching prompt creates concepts on first encounter

**Go-enforced invariants** (not in DDL):
- `domain` value set: validate against a shared constant set (same set across concepts, learning_items, learning_sessions)
- `parent_id` same-domain: parent and child must share `domain` — cross-domain parenting is a data quality error
- Acyclicity: no concept can be its own ancestor via `parent_id` chain

**Concept merge procedure** (needed when taxonomy stabilizes):
```
1. UPDATE attempt_observations SET concept_id = :surviving WHERE concept_id = :old
2. UPDATE learning_item_concepts SET concept_id = :surviving WHERE concept_id = :old
   (handle duplicate PK: ON CONFLICT DELETE the old row)
3. DELETE FROM concepts WHERE id = :old
   (RESTRICT on attempt_observations enforces step 1 happened first)
```

---

#### `learning_items` (DDL line ~1241)

**What it is**: Learning targets — things to practice/revisit. Independent from `notes` (different lifecycle). A LeetCode problem exists as a learning_item before a solve note is written.

**Key store operations needed**:
- Lookup by `(domain, external_id)` — partial unique index, the natural dedup key
- List by domain with optional project filter
- Upsert from coaching prompt: find-or-create by `(domain, external_id)`
- "Unattempted items" query: `LEFT JOIN attempts ... WHERE attempts.id IS NULL`

**Backfill from existing data**: Existing `notes` rows with `leetcode_id IS NOT NULL` contain learning item identity. One-time backfill:
```sql
INSERT INTO learning_items (domain, title, external_id, difficulty, note_id)
SELECT 'leetcode', n.title, n.leetcode_id::text, n.difficulty, n.id
FROM notes n
WHERE n.leetcode_id IS NOT NULL
ON CONFLICT (domain, external_id) WHERE external_id IS NOT NULL DO UPDATE
SET note_id = EXCLUDED.note_id;
```

**`metadata` JSONB structure** (not queryable — promote to column if needed later):
- LeetCode: `{problem_url, companies, frequency, constraints}`
- Japanese: `{jlpt_level, textbook, chapter, grammar_point}`
- System Design: `{source_book, chapter, scenario_type}`
- Reading: `{book_title, chapter, page_range}`

---

#### `learning_item_concepts` (DDL line ~1383)

**What it is**: Junction — which concepts an item exercises. Has `relevance` (primary/secondary) and `created_at`.

**Convention**: One primary per item. Multiple primaries should be rare. Not DDL-enforced — validate in Go if strictness is needed later.

**Population**: Written by coaching prompt during post-session analysis. Not manual.

---

#### `learning_sessions` (DDL line ~1413)

**What it is**: Orchestration boundary — explicit start/end, mode, and attempt container. Distinct from `journal` (post-hoc reflection). The session produces a journal entry, not the other way around.

**Session lifecycle** (the primary write path):
```
1. CREATE learning_session (domain, session_mode, started_at=now())
   → optional: link to daily_plan_item_id if this session was planned
2. For each problem/item in the session:
   a. Find-or-create learning_item by (domain, external_id)
   b. INSERT attempt (learning_item_id, session_id, outcome, duration, ...)
      → attempt_number = MAX(attempt_number) + 1 for this item
   c. INSERT attempt_observations (attempt_id, concept_id, signal_type, category, ...)
      → multiple observations per attempt (granularity matters)
3. UPDATE learning_session SET ended_at = now()
   → optional: create journal(kind='reflection') entry, set journal_id
```

**Session modes**:
| Mode | When | Typical domain |
|------|------|---------------|
| `retrieval` | Recall-based testing, no hints | LeetCode, flashcards |
| `practice` | Active problem-solving with coaching | LeetCode, grammar drills |
| `mixed` | Combination | Mixed sessions |
| `review` | Revisiting previously solved items | Any |
| `reading` | Comprehension-focused | DDIA, literary texts, O'Reilly |

**No `updated_at`**: Write-once-then-close. Only `ended_at` and `metadata` are set at session completion.

---

#### `attempts` (DDL line ~1477)

**What it is**: Individual attempt records. Append-only, no `updated_at`.

**`attempt_number` computation**: Application must compute `MAX(attempt_number) + 1` before INSERT. `DEFAULT 1` only applies to genuinely first attempts. The `UNIQUE (learning_item_id, attempt_number)` constraint catches bugs (safe failure mode — retry with correct number).

**Outcome paradigms** (MCP tool layer maps domain context to the right paradigm):
| Paradigm | Values | Domains |
|----------|--------|---------|
| Problem-solving | `solved_independent`, `solved_with_hint`, `solved_after_solution` | LeetCode, grammar drills |
| Immersive | `completed`, `completed_with_support` | Reading, listening, literary analysis |
| Shared | `incomplete`, `gave_up` | Any |

**`metadata` JSONB**: Coaching hints, alternative approaches, code quality observations, LLM transcript excerpts. Not queryable.

---

#### `attempt_observations` (DDL line ~1549)

**What it is**: The heart of learning analytics. Micro-cognitive signals connecting an attempt to a concept. Append-only.

**Signal types**:
| Type | Meaning | Severity applies? |
|------|---------|-------------------|
| `weakness` | Something went wrong | Yes: minor/moderate/critical |
| `improvement` | Progress vs previous attempts | No (NULL) |
| `mastery` | Independent, fluent application | No (NULL) |

**`category`**: Go-validated, not DB ENUM. Expands across domains:
- LeetCode: `pattern-recognition`, `constraint-analysis`, `edge-cases`, `implementation`, `complexity-analysis`, `approach-selection`
- Japanese: `conjugation-accuracy`, `particle-selection`, `listening-comprehension`, `vocabulary-recall`
- System Design: `tradeoff-analysis`, `bottleneck-diagnosis`, `capacity-estimation`

**RESTRICT on concept_id**: Cannot delete a concept that has observations. See concept merge procedure above.

**Observation quality is the critical path**: The entire learning analytics system's value depends on coaching prompts producing accurate, granular observations. Validate with 10-20 real sessions before trusting aggregate analytics.

---

#### `item_relations` (DDL line ~1604)

**What it is**: Directed graph of learning item relationships. Append-only.

**Direction convention**: Source is the reference point. `(source=42, target=167, easier_variant)` = "167 is an easier variant of 42."

**Go-enforced invariants**:
- Same-domain: both items must share `domain`
- No contradictory pairs: same ordered pair cannot have both `easier_variant` and `harder_variant`
- No symmetric conflicts: `(A→B, prerequisite)` and `(B→A, prerequisite)` cannot coexist

**Population strategy**: Post-session analysis by coaching prompt, not manual backfill. Flow:
1. Observe weakness signal on item X
2. Query `learning_item_concepts` for items sharing the same primary concept
3. Filter by difficulty (find easier items for same pattern)
4. Suggest relation, write to `item_relations`

---

#### `review_cards` modification (DDL line ~1308)

**What changed**: Unified FSRS target — `content_id OR learning_item_id`, exactly one (enforced by `chk_review_target_exactly_one`).

**Go impact on existing `internal/retrieval/`**:
- `DueItem` struct needs a `LearningItemID` field (nullable, mutually exclusive with `ContentID`)
- FSRS engine (`Review` function) is unchanged — it only touches `card_state` + `rating`
- New queries needed: create/query review cards by `learning_item_id`
- `retrieval_queue` MCP tool: return both content-based and item-based due cards

**`tag_id` only for content cards**: `chk_tag_requires_content` enforces this. Item-based cards use `learning_item_concepts` for concept associations instead.

---

### 7.2 Domain Validation — Shared Constant Set

Three tables share the `domain` vocabulary: `concepts`, `learning_items`, `learning_sessions`. DDL enforces format (`lower(btrim(domain)) AND domain <> ''`), Go enforces the value set:

```go
// Shared across concept, learning item, and session validation.
var ValidDomains = map[string]bool{
    "leetcode":       true,
    "japanese":       true,
    "system-design":  true,
    "go":             true,
    "english":        true,
    "reading":        true,
}
```

New domains: add to this map. No DB migration needed.

---

### 7.3 MCP Tool Impact

#### Modified tools

| Tool | Change |
|------|--------|
| `log_learning_session` | Rewrite: create session → attempts → observations (full write path from §7.1) |
| `retrieval_queue` | Include learning-item-based review cards alongside content-based cards |
| `log_retrieval_attempt` | Support both content-based and item-based card rating |

#### Existing analytics tools (currently compute from JSONB tags — will migrate to new tables)

| Tool | Current source | New source |
|------|---------------|------------|
| `mastery_map` | `content.RichTagEntry` JSONB | `attempt_observations` aggregation by concept |
| `concept_gaps` | JSONB `concept_breakdown` in metadata | `attempt_observations WHERE signal_type = 'weakness'` GROUP BY concept |
| `variation_map` | JSONB `variation_links` in metadata | `item_relations` table |
| `coverage_matrix` | Tag entries with `ai_metadata` | `attempts` + `learning_item_concepts` aggregation |
| `weakness_trend` | JSONB extraction | `attempt_observations` time-windowed by concept |

#### New tools to consider

| Tool | Purpose | Query path |
|------|---------|------------|
| `create_concept` | Seed concept ontology | Direct INSERT to `concepts` |
| `link_item_concepts` | Associate items with concepts | INSERT to `learning_item_concepts` |
| `suggest_relation` | Coaching prompt suggests item relation | INSERT to `item_relations` with validation |
| `concept_tree` | Browse concept hierarchy | Recursive CTE on `concepts.parent_id` |
| `unattempted_items` | Items never attempted for a domain | Anti-join `learning_items LEFT JOIN attempts` |

---

### 7.4 Key Queries (reference — see DDL §8 for full SQL)

| Query | Join path | Primary index |
|-------|-----------|--------------|
| Weakness overview (time-windowed) | `concepts ← attempt_observations ← attempts` | `idx_attempt_observations_concept_signal` + `idx_attempts_date` |
| Drill-down by concept | `attempt_observations → attempts → learning_items` | `idx_attempt_observations_concept_signal` |
| Progression timeline | Same as weakness overview + `date_trunc` | Same |
| Next-item recommendation | `learning_item_concepts → item_relations` | `idx_learning_item_concepts_concept` + `idx_item_relations_source` |
| Revisit history | `attempts WHERE learning_item_id = X` | `idx_attempts_item_number` |
| Session summary | `attempts WHERE session_id = X` | `idx_attempts_session` |
| Unattempted items | `learning_items LEFT JOIN attempts` | `idx_attempts_item_date` |

---

### 7.5 Migration from JSONB to First-Class Tables

The existing `internal/learning/` package computes analytics from `content.RichTagEntry` JSONB fields (`ai_metadata.concept_breakdown`, `ai_metadata.variation_links`, etc.). The new tables replace this:

| JSONB field | Replaced by | Migration path |
|-------------|------------|---------------|
| `ai_metadata.concept_breakdown[]` | `attempt_observations` | New sessions write to tables; old data stays in JSONB until backfilled |
| `ai_metadata.variation_links[]` | `item_relations` | Post-session analysis writes to table |
| `ai_metadata.solve_context.stuck_points[]` | `attempts.stuck_at` + `attempts.metadata` | Direct mapping |
| `ai_metadata.alternative_approaches[]` | `attempts.metadata` | Stays in JSONB (narrative, not queryable) |
| Tag-based result tracking (`ac-independent`, etc.) | `attempts.outcome` | Enum mapping: `ac-independent → solved_independent`, etc. |
| Tag-based topic tracking (`two-pointers`, etc.) | `learning_item_concepts.concept_id` | Concept lookup by slug |

**Dual-read period**: During migration, MCP tools may need to read from both JSONB (old data) and tables (new data). Keep the existing JSONB computation code until backfill is complete.

---

## 8. Implementation Order (Updated)

| Step | What | Depends On |
|------|------|-----------|
| 1 | Write query.sql for area, milestone, dailyplan | Schema applied |
| 2 | `sqlc generate` | Step 1 |
| 3 | `internal/area/` — types + store | Step 2 |
| 4 | `internal/milestone/` — types + store | Step 2 |
| 5 | `internal/dailyplan/` — types + store | Step 2 |
| 6 | Modify `internal/goal/` — area_id, on-hold | Step 3 (area store) |
| 7 | Modify `internal/project/` — area_id | Step 3 (area store) |
| 8 | Modify `internal/task/` — remove my_day, add inbox/someday/created_by | Step 2 |
| 9 | Modify `internal/notion/sync.go` — area resolution | Steps 3, 6, 7 |
| 10 | Modify `internal/mcp/` — base schema tool changes | Steps 3-8 |
| 11 | Rewrite `cmd/app/cron.go` — pipeline | Steps 5, 8 |
| 12 | Learning analytics: concept + learning_item store operations | Step 2 |
| 13 | Learning analytics: session + attempt + observation write path | Step 12 |
| 14 | Learning analytics: item_relations store + validation | Step 12 |
| 15 | Modify `internal/retrieval/` — unified review_cards target | Step 12 |
| 16 | Migrate MCP analytics tools from JSONB to table queries | Steps 12-14 |
| 17 | Backfill existing notes → learning_items | Step 12 |
| 18 | Tests | All above |

| Step | What | Depends On |
|------|------|-----------|
| 1 | Write query.sql for area, milestone, dailyplan | Schema applied |
| 2 | `sqlc generate` | Step 1 |
| 3 | `internal/area/` — types + store | Step 2 |
| 4 | `internal/milestone/` — types + store | Step 2 |
| 5 | `internal/dailyplan/` — types + store | Step 2 |
| 6 | Modify `internal/goal/` — area_id, on-hold | Step 3 (area store) |
| 7 | Modify `internal/project/` — area_id | Step 3 (area store) |
| 8 | Modify `internal/task/` — remove my_day, add inbox/someday/created_by | Step 2 |
| 9 | Modify `internal/notion/sync.go` — area resolution | Steps 3, 6, 7 |
| 10 | Modify `internal/mcp/` — all tool changes | Steps 3-8 |
| 11 | Rewrite `cmd/app/cron.go` — pipeline | Steps 5, 8 |
| 12 | Tests | All above |
