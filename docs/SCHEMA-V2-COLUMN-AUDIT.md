# Schema v2 — Column-by-Column Semantic Audit

**Date**: 2026-04-04
**Auditors**: 3 parallel agents (Opus 4.6), synthesized by main orchestrator
**Scope**: 40 tables (base v2), 2 views, 11 enums — every column reviewed
**v2.1 Note**: 7 learning analytics tables added after this audit (concepts, learning_items, learning_item_concepts, learning_sessions, attempts, attempt_observations, item_relations) + review_cards modified. See `docs/LEARNING-ANALYTICS-SCHEMA-DESIGN.md` for full column-level documentation. New tables have complete COMMENT ON for every column in the migration.
**Migration**: `migrations/001_initial.up.sql`

---

## Audit Summary

| Severity | Count | Description |
|----------|-------|-------------|
| Must-fix (constraint/integrity) | 12 | Missing CHECKs, FK behavior bugs, missing COMMENTs on domain columns |
| Naming debt | 4 | Legacy names carried into v2 clean slate |
| Observability offload | 2 | Tables better served by Loki/Prometheus/Grafana |
| Acknowledged debt | 8 | Known trade-offs, documented, not blocking |

---

## 1. Must-Fix: Constraint & Integrity Issues

### 1.1 `review_cards.tag_id` — ON DELETE SET NULL causes unique violation

**Table**: `review_cards` (line ~1065)
**Column**: `tag_id UUID REFERENCES tags(id) ON DELETE SET NULL`

**Bug**: Two partial unique indexes exist:
- `idx_review_cards_whole` — `UNIQUE(content_id) WHERE tag_id IS NULL`
- `idx_review_cards_tagged` — `UNIQUE(content_id, tag_id) WHERE tag_id IS NOT NULL`

If a tag is deleted, SET NULL changes `tag_id` to NULL. If a whole-content card already exists for that `content_id`, the SET NULL violates `idx_review_cards_whole` and the DELETE fails with a unique constraint error.

**Fix**: Change to `ON DELETE CASCADE`. Deleting a tag should remove the per-concept card.

**v2.1 Update**: `review_cards` was modified — `content_id` is now nullable (was NOT NULL), `learning_item_id` added, one-of CHECK `chk_review_target_exactly_one`. Content-based partial unique indexes now include `WHERE content_id IS NOT NULL`. The `tag_id` ON DELETE bug is **resolved** — current migration shows `ON DELETE CASCADE`.

### 1.2 Missing pair-consistency CHECKs (6 instances)

| Table | Column pair | Missing constraint |
|-------|------------|-------------------|
| `tag_aliases` | `confirmed` / `confirmed_at` | `CHECK ((confirmed = false AND confirmed_at IS NULL) OR (confirmed = true AND confirmed_at IS NOT NULL))` |
| `feeds` | `enabled` / `disabled_reason` | `CHECK (enabled = true AND disabled_reason IS NULL) OR (enabled = false)` |
| `feed_entries` | `user_feedback` / `feedback_at` | `CHECK ((user_feedback IS NULL) = (feedback_at IS NULL))` |
| `flow_runs` | `status` / `error` | `CHECK ((status = 'failed') = (error IS NOT NULL))` |
| `notes` | `chapter` / `book` | `CHECK (chapter IS NULL OR book IS NOT NULL)` |
| `review_queue` | `status` / `reviewed_at` | `CHECK (status IN ('pending') OR reviewed_at IS NOT NULL)` |

### 1.3 Missing range CHECKs (4 instances)

| Table | Column | Missing |
|-------|--------|---------|
| `contents` | `reading_time_min` | `CHECK (reading_time_min >= 0)` |
| `review_logs` | `scheduled_days` | `CHECK (scheduled_days >= 0)` |
| `review_logs` | `elapsed_days` | `CHECK (elapsed_days >= 0)` |
| `flow_runs` | `max_attempts` | `CHECK (max_attempts > 0)` |

### 1.4 Missing COMMENT ON COLUMN (critical columns only)

These are domain columns where the semantic purpose is non-obvious. Junction table FKs and standard `created_at`/`updated_at` are excluded.

| Table | Column | What the comment should say |
|-------|--------|-----------------------------|
| `contents` | `cover_image` | Cover image URL or path for content cards. NULL = no cover. |
| `review_logs` | `scheduled_days` | Days the FSRS algorithm scheduled until next review. |
| `review_logs` | `elapsed_days` | Actual days elapsed since previous review. |
| `insights` | `content` | Full narrative context for the insight. `hypothesis` is the one-line prediction; `content` is the supporting analysis. |
| `sources` | `sync_mode` | Missing CHECK — add `CHECK (sync_mode IN ('full', 'incremental'))` |

---

## 2. Naming Debt

### 2.1 `note_date` — legacy name on 4 tables

| Table | Current | Better name | Semantics |
|-------|---------|-------------|-----------|
| `directives` | `note_date` | `issued_date` | Date directive was issued |
| `reports` | `note_date` | `reported_date` | Date report was filed |
| `journal` | `note_date` | `entry_date` | Date of journal entry |
| `insights` | `note_date` | `observed_date` | Date insight was recorded |

All four comments say "inherited naming from session_notes lineage." This is a v2 clean-slate schema — the lineage no longer needs to be carried.

**Recommendation**: Rename all four in one migration. Or keep and accept as known debt.

### 2.2 `source` naming collision

Three different meanings across the schema:

| Location | Meaning |
|----------|---------|
| `notes.source` | Knowledge provenance (leetcode, claude, oreilly) |
| `sources` table | External sync configuration |
| `events.source` | Origin system name (github, notion, cron) |

Not blocking — but every new developer will be confused.

### 2.3 `topic_monitors.sources` vs `sources` table

Column name `sources` on `topic_monitors` (monitor URLs/domains to watch) collides with the `sources` table (sync config). Consider `watch_domains` or `monitor_urls`.

### 2.4 `feeds.schedule` vs `topic_monitors.schedule`

Same column name, different formats: `feeds.schedule` = human-readable ("daily", "weekly"), `topic_monitors.schedule` = cron expression ("0 */6 * * *"). Neither has a CHECK constraint. Confusing.

---

## 3. Observability Offload Recommendations

### 3.1 `tool_call_logs` + 2 views — REMOVE

**Verdict**: Replace with Loki structured logging + Prometheus metrics.

| Factor | Assessment |
|--------|-----------|
| FK dependencies | Zero — nothing references this table |
| Growth | Unbounded append-only, no retention policy |
| Query patterns | The 2 views are trivially replaced by Grafana panels |
| What you'd lose | Ad-hoc SQL aggregation (percentile_cont, custom GROUP BY) |
| What you'd gain | Native alerting, retention policies, Grafana dashboards, no schema migrations for new dimensions |

**Specific concerns**:
- `tool_usage_summary` view scans ALL historical data with no time bound — will degrade as table grows
- `tool_daily_trend` view lacks per-tool breakdown — limited diagnostic value
- UUID PK is wasteful for telemetry (16 bytes vs 8 for BIGSERIAL)

**Action**: Remove `tool_call_logs`, `tool_usage_summary`, `tool_daily_trend` from migration. Emit structured log lines from Go MCP handler middleware instead. Tables: 40 → 37 (+ drop 2 views).

### 3.2 `flow_runs` — ADD RETENTION POLICY

**Verdict**: Keep the table (retry logic is operational state), but add retention.

The `input` and `output` JSONB columns store full AI payloads that are heavy and rarely queried after completion. The table will grow with every pipeline invocation.

**Action**: Document a cron-based retention strategy in the table comment:
> Completed/failed runs older than 90 days should be archived or deleted by retention cron.

### 3.3 `reconcile_runs` — KEEP

52 rows/year. Schema surface cost is negligible. MCP `system_status` tool reads this. Keep as-is.

### 3.4 `schedule_runs` — KEEP

FK to `participant_schedules` is load-bearing. Relational queries ("which schedule has the worst failure rate?") are genuine needs. Supplement with Prometheus metrics for alerting if desired.

---

## 4. Acknowledged Debt (not blocking, documented)

| # | Issue | Table | Why it's acceptable |
|---|-------|-------|-------------------|
| 1 | TEXT PK (natural key) | platform, participant | 4+8 rows, rename-unlikely, simplifies FK readability |
| 2 | 24 columns (mixed concerns) | projects | Case study + operational in one table. Splitting adds join cost for no query benefit at current scale |
| 3 | Kitchen-sink design | notes | Type-specific columns (leetcode_id, difficulty, book, chapter) on generic table. Works but carries debt from obsidian_notes origins |
| 4 | BIGSERIAL vs UUID inconsistency | notes, events | Legacy ID scheme. Functional but causes type friction in Go stores |
| 5 | `contents.source_type` nullable ambiguity | contents | NULL vs 'manual' mean the same thing. Not harmful but not clean |
| 6 | `directives.acknowledged_by` redundant | directives | Always equals `target` per CHECK. Zero information gain. Exists for audit trail explicitness |
| 7 | JSONB promotion candidates | directives, reports, insights | `deadline`, `correlation_id`, `follow_up_needed`, `project`, `category` buried in JSONB metadata. Should be columns if queried. Defer until query patterns are proven |
| 8 | `goals.quarter` free-form TEXT | goals | No CHECK pattern for "Q1 2026" format. Values come from Notion. Low risk at current cardinality |

---

## 5. Missing `updated_at` Columns

| Table | Has `updated_at`? | Mutable? |
|-------|-------------------|----------|
| platform | ❌ | `description` is mutable |
| participant | ❌ | 5 capability flags are mutable |
| tag_aliases | ❌ | `tag_id`, `confirmed`, `match_method` are mutable |
| daily_plan_items | ❌ | `status` transitions are the primary mutation |
| feed_entries | ❌ | `status` transitions (unread → curated) |

**Recommendation**: Add `updated_at` to `daily_plan_items` (status transitions are the core use case and need timestamps). The others are lower priority.

---

## 6. Per-Table Verdict Summary

| # | Table | Verdict | Key Issues |
|---|-------|---------|-----------|
| 1 | platform | ✅ clean | Missing updated_at (minor) |
| 2 | participant | ✅ clean | Missing updated_at (minor) |
| 3 | users | ✅ clean | `role` column is self-documented dead weight |
| 4 | refresh_tokens | ✅ clean | — |
| 5 | topics | ✅ clean | — |
| 6 | tags | ✅ clean | `parent_id SET NULL` silently orphans (documented) |
| 7 | tag_aliases | ⚠️ fix | Missing confirmed/confirmed_at CHECK |
| 8 | areas | ✅ clean | — |
| 9 | goals | ✅ clean | `quarter` free-form (accepted) |
| 10 | milestones | ✅ clean | DATE vs TIMESTAMPTZ minor inconsistency |
| 11 | projects | ✅ clean | 24 columns, `github_url`/`repo` overlap (accepted) |
| 12 | contents | ⚠️ fix | Missing reading_time_min CHECK, cover_image COMMENT |
| 13 | content_topics | ✅ clean | — |
| 14 | content_tags | ✅ clean | Missing TABLE COMMENT (minor) |
| 15 | review_queue | ⚠️ fix | Missing reviewed_at/status CHECK |
| 16 | feeds | ⚠️ fix | Missing enabled/disabled_reason CHECK, schedule CHECK |
| 17 | feed_topics | ✅ clean | — |
| 18 | feed_entries | ⚠️ fix | Missing feedback pair CHECK, no updated_at |
| 19 | topic_monitors | ✅ clean | `sources` naming collision (minor) |
| 20 | flow_runs | ⚠️ fix | Missing error/status CHECK, needs retention comment |
| 21 | tasks | ✅ clean | — |
| 22 | daily_plan_items | ⚠️ fix | Missing updated_at for status transitions |
| 23 | task_skips | ✅ clean | `original_due`/`skipped_date` semantic overlap (minor) |
| 24 | sources | ⚠️ fix | Missing sync_mode CHECK |
| 25 | notes | ⚠️ debt | Kitchen-sink, BIGSERIAL, source naming, notion_task_id |
| 26 | note_tags | ✅ clean | — |
| 27 | note_links | ✅ clean | Soft reference by design |
| 28 | events | ⚠️ debt | source naming collision, soft project ref |
| 29 | event_tags | ✅ clean | Missing TABLE COMMENT (minor) |
| 30 | project_aliases | ⚠️ fix | Case-sensitivity mismatch UNIQUE vs index |
| 31 | directives | ⚠️ debt | note_date naming, acknowledged_by redundant, JSONB candidates |
| 32 | reports | ⚠️ debt | note_date naming, follow_up_needed in JSONB |
| 33 | journal | ✅ clean | note_date naming (minor) |
| 34 | insights | ⚠️ debt | content/hypothesis ambiguity, JSONB candidates |
| 35 | review_cards | ✅ fixed | tag_id now CASCADE. v2.1: content_id nullable, learning_item_id added, one-of CHECK |
| 36 | review_logs | ⚠️ fix | Missing scheduled_days/elapsed_days CHECKs + COMMENTs |
| 37 | tool_call_logs | ❌ remove | Observability offload candidate |
| 38 | reconcile_runs | ✅ keep | 52 rows/year, naming inconsistency (minor) |
| 39 | participant_schedules | ✅ clean | expected_outputs TEXT[] (accepted) |
| 40 | schedule_runs | ✅ clean | created_at/started_at redundancy (minor) |
| 41 | concepts | ✅ v2.1 | Full COMMENT ON coverage. See LEARNING-ANALYTICS-SCHEMA-DESIGN.md |
| 42 | learning_items | ✅ v2.1 | Full COMMENT ON coverage |
| 43 | learning_item_concepts | ✅ v2.1 | Junction table, full comments |
| 44 | learning_sessions | ✅ v2.1 | No participant column (documented trade-off) |
| 45 | attempts | ✅ v2.1 | Two outcome paradigms (problem-solving + immersive) |
| 46 | attempt_observations | ✅ v2.1 | category is Go-validated TEXT, not ENUM (deliberate) |
| 47 | item_relations | ✅ v2.1 | Direction semantics documented in table comment |
