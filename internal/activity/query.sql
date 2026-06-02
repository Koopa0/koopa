-- Copyright 2026 Koopa. All rights reserved.

-- name: EventsByTimeRange :many
-- List activity events within a time range, ordered by timestamp descending.
-- Sources exclusively from activity_events (internal entity state changes
-- written by AFTER triggers on covered tables). Hard cap prevents unbounded
-- result sets from wide time ranges. entity_title is the write-time snapshot
-- so a hard-deleted entity still renders meaningfully in the feed. actor is
-- the agent that caused the change (schema-mandatory NOT NULL) — exposed so
-- per-agent audit / timelines can attribute changes without a second JOIN.
SELECT a.id,
       a.entity_id::text AS entity_id,
       a.occurred_at     AS timestamp,
       a.change_kind,
       a.entity_type,
       a.actor,
       p.slug            AS project,
       a.entity_title    AS title,
       a.payload         AS metadata,
       a.created_at
FROM activity_events a
LEFT JOIN projects p ON p.id = a.project_id
WHERE a.occurred_at >= @start_time AND a.occurred_at < @end_time
ORDER BY a.occurred_at DESC
LIMIT 5000;

-- name: EventsByFilters :many
-- List activity events within a time range with optional entity_type, project,
-- and actor filters. entity_type matches activity_events.entity_type; project
-- matches the joined projects.slug; actors is a multi-value allowlist matching
-- activity_events.actor (NULL/empty → all actors). actor projection mirrors
-- EventsByTimeRange.
SELECT a.id,
       a.entity_id::text AS entity_id,
       a.occurred_at     AS timestamp,
       a.change_kind,
       a.entity_type,
       a.actor,
       p.slug            AS project,
       a.entity_title    AS title,
       a.payload         AS metadata,
       a.created_at
FROM activity_events a
LEFT JOIN projects p ON p.id = a.project_id
WHERE a.occurred_at >= @start_time AND a.occurred_at < @end_time
  AND (sqlc.narg('filter_entity_type')::text IS NULL OR a.entity_type = sqlc.narg('filter_entity_type'))
  AND (sqlc.narg('filter_project')::text IS NULL OR p.slug = sqlc.narg('filter_project'))
  AND (sqlc.narg('filter_actors')::text[] IS NULL OR a.actor = ANY(sqlc.narg('filter_actors')::text[]))
ORDER BY a.occurred_at DESC
LIMIT @max_results;

-- name: SelfAuditLearningPlanForceCount :one
-- Counts force-mode plan-entry completions in [start, end). The
-- 'manual override:' reason prefix is the audit signal for force=true
-- completions per mcp-decision-policy.md §13: the prefix is required by
-- validateCompleteEntryReason (internal/mcp/plan.go) and stamped into
-- activity_events.payload.reason by the audit_learning_plan_entries
-- trigger. Used by weekly_summary.self_audit to verify whether the
-- force-mode escape hatch is being used routinely (it should not be).
SELECT COUNT(*)::bigint AS count
FROM activity_events
WHERE entity_type = 'learning_plan_entry'
  AND change_kind = 'completed'
  AND COALESCE(payload->>'reason', '') LIKE 'manual override:%'
  AND occurred_at >= @start_at
  AND occurred_at < @end_at;

-- name: SelfAuditLearningPlanSkippedHistogram :many
-- Skipped-entry counts grouped by the normalized text AFTER the
-- 'skipped:' convention prefix in payload->>'reason'.
--
-- Bucketing contract (must stay in sync with the SelfAudit docstring
-- and the ops catalog WeeklySummary description):
--   - Reason matching '^skipped:\s*<text>' → prefix is <text> trimmed.
--     Example: 'skipped: solved offline' → 'solved offline'.
--   - Reason that does NOT start with 'skipped:' → 'unclassified'.
--   - Reason that is empty, NULL, or only whitespace after the
--     'skipped:' prefix → 'unclassified'.
--
-- This deliberately collapses non-conforming reasons into a single
-- 'unclassified' bucket so the histogram reports the rate of
-- convention adherence as a side effect. It does NOT collapse all
-- conforming reasons into 'skipped' — that bug shipped in the first
-- draft of CF-08 P0 (split_part-before-colon) and was caught in
-- review before push.
--
-- 'skipped:' is 8 characters; SUBSTRING(... FROM 9) skips it. TRIM
-- removes any whitespace between the prefix and the category text so
-- 'skipped: foo' and 'skipped:foo' bucket identically.
--
-- audit_learning_plan_entries records change_kind='state_changed' (not
-- 'completed') for status='skipped'; pairing change_kind='state_changed'
-- with payload->>'to'='skipped' is the unique trigger signature for a
-- skip transition.
SELECT
    CASE
        WHEN payload->>'reason' LIKE 'skipped:%' THEN
            COALESCE(NULLIF(TRIM(SUBSTRING(payload->>'reason' FROM 9)), ''), 'unclassified')
        ELSE 'unclassified'
    END::text AS prefix,
    COUNT(*)::bigint AS count
FROM activity_events
WHERE entity_type = 'learning_plan_entry'
  AND change_kind = 'state_changed'
  AND payload->>'to' = 'skipped'
  AND occurred_at >= @start_at
  AND occurred_at < @end_at
GROUP BY prefix
ORDER BY count DESC, prefix ASC;
