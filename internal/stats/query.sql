-- Copyright 2026 Koopa. All rights reserved.

-- Stats package queries. All cross-table aggregation for the admin
-- dashboard lives here. Names are prefixed `Stats` to avoid collision
-- with feature-package queries in the shared sqlc namespace.

-- name: StatsContentsByStatusType :many
SELECT status::text AS status, type::text AS type, COUNT(*)::int AS count
FROM contents
GROUP BY status, type;

-- name: StatsFeedEntriesByStatus :many
SELECT status::text AS status, COUNT(*)::int AS count
FROM feed_entries
GROUP BY status;

-- name: StatsFeedCounts :one
SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE enabled)::int AS enabled
FROM feeds;

-- name: StatsProcessRunsByStatus :many
-- Count process_runs grouped by status within a single kind
-- (one of: crawl, agent_schedule).
SELECT status::text AS status, COUNT(*)::int AS count
FROM process_runs
WHERE kind = @kind::text
GROUP BY status;

-- name: StatsProjectsByStatus :many
SELECT status::text AS status, COUNT(*)::int AS count
FROM projects
GROUP BY status;

-- name: StatsActivityWindow :one
-- Activity counts across all internal entity state changes.
SELECT COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE occurred_at > now() - interval '24 hours')::int AS last_24h,
       COUNT(*) FILTER (WHERE occurred_at > now() - interval '7 days')::int AS last_7d
FROM activity_events;

-- name: StatsActivityBySource :many
-- Groups activity_events by entity_type.
SELECT entity_type AS source, COUNT(*)::int AS count
FROM activity_events
GROUP BY entity_type;

-- name: StatsTagCounts :one
SELECT
    (SELECT COUNT(*) FROM tags)::int AS canonical,
    (SELECT COUNT(*) FROM tag_aliases)::int AS aliases,
    (SELECT COUNT(*) FROM tag_aliases WHERE NOT confirmed)::int AS unconfirmed;

-- name: StatsGoalsByArea :many
-- Active goals (not started or in progress) grouped by area name.
-- Goals without an area appear as 'unset'.
SELECT COALESCE(a.name, 'unset') AS area, COUNT(*)::int AS count
FROM goals g
LEFT JOIN areas a ON a.id = g.area_id
WHERE g.status IN ('not_started', 'in_progress')
GROUP BY a.name;

-- name: StatsEventsByArea :many
-- Activity events grouped by the area of their associated project.
SELECT COALESCE(a.name, 'unset') AS area, COUNT(*)::int AS count
FROM activity_events ev
LEFT JOIN projects p ON p.id = ev.project_id
LEFT JOIN areas a ON a.id = p.area_id
WHERE ev.occurred_at > now() - make_interval(days => @days::int)
GROUP BY a.name;

-- name: StatsProcessRunsSummary :one
-- Aggregate process_runs counts since cutoff within a single kind, with
-- optional name and status filters.
SELECT
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE status = 'completed')::int AS completed,
    COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
    COUNT(*) FILTER (WHERE status = 'running')::int AS running,
    COUNT(*) FILTER (WHERE status = 'pending')::int AS pending
FROM process_runs
WHERE kind = @kind::text
  AND created_at >= @since
  AND (sqlc.narg('name')::text IS NULL OR name = sqlc.narg('name'))
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'));

-- name: StatsFeedHealthSummary :one
SELECT
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE enabled)::int AS enabled,
    COUNT(*) FILTER (WHERE consecutive_failures > 0)::int AS failing_feeds
FROM feeds;

-- name: StatsRecentProcessRuns :many
-- Recent process_runs within a single kind, newest first.
SELECT id, name, status::text AS status, error, created_at, ended_at
FROM process_runs
WHERE kind = @kind::text
  AND created_at >= @since
  AND (sqlc.narg('name')::text IS NULL OR name = sqlc.narg('name'))
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
ORDER BY created_at DESC
LIMIT @max_results;

-- name: StatsProcessRunsByName :many
-- Per-name aggregate within a single kind over a time window, plus the
-- last status seen (the array_agg trick returns the most recent row by
-- created_at DESC).
SELECT
    name,
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE status = 'completed')::int AS completed,
    COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
    COUNT(*) FILTER (WHERE status = 'running')::int AS running,
    MAX(created_at)::timestamptz AS last_run_at,
    ((array_agg(status::text ORDER BY created_at DESC))[1])::text AS last_status
FROM process_runs
WHERE kind = @kind::text
  AND created_at >= @since
GROUP BY name
ORDER BY name;

-- name: StatsNoteGrowth :one
-- Short-form knowledge growth: Zettelkasten notes (notes table) plus
-- TIL contents. Phase 2 entry split notes out of contents — the two
-- short-form formats now live in separate tables and the union here
-- reassembles the dashboard view.
WITH knowledge AS (
    SELECT created_at FROM notes
    UNION ALL
    SELECT created_at FROM contents WHERE type = 'til'
)
SELECT
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE created_at > now() - interval '7 days')::int AS last_week,
    COUNT(*) FILTER (WHERE created_at > now() - interval '30 days')::int AS last_month
FROM knowledge;

-- name: StatsWeeklyActivity :one
-- Compares this week (last 7 days) vs last week (7-14 days ago).
SELECT
    COUNT(*) FILTER (WHERE occurred_at > now() - interval '7 days')::int AS this_week,
    COUNT(*) FILTER (WHERE occurred_at > now() - interval '14 days' AND occurred_at <= now() - interval '7 days')::int AS last_week
FROM activity_events;

-- name: StatsTopTags :many
-- Top tags across TIL contents, ranked by usage. notes table has no
-- tag relationships post Phase 2 entry — tags here count TILs only.
SELECT t.name, COUNT(ct.content_id)::int AS count
FROM tags t
JOIN content_tags ct ON ct.tag_id = t.id
JOIN contents c ON c.id = ct.content_id
WHERE c.type = 'til'
GROUP BY t.id, t.name
ORDER BY count DESC
LIMIT 10;

-- name: StatsFeedHealthCounts :one
SELECT
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE consecutive_failures = 0)::int AS healthy,
    COUNT(*) FILTER (WHERE consecutive_failures > 0)::int AS failing
FROM feeds;

-- name: StatsFailingFeeds :many
SELECT name, COALESCE(last_error, '') AS last_error, last_fetched_at
FROM feeds
WHERE consecutive_failures > 0
ORDER BY consecutive_failures DESC, name;

-- name: StatsProcessRunsRecent :one
-- Activity snapshot across ALL process_runs kinds within a time window.
-- Used by SystemHealth.Pipelines which represents the overall background
-- processing subsystem, not any single kind.
--
-- last_run_at uses COALESCE to Go's zero time ('0001-01-01 00:00:00+00')
-- because MAX(created_at) over an empty set returns NULL, which a
-- non-null time.Time scan rejects. The Go-side handler checks IsZero()
-- to translate the sentinel back into a nil JSON field on the wire —
-- callers see last_run_at: null when there's been no activity, not an
-- ancient year-1 date.
SELECT
    COUNT(*)::int AS recent_runs,
    COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
    COALESCE(MAX(created_at), '0001-01-01 00:00:00+00'::timestamptz)::timestamptz AS last_run_at
FROM process_runs
WHERE created_at >= @since;

-- name: StatsLastAgentScheduleRuns :many
-- Latest started_at per agent across all agent_schedule runs.
-- process_runs.name format is "<agent>:<schedule>" (see migration COMMENT on
-- process_runs.name); split_part extracts the agent identifier. Rows whose
-- started_at is NULL (still pending) are skipped so the result reports only
-- runs the external scheduler has actually begun.
SELECT split_part(name, ':', 1)::text   AS agent_name,
       MAX(started_at)::timestamptz     AS last_run_at
FROM process_runs
WHERE kind = 'agent_schedule'
  AND started_at IS NOT NULL
GROUP BY split_part(name, ':', 1);

-- name: StatsDatabaseCounts :one
-- Core entity counts for SystemHealth. todos is the personal GTD store;
-- the inter-agent coordination tasks table is intentionally NOT counted
-- here (it would mix two entirely different concepts with the same word).
-- notes lives in its own table (Phase 2 entry extracted Zettelkasten
-- notes from the old contents.type='note' polymorphism).
--
-- Learning-domain counts added in F-3 follow-up: a learning-studio
-- audit reported the previous shape made the learning surface invisible
-- in system_status. attempts/sessions/concepts/fsrs covers the four
-- top-level entities a learning coach checks for "is the system
-- populated yet". One query, not four, keeps the round-trip at 1.
SELECT
    (SELECT COUNT(*) FROM contents)::int                 AS contents_count,
    (SELECT COUNT(*) FROM todos)::int                    AS todos_count,
    (SELECT COUNT(*) FROM notes)::int                    AS notes_count,
    (SELECT COUNT(*) FROM learning_attempts)::int        AS attempts_count,
    (SELECT COUNT(*) FROM learning_sessions)::int        AS sessions_count,
    (SELECT COUNT(*) FROM concepts)::int                 AS concepts_count,
    (SELECT COUNT(*) FROM review_cards)::int             AS fsrs_cards_count;
