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

-- name: StatsFlowRunsByStatus :many
SELECT status::text AS status, COUNT(*)::int AS count
FROM flow_runs
GROUP BY status;

-- name: StatsProjectsByStatus :many
SELECT status::text AS status, COUNT(*)::int AS count
FROM projects
GROUP BY status;

-- name: StatsEditorialQueueCounts :one
SELECT COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE status = 'pending')::int AS pending
FROM editorial_queue;

-- name: StatsNotesByType :many
SELECT COALESCE(type, 'unknown') AS type, COUNT(*)::int AS count
FROM obsidian_notes
GROUP BY type;

-- name: StatsActivityWindow :one
SELECT COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE timestamp > now() - interval '24 hours')::int AS last_24h,
       COUNT(*) FILTER (WHERE timestamp > now() - interval '7 days')::int AS last_7d
FROM events;

-- name: StatsActivityBySource :many
SELECT source, COUNT(*)::int AS count
FROM events
GROUP BY source;

-- name: StatsSyncSourceCounts :one
SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE enabled)::int AS enabled
FROM sync_sources;

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
WHERE g.status IN ('not-started', 'in-progress')
GROUP BY a.name;

-- name: StatsEventsByArea :many
-- Activity events grouped by the area of their associated project.
-- Project lookup matches by project slug or repo. Events without a
-- project, or whose project has no area, appear as 'unset'.
SELECT COALESCE(a.name, 'unset') AS area, COUNT(*)::int AS count
FROM events ae
LEFT JOIN projects p ON ae.project = p.slug
   OR (p.repo IS NOT NULL AND p.repo != '' AND ae.project = p.repo)
LEFT JOIN areas a ON a.id = p.area_id
WHERE ae.timestamp > now() - make_interval(days => @days::int)
GROUP BY a.name;

-- name: StatsFlowRunsSummary :one
-- Aggregate flow run counts since cutoff, with optional flow_name and status filters.
SELECT
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE status = 'completed')::int AS completed,
    COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
    COUNT(*) FILTER (WHERE status = 'running')::int AS running
FROM flow_runs
WHERE created_at >= @since
  AND (sqlc.narg('flow_name')::text IS NULL OR flow_name = sqlc.narg('flow_name'))
  AND (sqlc.narg('status')::flow_status IS NULL OR status = sqlc.narg('status')::flow_status);

-- name: StatsFeedHealthSummary :one
SELECT
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE enabled)::int AS enabled,
    COUNT(*) FILTER (WHERE consecutive_failures > 0)::int AS failing_feeds
FROM feeds;

-- name: StatsRecentFlowRuns :many
SELECT id, flow_name, status::text AS status, error, created_at, ended_at
FROM flow_runs
WHERE created_at >= @since
  AND (sqlc.narg('flow_name')::text IS NULL OR flow_name = sqlc.narg('flow_name'))
  AND (sqlc.narg('status')::flow_status IS NULL OR status = sqlc.narg('status')::flow_status)
ORDER BY created_at DESC
LIMIT @max_results;

-- name: StatsPipelineSummaries :many
-- Per-flow-name aggregate over a time window, plus the last status seen
-- (the array_agg trick returns the most recent row by created_at DESC).
SELECT
    flow_name,
    COUNT(*)::int AS total,
    COUNT(*) FILTER (WHERE status = 'completed')::int AS completed,
    COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
    COUNT(*) FILTER (WHERE status = 'running')::int AS running,
    MAX(created_at) AS last_run_at,
    (array_agg(status::text ORDER BY created_at DESC))[1] AS last_status
FROM flow_runs
WHERE created_at >= @since
GROUP BY flow_name
ORDER BY flow_name;

-- name: StatsNoteGrowth :one
-- Combined note count from obsidian_notes table + TIL entries from contents.
-- obsidian_notes uses synced_at; contents uses created_at.
SELECT
    (COALESCE(o.total, 0) + COALESCE(c.total, 0))::int AS total,
    (COALESCE(o.last_week, 0) + COALESCE(c.last_week, 0))::int AS last_week,
    (COALESCE(o.last_month, 0) + COALESCE(c.last_month, 0))::int AS last_month
FROM
    (SELECT COUNT(*) AS total,
        COUNT(*) FILTER (WHERE synced_at > now() - interval '7 days') AS last_week,
        COUNT(*) FILTER (WHERE synced_at > now() - interval '30 days') AS last_month
     FROM obsidian_notes) o,
    (SELECT COUNT(*) AS total,
        COUNT(*) FILTER (WHERE created_at > now() - interval '7 days') AS last_week,
        COUNT(*) FILTER (WHERE created_at > now() - interval '30 days') AS last_month
     FROM contents WHERE type = 'til') c;

-- name: StatsNoteGrowthByType :many
-- By-type breakdown across obsidian_notes + TIL contents.
SELECT type, SUM(cnt)::int AS count FROM (
    SELECT COALESCE(type, 'unknown') AS type, COUNT(*) AS cnt FROM obsidian_notes GROUP BY type
    UNION ALL
    SELECT 'til' AS type, COUNT(*) AS cnt FROM contents WHERE type = 'til'
) combined
GROUP BY type;

-- name: StatsWeeklyActivity :one
-- Compares this week (last 7 days) vs last week (7-14 days ago).
SELECT
    COUNT(*) FILTER (WHERE timestamp > now() - interval '7 days')::int AS this_week,
    COUNT(*) FILTER (WHERE timestamp > now() - interval '14 days' AND timestamp <= now() - interval '7 days')::int AS last_week
FROM events;

-- name: StatsTopTags :many
-- Top tags by combined usage across obsidian_note_tags and content_tags (TIL only).
SELECT name, SUM(cnt)::int AS count FROM (
    SELECT t.name, COUNT(ont.note_id) AS cnt
    FROM tags t
    JOIN obsidian_note_tags ont ON ont.tag_id = t.id
    GROUP BY t.id, t.name
    UNION ALL
    SELECT t.name, COUNT(ct.content_id) AS cnt
    FROM tags t
    JOIN content_tags ct ON ct.tag_id = t.id
    JOIN contents c ON c.id = ct.content_id
    WHERE c.type = 'til'
    GROUP BY t.id, t.name
) combined
GROUP BY name
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

-- name: StatsPipelineActivityRecent :one
-- 24h pipeline activity snapshot for SystemHealth.
SELECT
    COUNT(*)::int AS recent_runs,
    COUNT(*) FILTER (WHERE status = 'failed')::int AS failed,
    MAX(created_at) AS last_run_at
FROM flow_runs
WHERE created_at >= @since;

-- name: StatsDatabaseCounts :one
-- Core entity counts for SystemHealth. todos replaces the old
-- GTD tasks table; the new tasks table is the inter-agent coordination
-- entity and is intentionally NOT counted here (it would mix two
-- entirely different concepts of "task").
SELECT
    (SELECT COUNT(*) FROM contents)::int AS contents_count,
    (SELECT COUNT(*) FROM todos)::int AS todos_count,
    (SELECT COUNT(*) FROM obsidian_notes)::int AS notes_count;
