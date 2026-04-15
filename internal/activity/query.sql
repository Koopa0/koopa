-- name: CreateEvent :one
-- Insert an activity event. Dedup on (source, event_type, source_id) for events
-- with a non-null source_id; null-source_id events are always inserted.
-- Returns the event ID on both fresh insert and dedup hit.
-- The DO UPDATE SET id = id is a no-op that forces RETURNING to work on conflict.
INSERT INTO events (
    source_id, timestamp, event_type, source,
    project, repo, ref, title, body, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
)
ON CONFLICT (source, event_type, source_id) WHERE source_id IS NOT NULL
DO UPDATE SET id = events.id
RETURNING id;

-- name: EventsByTimeRange :many
-- List activity events within a time range, ordered by timestamp descending.
-- Used by the daily-dev-log flow to gather a day's activity.
-- Hard cap prevents unbounded result sets from wide time ranges.
SELECT id, source_id, timestamp, event_type, source,
       project, repo, ref, title, body, metadata, created_at
FROM events
WHERE timestamp >= @start_time AND timestamp < @end_time
ORDER BY timestamp DESC
LIMIT 5000;

-- name: InsertEventTag :exec
-- Link an activity event to a canonical tag. Silently ignores duplicates.
INSERT INTO event_tags (event_id, tag_id)
VALUES ($1, $2)
ON CONFLICT (event_id, tag_id) DO NOTHING;

-- name: InsertEventTags :exec
-- Bulk-link an activity event to multiple canonical tags. Silently ignores duplicates.
INSERT INTO event_tags (event_id, tag_id)
SELECT @event_id, unnest(@tag_ids::uuid[])
ON CONFLICT DO NOTHING;

-- name: EventsByFilters :many
-- List activity events within a time range with optional source and project filters.
SELECT id, source_id, timestamp, event_type, source,
       project, repo, ref, title, body, metadata, created_at
FROM events
WHERE timestamp >= @start_time AND timestamp < @end_time
  AND (sqlc.narg('filter_source')::text IS NULL OR source = sqlc.narg('filter_source'))
  AND (sqlc.narg('filter_project')::text IS NULL OR project = sqlc.narg('filter_project'))
ORDER BY timestamp DESC
LIMIT @max_results;

-- name: EventsByProject :many
-- List recent activity events for a specific project name.
SELECT id, source_id, timestamp, event_type, source,
       project, repo, ref, title, body, metadata, created_at
FROM events
WHERE project = @project_name
ORDER BY timestamp DESC
LIMIT @max_results;

-- name: DeleteOldEvents :execrows
-- Cleanup: delete activity events older than the given cutoff.
DELETE FROM events WHERE timestamp < @cutoff;

-- name: CountEventsBySourcePrefix :one
-- Count events matching an event_type and source_id prefix since a given time.
-- Used for double-complete detection: count today's todo_completed events for a specific todo item.
SELECT count(*)::int FROM events
WHERE event_type = @event_type
  AND source_id LIKE @source_prefix || '%'
  AND timestamp >= @since;

-- name: CompletionEventsByProjectSince :many
-- Count todo completions per project from activity events since the given time.
-- Captures both one-time and recurring todo completions (recurring items reset
-- state to "todo" in the todo_items table, making snapshot queries miss them).
-- Sources: "todo_completed" events from MCP/HTTP, plus "todo_state_change" events
-- from Notion sync where metadata status is "Done".
-- Deduplicates by (title, day) to avoid double-counting when MCP complete triggers
-- a Notion webhook in the same day.
WITH completions AS (
    SELECT DISTINCT ON (COALESCE(title, ''), timestamp::date)
           COALESCE(project, '') AS project_slug,
           title,
           timestamp::date AS completed_date
    FROM events
    WHERE timestamp >= @since
      AND (
          event_type = 'todo_completed'
          OR (event_type = 'todo_state_change' AND metadata->>'status' = 'Done')
      )
    ORDER BY COALESCE(title, ''), timestamp::date, timestamp ASC
)
SELECT COALESCE(p.title, c.project_slug, '(no project)') AS project_title,
       count(*) AS completed
FROM completions c
LEFT JOIN projects p ON c.project_slug = p.slug
GROUP BY COALESCE(p.title, c.project_slug, '(no project)')
ORDER BY completed DESC;
