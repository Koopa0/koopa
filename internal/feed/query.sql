-- name: Feeds :many
SELECT f.id, f.url, f.name, f.schedule, f.enabled, f.priority, f.etag, f.last_modified,
       f.last_fetched_at, f.consecutive_failures, f.last_error, f.disabled_reason,
       f.filter_config, f.created_at, f.updated_at,
       COALESCE(array_agg(t.slug) FILTER (WHERE t.slug IS NOT NULL), '{}')::text[] AS topics
FROM feeds f
LEFT JOIN feed_topics ft ON ft.feed_id = f.id
LEFT JOIN topics t ON t.id = ft.topic_id
WHERE (sqlc.narg('schedule')::text IS NULL OR f.schedule = sqlc.narg('schedule'))
GROUP BY f.id
ORDER BY f.created_at DESC;

-- name: FeedByID :one
SELECT f.id, f.url, f.name, f.schedule, f.enabled, f.priority, f.etag, f.last_modified,
       f.last_fetched_at, f.consecutive_failures, f.last_error, f.disabled_reason,
       f.filter_config, f.created_at, f.updated_at,
       COALESCE(array_agg(t.slug) FILTER (WHERE t.slug IS NOT NULL), '{}')::text[] AS topics
FROM feeds f
LEFT JOIN feed_topics ft ON ft.feed_id = f.id
LEFT JOIN topics t ON t.id = ft.topic_id
WHERE f.id = $1
GROUP BY f.id;

-- name: EnabledFeeds :many
SELECT id, url, name, schedule, enabled, priority, etag, last_modified,
       last_fetched_at, consecutive_failures, last_error, disabled_reason,
       filter_config, created_at, updated_at
FROM feeds WHERE enabled = true
ORDER BY created_at;

-- name: EnabledFeedsBySchedule :many
SELECT id, url, name, schedule, enabled, priority, etag, last_modified,
       last_fetched_at, consecutive_failures, last_error, disabled_reason,
       filter_config, created_at, updated_at
FROM feeds WHERE enabled = true AND schedule = $1;

-- name: CreateFeed :one
-- NOTE: topics are now managed via feed_topics junction table, not a column on feeds.
INSERT INTO feeds (url, name, schedule, filter_config)
VALUES ($1, $2, $3, $4)
RETURNING id, url, name, schedule, enabled, priority, etag, last_modified,
          last_fetched_at, consecutive_failures, last_error, disabled_reason,
          filter_config, created_at, updated_at;

-- name: UpdateFeed :one
UPDATE feeds SET
    url = COALESCE(sqlc.narg('url'), url),
    name = COALESCE(sqlc.narg('name'), name),
    schedule = COALESCE(sqlc.narg('schedule'), schedule),
    enabled = COALESCE(sqlc.narg('enabled'), enabled),
    filter_config = COALESCE(sqlc.narg('filter_config'), filter_config),
    updated_at = now()
WHERE id = $1
RETURNING id, url, name, schedule, enabled, priority, etag, last_modified,
          last_fetched_at, consecutive_failures, last_error, disabled_reason,
          filter_config, created_at, updated_at;

-- name: DeleteFeed :exec
DELETE FROM feeds WHERE id = $1;

-- name: IncrementFeedFailure :one
UPDATE feeds SET
    consecutive_failures = consecutive_failures + 1,
    last_error = $2,
    updated_at = now()
WHERE id = $1
RETURNING consecutive_failures;

-- name: AutoDisableFeed :exec
UPDATE feeds SET
    enabled = false,
    disabled_reason = $2,
    updated_at = now()
WHERE id = $1;

-- name: ResetFeedFailure :exec
UPDATE feeds SET
    consecutive_failures = 0,
    last_error = '',
    etag = $2,
    last_modified = $3,
    last_fetched_at = now(),
    updated_at = now()
WHERE id = $1;

-- name: InsertFlowRun :exec
INSERT INTO flow_runs (flow_name, input, output, status, error, started_at, ended_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);
