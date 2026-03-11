-- name: Feeds :many
SELECT id, url, name, schedule, topics, enabled, etag, last_modified,
       last_fetched_at, consecutive_failures, last_error, disabled_reason,
       created_at, updated_at
FROM feeds
WHERE (sqlc.narg('schedule')::text IS NULL OR schedule = sqlc.narg('schedule'))
ORDER BY created_at DESC;

-- name: FeedByID :one
SELECT id, url, name, schedule, topics, enabled, etag, last_modified,
       last_fetched_at, consecutive_failures, last_error, disabled_reason,
       created_at, updated_at
FROM feeds WHERE id = $1;

-- name: EnabledFeedsBySchedule :many
SELECT id, url, name, schedule, topics, enabled, etag, last_modified,
       last_fetched_at, consecutive_failures, last_error, disabled_reason,
       created_at, updated_at
FROM feeds WHERE enabled = true AND schedule = $1;

-- name: CreateFeed :one
INSERT INTO feeds (url, name, schedule, topics)
VALUES ($1, $2, $3, $4)
RETURNING id, url, name, schedule, topics, enabled, etag, last_modified,
          last_fetched_at, consecutive_failures, last_error, disabled_reason,
          created_at, updated_at;

-- name: UpdateFeed :one
UPDATE feeds SET
    url = COALESCE(sqlc.narg('url'), url),
    name = COALESCE(sqlc.narg('name'), name),
    schedule = COALESCE(sqlc.narg('schedule'), schedule),
    topics = COALESCE(sqlc.narg('topics'), topics),
    enabled = COALESCE(sqlc.narg('enabled'), enabled),
    updated_at = now()
WHERE id = $1
RETURNING id, url, name, schedule, topics, enabled, etag, last_modified,
          last_fetched_at, consecutive_failures, last_error, disabled_reason,
          created_at, updated_at;

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
