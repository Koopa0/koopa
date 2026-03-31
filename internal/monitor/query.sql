-- name: MonitorTopics :many
SELECT id, name, keywords, sources, enabled, schedule, created_at, updated_at
FROM tracking_topics ORDER BY created_at DESC;

-- name: MonitorTopicByID :one
SELECT id, name, keywords, sources, enabled, schedule, created_at, updated_at
FROM tracking_topics WHERE id = $1;

-- name: MonitorCreate :one
INSERT INTO tracking_topics (name, keywords, sources, enabled, schedule)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, name, keywords, sources, enabled, schedule, created_at, updated_at;

-- name: MonitorUpdate :one
UPDATE tracking_topics SET
    name = COALESCE(sqlc.narg('name'), name),
    keywords = COALESCE(sqlc.narg('keywords'), keywords),
    sources = COALESCE(sqlc.narg('sources'), sources),
    enabled = COALESCE(sqlc.narg('enabled'), enabled),
    schedule = COALESCE(sqlc.narg('schedule'), schedule),
    updated_at = now()
WHERE id = $1
RETURNING id, name, keywords, sources, enabled, schedule, created_at, updated_at;

-- name: MonitorDelete :execrows
DELETE FROM tracking_topics WHERE id = $1;
