-- name: TrackingTopics :many
SELECT * FROM tracking_topics ORDER BY created_at DESC;

-- name: TrackingTopicByID :one
SELECT * FROM tracking_topics WHERE id = $1;

-- name: CreateTrackingTopic :one
INSERT INTO tracking_topics (name, keywords, sources, enabled, schedule)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: UpdateTrackingTopic :one
UPDATE tracking_topics SET
    name = COALESCE(sqlc.narg('name'), name),
    keywords = COALESCE(sqlc.narg('keywords'), keywords),
    sources = COALESCE(sqlc.narg('sources'), sources),
    enabled = COALESCE(sqlc.narg('enabled'), enabled),
    schedule = COALESCE(sqlc.narg('schedule'), schedule),
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: DeleteTrackingTopic :exec
DELETE FROM tracking_topics WHERE id = $1;
