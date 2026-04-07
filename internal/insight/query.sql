-- name: CreateInsight :one
INSERT INTO insights (source, content, hypothesis, invalidation_condition, metadata, observed_date)
VALUES (@source, @content, @hypothesis, @invalidation_condition, @metadata, @observed_date)
RETURNING id, source, content, status, hypothesis, invalidation_condition, metadata, observed_date, created_at;

-- name: InsightByID :one
SELECT id, source, content, status, hypothesis, invalidation_condition, metadata, observed_date, created_at
FROM insights WHERE id = @id;

-- name: UpdateInsightStatus :one
UPDATE insights SET status = @status
WHERE id = @id
RETURNING id, source, content, status, hypothesis, invalidation_condition, metadata, observed_date, created_at;

-- name: UpdateInsightMetadata :one
UPDATE insights SET metadata = @metadata
WHERE id = @id
RETURNING id, source, content, status, hypothesis, invalidation_condition, metadata, observed_date, created_at;

-- name: UnverifiedInsights :many
SELECT id, source, content, status, hypothesis, invalidation_condition, metadata, observed_date, created_at
FROM insights
WHERE status = 'unverified'
ORDER BY observed_date DESC, created_at DESC
LIMIT @max_results;

-- name: InsightsByStatus :many
SELECT id, source, content, status, hypothesis, invalidation_condition, metadata, observed_date, created_at
FROM insights
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
ORDER BY observed_date DESC, created_at DESC
LIMIT @max_results;
