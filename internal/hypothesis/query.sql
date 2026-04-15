-- name: CreateHypothesis :one
INSERT INTO hypotheses (author, content, claim, invalidation_condition, metadata, observed_date)
VALUES (@author, @content, @claim, @invalidation_condition, @metadata, @observed_date)
RETURNING id, author, content, state, claim, invalidation_condition, metadata, observed_date, created_at;

-- name: HypothesisByID :one
SELECT id, author, content, state, claim, invalidation_condition, metadata, observed_date, created_at
FROM hypotheses WHERE id = @id;

-- name: UpdateHypothesisState :one
UPDATE hypotheses SET state = @state::hypothesis_state
WHERE id = @id
RETURNING id, author, content, state, claim, invalidation_condition, metadata, observed_date, created_at;

-- name: UpdateHypothesisMetadata :one
UPDATE hypotheses SET metadata = @metadata
WHERE id = @id
RETURNING id, author, content, state, claim, invalidation_condition, metadata, observed_date, created_at;

-- name: UnverifiedHypotheses :many
SELECT id, author, content, state, claim, invalidation_condition, metadata, observed_date, created_at
FROM hypotheses
WHERE state = 'unverified'
ORDER BY observed_date DESC, created_at DESC
LIMIT @max_results;

-- name: HypothesesByState :many
SELECT id, author, content, state, claim, invalidation_condition, metadata, observed_date, created_at
FROM hypotheses
WHERE (sqlc.narg('state')::hypothesis_state IS NULL OR state = sqlc.narg('state')::hypothesis_state)
ORDER BY observed_date DESC, created_at DESC
LIMIT @max_results;
