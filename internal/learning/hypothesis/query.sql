-- name: CreateHypothesis :one
INSERT INTO learning_hypotheses (created_by, content, claim, invalidation_condition, metadata, observed_date)
VALUES (@created_by, @content, @claim, @invalidation_condition, @metadata, @observed_date)
RETURNING id, created_by, content, state, claim, invalidation_condition, metadata, observed_date,
          resolved_at, resolved_by_attempt_id, resolved_by_observation_id, resolution_summary, created_at;

-- name: HypothesisByID :one
SELECT id, created_by, content, state, claim, invalidation_condition, metadata, observed_date,
       resolved_at, resolved_by_attempt_id, resolved_by_observation_id, resolution_summary, created_at
FROM learning_hypotheses WHERE id = @id;

-- name: UpdateHypothesisState :one
-- Only safe for transitions that do not require resolution evidence
-- (e.g. unverified ↔ archived). Transitions to verified/invalidated MUST
-- go through UpdateHypothesisResolution so resolved_at and at least one
-- evidence source are set atomically; otherwise chk_learning_hypothesis_resolved_at
-- and chk_learning_hypothesis_resolution will fire.
UPDATE learning_hypotheses SET state = @state::hypothesis_state
WHERE id = @id
RETURNING id, created_by, content, state, claim, invalidation_condition, metadata, observed_date,
          resolved_at, resolved_by_attempt_id, resolved_by_observation_id, resolution_summary, created_at;

-- name: UpdateHypothesisResolution :one
-- Resolves a hypothesis by setting state + evidence + timestamp atomically.
-- Caller must supply state IN ('verified', 'invalidated') and at least one
-- evidence source (attempt_id, observation_id, or non-blank summary).
-- chk_learning_hypothesis_resolved_at and chk_learning_hypothesis_resolution enforce this at DB.
UPDATE learning_hypotheses
SET state                      = sqlc.arg('state')::hypothesis_state,
    resolved_at                = now(),
    resolved_by_attempt_id     = sqlc.narg('attempt_id')::uuid,
    resolved_by_observation_id = sqlc.narg('observation_id')::uuid,
    resolution_summary         = sqlc.narg('summary')::text
WHERE id = sqlc.arg('id')::uuid
RETURNING id, created_by, content, state, claim, invalidation_condition, metadata, observed_date,
          resolved_at, resolved_by_attempt_id, resolved_by_observation_id, resolution_summary, created_at;

-- name: UpdateHypothesisMetadata :one
UPDATE learning_hypotheses SET metadata = @metadata
WHERE id = @id
RETURNING id, created_by, content, state, claim, invalidation_condition, metadata, observed_date,
          resolved_at, resolved_by_attempt_id, resolved_by_observation_id, resolution_summary, created_at;

-- name: AppendHypothesisEvidence :one
-- Atomically appends a JSON entry to metadata->evidence_key (e.g.
-- 'supporting_evidence' or 'counter_evidence') in a single statement so
-- concurrent evidence posts cannot lose entries under Read Committed.
-- Replaces the read-modify-write path the HTTP AddEvidence handler used
-- to take through UpdateHypothesisMetadata. The DB does the array append
-- via jsonb || jsonb — callers pass the new entry as a single-element
-- JSON array (e.g. '[{"type":"supporting","description":"..."}]').
UPDATE learning_hypotheses
SET metadata = jsonb_set(
        COALESCE(metadata, '{}'::jsonb),
        ARRAY[@evidence_key::text],
        COALESCE(metadata -> @evidence_key::text, '[]'::jsonb) || @entry::jsonb,
        true
    )
WHERE id = @id
RETURNING id, created_by, content, state, claim, invalidation_condition, metadata, observed_date,
          resolved_at, resolved_by_attempt_id, resolved_by_observation_id, resolution_summary, created_at;

-- name: UnverifiedHypotheses :many
SELECT id, created_by, content, state, claim, invalidation_condition, metadata, observed_date,
       resolved_at, resolved_by_attempt_id, resolved_by_observation_id, resolution_summary, created_at
FROM learning_hypotheses
WHERE state = 'unverified'
ORDER BY observed_date DESC, created_at DESC
LIMIT @max_results;

-- name: HypothesesByState :many
SELECT id, created_by, content, state, claim, invalidation_condition, metadata, observed_date,
       resolved_at, resolved_by_attempt_id, resolved_by_observation_id, resolution_summary, created_at
FROM learning_hypotheses
WHERE (sqlc.narg('state')::hypothesis_state IS NULL OR state = sqlc.narg('state')::hypothesis_state)
ORDER BY observed_date DESC, created_at DESC
LIMIT @max_results;

-- name: HypothesesPaged :many
-- Admin paginated list with optional state filter.
SELECT id, created_by, content, state, claim, invalidation_condition, metadata, observed_date,
       resolved_at, resolved_by_attempt_id, resolved_by_observation_id, resolution_summary, created_at
FROM learning_hypotheses
WHERE (sqlc.narg('state')::hypothesis_state IS NULL OR state = sqlc.narg('state')::hypothesis_state)
ORDER BY observed_date DESC, created_at DESC
LIMIT @page_limit OFFSET @page_offset;

-- name: HypothesesPagedCount :one
SELECT COUNT(*) FROM learning_hypotheses
WHERE (sqlc.narg('state')::hypothesis_state IS NULL OR state = sqlc.narg('state')::hypothesis_state);
