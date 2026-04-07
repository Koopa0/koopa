-- name: CreateSession :one
INSERT INTO learning_sessions (domain, session_mode, daily_plan_item_id)
VALUES (@domain, @session_mode, @daily_plan_item_id)
RETURNING id, domain, session_mode, journal_id, daily_plan_item_id, started_at, ended_at, metadata, created_at;

-- name: SessionByID :one
SELECT id, domain, session_mode, journal_id, daily_plan_item_id, started_at, ended_at, metadata, created_at
FROM learning_sessions WHERE id = @id;

-- name: ActiveSession :one
-- Find a session that hasn't ended yet.
SELECT id, domain, session_mode, journal_id, daily_plan_item_id, started_at, ended_at, metadata, created_at
FROM learning_sessions WHERE ended_at IS NULL
ORDER BY started_at DESC LIMIT 1;

-- name: EndSession :one
UPDATE learning_sessions SET ended_at = now(), journal_id = @journal_id
WHERE id = @id AND ended_at IS NULL
RETURNING id, domain, session_mode, journal_id, daily_plan_item_id, started_at, ended_at, metadata, created_at;

-- name: RecentSessions :many
SELECT id, domain, session_mode, journal_id, daily_plan_item_id, started_at, ended_at, metadata, created_at
FROM learning_sessions
WHERE (sqlc.narg('domain')::text IS NULL OR domain = sqlc.narg('domain'))
  AND started_at >= @since
ORDER BY started_at DESC
LIMIT @max_results;

-- name: FindOrCreateItem :one
-- Upsert a learning item by domain + external_id (if present) or domain + title.
INSERT INTO learning_items (domain, title, external_id, difficulty)
VALUES (@domain, @title, @external_id, @difficulty)
ON CONFLICT (domain, external_id) WHERE external_id IS NOT NULL
DO UPDATE SET title = EXCLUDED.title, difficulty = COALESCE(EXCLUDED.difficulty, learning_items.difficulty), updated_at = now()
RETURNING id, domain, title, external_id, difficulty, note_id, content_id, project_id, metadata, created_at, updated_at;

-- name: CreateAttempt :one
INSERT INTO attempts (learning_item_id, session_id, attempt_number, outcome, duration_minutes, stuck_at, approach_used, metadata)
VALUES (@learning_item_id, @session_id, @attempt_number, @outcome, @duration_minutes, @stuck_at, @approach_used, @metadata)
RETURNING id, learning_item_id, session_id, attempt_number, outcome, duration_minutes, stuck_at, approach_used, note_id, metadata, attempted_at, created_at;

-- name: AttemptCountForItem :one
SELECT COALESCE(MAX(attempt_number), 0)::int AS max_number
FROM attempts WHERE learning_item_id = @learning_item_id;

-- name: CreateObservation :one
INSERT INTO attempt_observations (attempt_id, concept_id, signal_type, category, severity, detail)
VALUES (@attempt_id, @concept_id, @signal_type, @category, @severity, @detail)
RETURNING id, attempt_id, concept_id, signal_type, category, severity, detail, created_at;

-- name: FindOrCreateConcept :one
-- Upsert a concept by domain + slug.
INSERT INTO concepts (slug, name, domain, kind)
VALUES (@slug, @name, @domain, @kind)
ON CONFLICT (domain, LOWER(slug))
DO UPDATE SET updated_at = now()
RETURNING id, slug, name, domain, kind, parent_id, tag_id, description, created_at, updated_at;

-- name: AttemptsBySession :many
SELECT a.id, a.learning_item_id, a.session_id, a.attempt_number, a.outcome,
       a.duration_minutes, a.stuck_at, a.approach_used, a.attempted_at,
       li.title AS item_title, li.external_id AS item_external_id
FROM attempts a
JOIN learning_items li ON li.id = a.learning_item_id
WHERE a.session_id = @session_id
ORDER BY a.attempted_at;

-- name: ObservationsByAttempt :many
SELECT ao.id, ao.attempt_id, ao.concept_id, ao.signal_type, ao.category, ao.severity, ao.detail,
       c.slug AS concept_slug, c.name AS concept_name
FROM attempt_observations ao
JOIN concepts c ON c.id = ao.concept_id
WHERE ao.attempt_id = @attempt_id;
