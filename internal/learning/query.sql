-- name: CreateSession :one
INSERT INTO sessions (domain, session_mode, daily_plan_item_id)
VALUES (@domain, @session_mode, @daily_plan_item_id)
RETURNING id, domain, session_mode, journal_id, daily_plan_item_id, started_at, ended_at, metadata, created_at;

-- name: SessionByID :one
SELECT id, domain, session_mode, journal_id, daily_plan_item_id, started_at, ended_at, metadata, created_at
FROM sessions WHERE id = @id;

-- name: ActiveSession :one
-- Find a session that hasn't ended yet.
SELECT id, domain, session_mode, journal_id, daily_plan_item_id, started_at, ended_at, metadata, created_at
FROM sessions WHERE ended_at IS NULL
ORDER BY started_at DESC LIMIT 1;

-- name: EndSession :one
UPDATE sessions SET ended_at = now(), journal_id = @journal_id
WHERE id = @id AND ended_at IS NULL
RETURNING id, domain, session_mode, journal_id, daily_plan_item_id, started_at, ended_at, metadata, created_at;

-- name: RecentSessions :many
SELECT id, domain, session_mode, journal_id, daily_plan_item_id, started_at, ended_at, metadata, created_at
FROM sessions
WHERE (sqlc.narg('domain')::text IS NULL OR domain = sqlc.narg('domain'))
  AND started_at >= @since
ORDER BY started_at DESC
LIMIT @max_results;

-- name: FindOrCreateItem :one
-- Upsert a learning item by domain + external_id (if present) or domain + title.
INSERT INTO items (domain, title, external_id, difficulty)
VALUES (@domain, @title, @external_id, @difficulty)
ON CONFLICT (domain, external_id) WHERE external_id IS NOT NULL
DO UPDATE SET title = EXCLUDED.title, difficulty = COALESCE(EXCLUDED.difficulty, items.difficulty), updated_at = now()
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
JOIN items li ON li.id = a.learning_item_id
WHERE a.session_id = @session_id
ORDER BY a.attempted_at;

-- name: ObservationsByAttempt :many
SELECT ao.id, ao.attempt_id, ao.concept_id, ao.signal_type, ao.category, ao.severity, ao.detail,
       c.slug AS concept_slug, c.name AS concept_name
FROM attempt_observations ao
JOIN concepts c ON c.id = ao.concept_id
WHERE ao.attempt_id = @attempt_id;

-- name: ConceptMastery :many
-- Per-concept mastery with signal counts from attempt_observations.
-- Used by learning_dashboard mastery view.
SELECT c.id, c.slug, c.name, c.domain, c.kind,
       COUNT(*) FILTER (WHERE ao.signal_type = 'weakness') AS weakness_count,
       COUNT(*) FILTER (WHERE ao.signal_type = 'improvement') AS improvement_count,
       COUNT(*) FILTER (WHERE ao.signal_type = 'mastery') AS mastery_count,
       COUNT(*) AS total_observations,
       MAX(ao.created_at) AS last_observed_at
FROM concepts c
JOIN attempt_observations ao ON ao.concept_id = c.id
JOIN attempts a ON a.id = ao.attempt_id
WHERE (sqlc.narg('domain')::text IS NULL OR c.domain = sqlc.narg('domain'))
  AND a.attempted_at >= @since
GROUP BY c.id
ORDER BY total_observations DESC;

-- name: WeaknessAnalysis :many
-- Cross-pattern weakness analysis from attempt_observations.
-- Used by learning_dashboard weaknesses view.
SELECT c.slug AS concept_slug, c.name AS concept_name, c.domain,
       ao.category,
       COUNT(*) AS occurrence_count,
       COUNT(*) FILTER (WHERE ao.severity = 'critical') AS critical_count,
       COUNT(*) FILTER (WHERE ao.severity = 'moderate') AS moderate_count,
       COUNT(*) FILTER (WHERE ao.severity = 'minor') AS minor_count,
       MAX(ao.created_at)::timestamptz AS last_seen_at
FROM attempt_observations ao
JOIN concepts c ON c.id = ao.concept_id
JOIN attempts a ON a.id = ao.attempt_id
WHERE ao.signal_type = 'weakness'
  AND (sqlc.narg('domain')::text IS NULL OR c.domain = sqlc.narg('domain'))
  AND a.attempted_at >= @since
GROUP BY c.slug, c.name, c.domain, ao.category
ORDER BY critical_count DESC, occurrence_count DESC;

-- name: RetrievalQueue :many
-- Items due for spaced review from review_cards.
-- Used by learning_dashboard retrieval view.
SELECT rc.id AS card_id, rc.due,
       li.id AS item_id, li.title, li.domain, li.difficulty, li.external_id
FROM review_cards rc
JOIN items li ON li.id = rc.learning_item_id
WHERE rc.due <= @due_before
  AND (sqlc.narg('domain')::text IS NULL OR li.domain = sqlc.narg('domain'))
ORDER BY rc.due ASC
LIMIT @max_results;

-- name: SessionTimeline :many
-- Recent sessions grouped by day with attempt counts.
-- Used by learning_dashboard timeline view.
SELECT ls.id, ls.domain, ls.session_mode, ls.started_at, ls.ended_at,
       COUNT(a.id) AS attempt_count,
       COUNT(*) FILTER (WHERE a.outcome IN ('solved_independent', 'completed')) AS success_count
FROM sessions ls
LEFT JOIN attempts a ON a.session_id = ls.id
WHERE (sqlc.narg('domain')::text IS NULL OR ls.domain = sqlc.narg('domain'))
  AND ls.started_at >= @since
GROUP BY ls.id
ORDER BY ls.started_at DESC;

-- name: ItemVariations :many
-- Problem relationship graph from item_relations.
-- Used by learning_dashboard variations view.
SELECT ir.id AS relation_id, ir.relation_type,
       src.id AS source_id, src.title AS source_title, src.domain AS source_domain,
       tgt.id AS target_id, tgt.title AS target_title, tgt.domain AS target_domain
FROM item_relations ir
JOIN items src ON src.id = ir.source_item_id
JOIN items tgt ON tgt.id = ir.target_item_id
WHERE (sqlc.narg('domain')::text IS NULL OR src.domain = sqlc.narg('domain'))
ORDER BY ir.created_at DESC
LIMIT @max_results;

-- ============================================================
-- FSRS review cards + review logs
-- ============================================================

-- name: CardByLearningItem :one
-- Get the review card for a learning item.
SELECT * FROM review_cards WHERE learning_item_id = @learning_item_id;

-- name: CreateCardForItem :one
-- Create a new FSRS review card for a learning item.
INSERT INTO review_cards (learning_item_id, card_state, due)
VALUES (@learning_item_id, @card_state, @due)
RETURNING *;

-- name: UpdateCardState :one
-- Update card state and due date after a review.
UPDATE review_cards
SET card_state = @card_state, due = @due, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: InsertReviewLog :exec
-- Append a review log entry after rating a card.
INSERT INTO review_logs (card_id, rating, scheduled_days, elapsed_days, state, reviewed_at)
VALUES (@card_id, @rating, @scheduled_days, @elapsed_days, @state, @reviewed_at);

-- name: CardByID :one
-- Get a review card by its primary key (used after retrieval queue lookup).
SELECT * FROM review_cards WHERE id = @id;

-- name: ReviewLogsByCard :many
-- Review history for a card, newest first. Supports idx_review_logs_card index.
SELECT id, card_id, rating, scheduled_days, elapsed_days, state, reviewed_at
FROM review_logs
WHERE card_id = @card_id
ORDER BY reviewed_at DESC
LIMIT @max_results;

-- name: DueReviewCount :one
-- Count of review cards due before a given time (for needs_attention badge).
SELECT count(*)::int FROM review_cards WHERE due <= @due_before;

-- name: ConceptByDomainSlug :one
-- Get a single concept by domain + slug for drilldown.
SELECT id, slug, name, domain, kind, parent_id, tag_id, description, created_at, updated_at
FROM concepts
WHERE domain = @domain AND LOWER(slug) = LOWER(@slug);

-- name: ObservationsByConcept :many
-- Observations for a concept, newest first. For concept drilldown.
SELECT ao.id, ao.attempt_id, ao.signal_type, ao.category, ao.severity, ao.detail, ao.created_at,
       a.outcome, a.attempted_at,
       li.title AS item_title
FROM attempt_observations ao
JOIN attempts a ON a.id = ao.attempt_id
JOIN items li ON li.id = a.learning_item_id
WHERE ao.concept_id = @concept_id
ORDER BY ao.created_at DESC
LIMIT @max_results;

-- name: AttemptsByConcept :many
-- Recent attempts on items that exercise a given concept. For concept drilldown.
SELECT DISTINCT a.id, a.learning_item_id, a.outcome, a.attempted_at, a.duration_minutes,
       li.title AS item_title, li.difficulty
FROM attempts a
JOIN items li ON li.id = a.learning_item_id
JOIN item_concepts ic ON ic.learning_item_id = li.id
WHERE ic.concept_id = @concept_id
ORDER BY a.attempted_at DESC
LIMIT @max_results;

-- name: ItemsByConcept :many
-- Items linked to a concept. For concept drilldown related_items.
SELECT li.id, li.title, li.domain, li.difficulty, li.external_id, ic.relevance
FROM items li
JOIN item_concepts ic ON ic.learning_item_id = li.id
WHERE ic.concept_id = @concept_id
ORDER BY ic.relevance, li.title;

-- name: SessionStreak :one
-- Count consecutive days (from today backwards) with at least one session.
WITH daily AS (
    SELECT DISTINCT (started_at AT TIME ZONE 'UTC')::date AS d
    FROM sessions
    WHERE ended_at IS NOT NULL
),
numbered AS (
    SELECT d, d - (ROW_NUMBER() OVER (ORDER BY d DESC))::int AS grp
    FROM daily
)
SELECT count(*)::int AS streak
FROM numbered
WHERE grp = (SELECT grp FROM numbered ORDER BY d DESC LIMIT 1);
