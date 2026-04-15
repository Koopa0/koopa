-- name: CreateSession :one
INSERT INTO learning_sessions (domain, session_mode, daily_plan_item_id)
VALUES (@domain, @session_mode, @daily_plan_item_id)
RETURNING id, domain, session_mode, agent_note_id, daily_plan_item_id, started_at, ended_at, metadata, created_at, updated_at;

-- name: SessionByID :one
SELECT id, domain, session_mode, agent_note_id, daily_plan_item_id, started_at, ended_at, metadata, created_at, updated_at
FROM learning_sessions WHERE id = @id;

-- name: ActiveSession :one
-- Find a session that hasn't ended yet.
SELECT id, domain, session_mode, agent_note_id, daily_plan_item_id, started_at, ended_at, metadata, created_at, updated_at
FROM learning_sessions WHERE ended_at IS NULL
ORDER BY started_at DESC LIMIT 1;

-- name: EndSession :one
UPDATE learning_sessions SET ended_at = now(), agent_note_id = @agent_note_id, updated_at = now()
WHERE id = @id AND ended_at IS NULL
RETURNING id, domain, session_mode, agent_note_id, daily_plan_item_id, started_at, ended_at, metadata, created_at, updated_at;

-- name: RecentSessions :many
SELECT id, domain, session_mode, agent_note_id, daily_plan_item_id, started_at, ended_at, metadata, created_at, updated_at
FROM learning_sessions
WHERE (sqlc.narg('domain')::text IS NULL OR domain = sqlc.narg('domain'))
  AND started_at >= @since
ORDER BY started_at DESC
LIMIT @max_results;

-- name: FindItemByDomainTitle :one
-- Read-only item lookup by (domain, title). Returns ErrNotFound when the
-- item does not exist — used by attempt_history which must NOT create new
-- items (it would silently pollute the catalog from a read tool).
SELECT id, domain, title, external_id, difficulty, created_at, updated_at
FROM learning_targets
WHERE domain = @domain AND title = @title
LIMIT 1;

-- name: FindOrCreateItem :one
-- Upsert a learning item by domain + external_id (if present) or domain + title.
INSERT INTO learning_targets (domain, title, external_id, difficulty)
VALUES (@domain, @title, @external_id, @difficulty)
ON CONFLICT (domain, external_id) WHERE external_id IS NOT NULL
DO UPDATE SET title = EXCLUDED.title, difficulty = COALESCE(EXCLUDED.difficulty, learning_targets.difficulty), updated_at = now()
RETURNING id, domain, title, external_id, difficulty, obsidian_note_id, content_id, project_id, metadata, created_at, updated_at;

-- name: InsertItemRelation :exec
-- Idempotent insert into item_relations. Conflicts on
-- (anchor_id, related_id, relation_type) are ignored so re-recording
-- the same relationship during a later session is safe.
INSERT INTO learning_target_relations (anchor_id, related_id, relation_type)
VALUES (@anchor_id, @related_id, @relation_type)
ON CONFLICT (anchor_id, related_id, relation_type) DO NOTHING;

-- name: CreateAttempt :one
INSERT INTO learning_attempts (learning_target_id, session_id, attempt_number, outcome, duration_minutes, stuck_at, approach_used, metadata)
VALUES (@learning_target_id, @session_id, @attempt_number, @outcome, @duration_minutes, @stuck_at, @approach_used, @metadata)
RETURNING id, learning_target_id, session_id, attempt_number, outcome, duration_minutes, stuck_at, approach_used, obsidian_note_id, metadata, attempted_at, created_at;

-- name: AttemptCountForItem :one
SELECT COALESCE(MAX(attempt_number), 0)::int AS max_number
FROM learning_attempts WHERE learning_target_id = @learning_target_id;

-- name: CreateObservation :one
INSERT INTO learning_attempt_observations (attempt_id, concept_id, signal_type, category, severity, detail, confidence)
VALUES (@attempt_id, @concept_id, @signal_type, @category, @severity, @detail, @confidence)
RETURNING id, attempt_id, concept_id, signal_type, category, severity, detail, confidence, created_at;

-- name: FindOrCreateConcept :one
-- Upsert a concept by domain + slug.
INSERT INTO concepts (slug, name, domain, kind)
VALUES (@slug, @name, @domain, @kind)
ON CONFLICT (domain, LOWER(slug))
DO UPDATE SET updated_at = now()
RETURNING id, slug, name, domain, kind, parent_id, tag_id, description, created_at, updated_at;

-- name: AttemptsBySession :many
-- All attempts within a session, oldest first. Backs end_session summary
-- and the by_session path of attempt_history.
SELECT a.id, a.learning_target_id, a.session_id, a.attempt_number, a.outcome,
       a.duration_minutes, a.stuck_at, a.approach_used, a.attempted_at, a.metadata,
       li.title AS item_title, li.external_id AS item_external_id
FROM learning_attempts a
JOIN learning_targets li ON li.id = a.learning_target_id
WHERE a.session_id = @session_id
ORDER BY a.attempted_at;

-- name: AttemptsByItem :many
-- All attempts on a specific learning item, newest first. Primary backing
-- query for Improvement Verification Loop — "how did he do this problem
-- last time?". Same shape as AttemptsBySession so they share the Go DTO.
SELECT a.id, a.learning_target_id, a.session_id, a.attempt_number, a.outcome,
       a.duration_minutes, a.stuck_at, a.approach_used, a.attempted_at, a.metadata,
       li.title AS item_title, li.external_id AS item_external_id
FROM learning_attempts a
JOIN learning_targets li ON li.id = a.learning_target_id
WHERE a.learning_target_id = @learning_target_id
ORDER BY a.attempted_at DESC
LIMIT @max_results;

-- name: ObservationsByAttempt :many
SELECT ao.id, ao.attempt_id, ao.concept_id, ao.signal_type, ao.category, ao.severity, ao.detail,
       c.slug AS concept_slug, c.name AS concept_name
FROM learning_attempt_observations ao
JOIN concepts c ON c.id = ao.concept_id
WHERE ao.attempt_id = @attempt_id;

-- name: ConceptMastery :many
-- Per-concept mastery with signal counts from attempt_observations within
-- the @since window. Used by learning_dashboard mastery view.
--
-- @confidence_filter: 'high' (default) restricts the aggregation to
-- high-confidence observations; 'all' includes both. The filter is
-- applied via WHERE so the COUNT(*) FILTER clauses see the same row set
-- and the < N observations → developing floor in deriveMasteryStage
-- looks at FILTERED counts only — that property is the difference between
-- "confidence is a label" (this design) and "confidence is a half-gate".
--
-- Stage is derived in Go (not SQL) from the signal counts —
-- see mcp.deriveMasteryStage.
SELECT c.id, c.slug, c.name, c.domain, c.kind,
       COUNT(*) FILTER (WHERE ao.signal_type = 'weakness') AS weakness_count,
       COUNT(*) FILTER (WHERE ao.signal_type = 'improvement') AS improvement_count,
       COUNT(*) FILTER (WHERE ao.signal_type = 'mastery') AS mastery_count,
       COUNT(*) AS total_observations,
       MIN(ao.created_at)::timestamptz AS first_observed_at,
       MAX(ao.created_at)::timestamptz AS last_observed_at
FROM concepts c
JOIN learning_attempt_observations ao ON ao.concept_id = c.id
JOIN learning_attempts a ON a.id = ao.attempt_id
WHERE (sqlc.narg('domain')::text IS NULL OR c.domain = sqlc.narg('domain'))
  AND a.attempted_at >= @since
  AND (@confidence_filter::text = 'all' OR ao.confidence = 'high')
GROUP BY c.id
ORDER BY total_observations DESC;

-- name: WeaknessAnalysis :many
-- Cross-pattern weakness analysis from attempt_observations within the
-- @since window. Used by learning_dashboard weaknesses view.
--
-- @confidence_filter: same semantics as ConceptMastery — 'high' (default)
-- or 'all'. Aggregations that mastery returns under the same filter MUST
-- match this view's occurrence_counts for the same concept; this
-- invariant is enforced by integration test.
SELECT c.slug AS concept_slug, c.name AS concept_name, c.domain,
       ao.category,
       COUNT(*) AS occurrence_count,
       COUNT(*) FILTER (WHERE ao.severity = 'critical') AS critical_count,
       COUNT(*) FILTER (WHERE ao.severity = 'moderate') AS moderate_count,
       COUNT(*) FILTER (WHERE ao.severity = 'minor') AS minor_count,
       MAX(ao.created_at)::timestamptz AS last_seen_at
FROM learning_attempt_observations ao
JOIN concepts c ON c.id = ao.concept_id
JOIN learning_attempts a ON a.id = ao.attempt_id
WHERE ao.signal_type = 'weakness'
  AND (sqlc.narg('domain')::text IS NULL OR c.domain = sqlc.narg('domain'))
  AND a.attempted_at >= @since
  AND (@confidence_filter::text = 'all' OR ao.confidence = 'high')
GROUP BY c.slug, c.name, c.domain, ao.category
ORDER BY critical_count DESC, occurrence_count DESC;

-- name: RetrievalQueue :many
-- Items due for spaced review from review_cards.
-- Used by learning_dashboard retrieval view.
SELECT rc.id AS card_id, rc.due,
       li.id AS item_id, li.title, li.domain, li.difficulty, li.external_id
FROM review_cards rc
JOIN learning_targets li ON li.id = rc.learning_target_id
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
FROM learning_sessions ls
LEFT JOIN learning_attempts a ON a.session_id = ls.id
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
FROM learning_target_relations ir
JOIN learning_targets src ON src.id = ir.anchor_id
JOIN learning_targets tgt ON tgt.id = ir.related_id
WHERE (sqlc.narg('domain')::text IS NULL OR src.domain = sqlc.narg('domain'))
ORDER BY ir.created_at DESC
LIMIT @max_results;

-- ============================================================
-- FSRS review cards + review logs
-- ============================================================

-- name: CardByLearningItem :one
-- Get the review card for a learning item.
SELECT * FROM review_cards WHERE learning_target_id = @learning_target_id;

-- name: CreateCardForItem :one
-- Create a new FSRS review card for a learning item.
INSERT INTO review_cards (learning_target_id, card_state, due)
VALUES (@learning_target_id, @card_state, @due)
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
FROM learning_attempt_observations ao
JOIN learning_attempts a ON a.id = ao.attempt_id
JOIN learning_targets li ON li.id = a.learning_target_id
WHERE ao.concept_id = @concept_id
ORDER BY ao.created_at DESC
LIMIT @max_results;

-- name: AttemptsByConcept :many
-- Attempts that produced an observation about the given concept, newest first.
-- Each row carries the matched observation's signal/category/severity/detail
-- so the caller knows WHY this attempt is in the result set without a second
-- query.
--
-- The inner SELECT uses DISTINCT ON (a.id) to keep one row per attempt even
-- when a single attempt recorded multiple observations on the same concept;
-- the picked observation is highest-priority by signal (weakness > improvement
-- > mastery) then severity (critical > moderate > minor). The outer SELECT
-- re-sorts by attempted_at DESC because DISTINCT ON forces the inner ORDER BY
-- to lead with a.id.
--
-- Replaces the prior version that joined through item_concepts (a static
-- tag table that no production code path populates). The semantics changed:
-- this now returns "attempts where the user explicitly observed this
-- concept", not "attempts on items tagged with this concept". The new
-- semantics is what concept drilldown actually wants.
SELECT id, learning_target_id, session_id, attempt_number, outcome,
       duration_minutes, stuck_at, approach_used, attempted_at, metadata,
       item_title, item_external_id, difficulty,
       matched_signal, matched_category, matched_severity, matched_detail
FROM (
    SELECT DISTINCT ON (a.id)
           a.id, a.learning_target_id, a.session_id, a.attempt_number, a.outcome,
           a.duration_minutes, a.stuck_at, a.approach_used, a.attempted_at, a.metadata,
           li.title AS item_title, li.external_id AS item_external_id, li.difficulty,
           ao.signal_type AS matched_signal,
           ao.category   AS matched_category,
           ao.severity   AS matched_severity,
           ao.detail     AS matched_detail
    FROM learning_attempts a
    JOIN learning_targets li ON li.id = a.learning_target_id
    JOIN learning_attempt_observations ao ON ao.attempt_id = a.id
    WHERE ao.concept_id = @concept_id
    -- Priority order when an attempt has multiple observations on the
    -- concept: weakness signals first, then improvement, then mastery. Within
    -- the same signal, classified severities beat NULL (NULL = unclassified,
    -- which can only happen for weakness since the schema CHECK forbids
    -- non-NULL severity on improvement/mastery rows). Treating NULL as
    -- lowest is deliberate — we surface the rows where the coach left a
    -- concrete severity note ahead of the rows where they did not.
    ORDER BY a.id,
             CASE ao.signal_type WHEN 'weakness' THEN 0 WHEN 'improvement' THEN 1 WHEN 'mastery' THEN 2 END,
             CASE ao.severity WHEN 'critical' THEN 0 WHEN 'moderate' THEN 1 WHEN 'minor' THEN 2 ELSE 3 END
) deduped
ORDER BY attempted_at DESC
LIMIT @max_results;

-- name: ItemsByConcept :many
-- Items linked to a concept. For concept drilldown related_items.
SELECT li.id, li.title, li.domain, li.difficulty, li.external_id, ic.relevance
FROM learning_targets li
JOIN learning_target_concepts ic ON ic.learning_target_id = li.id
WHERE ic.concept_id = @concept_id
ORDER BY ic.relevance, li.title;

-- name: SessionStreak :one
-- Count consecutive days (from today backwards) with at least one session.
WITH daily AS (
    SELECT DISTINCT (started_at AT TIME ZONE 'UTC')::date AS d
    FROM learning_sessions
    WHERE ended_at IS NOT NULL
),
numbered AS (
    SELECT d, d - (ROW_NUMBER() OVER (ORDER BY d DESC))::int AS grp
    FROM daily
)
SELECT count(*)::int AS streak
FROM numbered
WHERE grp = (SELECT grp FROM numbered ORDER BY d DESC LIMIT 1);
