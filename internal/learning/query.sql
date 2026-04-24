-- name: CreateLearningDomain :one
INSERT INTO learning_domains (slug, name)
VALUES (@slug, @name)
RETURNING slug, name, active, created_at;

-- name: LearningDomainExists :one
SELECT EXISTS(SELECT 1 FROM learning_domains WHERE slug = @slug);

-- name: ListLearningDomains :many
SELECT slug, name, active, created_at FROM learning_domains
WHERE active = TRUE
ORDER BY slug;

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

-- name: EndStaleActiveSession :one
-- Ends the currently-active session if its most recent activity is more than
-- 12 hours old. "Most recent activity" is the later of started_at and the
-- most recent attempt; with no attempts it falls back to started_at. Returns
-- the ended session, or no rows when the active session is still fresh (or
-- when no active session exists).
--
-- The single 12h threshold intentionally tolerates multi-hour reading/practice
-- sessions that record attempts along the way — a 3-hour JLPT block with
-- regular record_attempts stays well inside the window. The zombie case is
-- "agent crashed or user walked away and never came back": the last signal
-- (session start, or last attempt) is yesterday or older.
--
-- Called by start_session to unblock the single-active-session invariant when
-- the prior agent or process exited without ending its session.
WITH active AS (
    SELECT s.id, s.started_at,
           (SELECT MAX(a.attempted_at) FROM learning_attempts a WHERE a.session_id = s.id) AS last_attempt
    FROM learning_sessions s
    WHERE s.ended_at IS NULL
    ORDER BY s.started_at DESC
    LIMIT 1
),
to_end AS (
    SELECT id FROM active
    WHERE COALESCE(last_attempt, started_at) < now() - INTERVAL '12 hours'
)
UPDATE learning_sessions
SET ended_at = now(), updated_at = now()
WHERE id IN (SELECT id FROM to_end) AND ended_at IS NULL
RETURNING id, domain, session_mode, agent_note_id, daily_plan_item_id, started_at, ended_at, metadata, created_at, updated_at;

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

-- name: FindTargetByDomainTitle :one
-- Read-only target lookup by (domain, title). Returns ErrNotFound when the
-- target does not exist — used by attempt_history which must NOT create new
-- targets (it would silently pollute the catalog from a read tool).
SELECT id, domain, title, external_id, difficulty, created_at, updated_at
FROM learning_targets
WHERE domain = @domain AND title = @title
LIMIT 1;

-- name: FindOrCreateLearningTarget :one
-- Upsert a learning target by domain + external_id (if present) or domain + title.
INSERT INTO learning_targets (domain, title, external_id, difficulty)
VALUES (@domain, @title, @external_id, @difficulty)
ON CONFLICT (domain, external_id) WHERE external_id IS NOT NULL
DO UPDATE SET title = EXCLUDED.title, difficulty = COALESCE(EXCLUDED.difficulty, learning_targets.difficulty), updated_at = now()
RETURNING id, domain, title, external_id, difficulty, metadata, created_at, updated_at;

-- name: InsertLearningTargetRelation :exec
-- Idempotent insert into learning_target_relations. Conflicts on
-- (anchor_id, related_id, relation_type) are ignored so re-recording
-- the same relationship during a later session is safe.
INSERT INTO learning_target_relations (anchor_id, related_id, relation_type)
VALUES (@anchor_id, @related_id, @relation_type)
ON CONFLICT (anchor_id, related_id, relation_type) DO NOTHING;

-- name: CreateAttempt :one
INSERT INTO learning_attempts (learning_target_id, session_id, attempt_number, paradigm, outcome, duration_minutes, stuck_at, approach_used, metadata)
VALUES (@learning_target_id, @session_id, @attempt_number, @paradigm, @outcome, @duration_minutes, @stuck_at, @approach_used, @metadata)
RETURNING id, learning_target_id, session_id, attempt_number, paradigm, outcome, duration_minutes, stuck_at, approach_used, metadata, attempted_at, created_at;

-- name: AttemptCountForLearningTarget :one
SELECT COALESCE(MAX(attempt_number), 0)::int AS max_number
FROM learning_attempts WHERE learning_target_id = @learning_target_id;

-- name: AttemptByID :one
-- Fetch a single attempt with its learning_target_id for target-alignment
-- checks (e.g. manage_plan.update_entry must verify the caller-supplied
-- completed_by_attempt_id actually maps to the plan entry's target).
SELECT id, learning_target_id, session_id, attempt_number, paradigm, outcome,
       duration_minutes, stuck_at, approach_used, attempted_at, metadata
FROM learning_attempts WHERE id = @id;

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
RETURNING id, slug, name, domain, kind, parent_id, description, created_at, updated_at;

-- name: AttemptsBySession :many
-- All attempts within a session, oldest first. Backs end_session summary
-- and the by_session path of attempt_history.
SELECT a.id, a.learning_target_id, a.session_id, a.attempt_number, a.paradigm, a.outcome,
       a.duration_minutes, a.stuck_at, a.approach_used, a.attempted_at, a.metadata,
       lt.title AS target_title, lt.external_id AS target_external_id
FROM learning_attempts a
JOIN learning_targets lt ON lt.id = a.learning_target_id
WHERE a.session_id = @session_id
ORDER BY a.attempted_at;

-- name: AttemptsByLearningTarget :many
-- All attempts on a specific learning target, newest first. Primary backing
-- query for Improvement Verification Loop — "how did he do this target
-- last time?". Same shape as AttemptsBySession so they share the Go DTO.
SELECT a.id, a.learning_target_id, a.session_id, a.attempt_number, a.paradigm, a.outcome,
       a.duration_minutes, a.stuck_at, a.approach_used, a.attempted_at, a.metadata,
       lt.title AS target_title, lt.external_id AS target_external_id
FROM learning_attempts a
JOIN learning_targets lt ON lt.id = a.learning_target_id
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
-- Learning targets due for spaced review from review_cards.
-- Used by learning_dashboard retrieval view.
--
-- drift_suspect: true when the card's most recent attempt-driven review
-- could not be applied cleanly (last_sync_drift_at is more recent than the
-- last attempt on the target). Surfaces FSRS scheduling drift to the
-- consumer so the coach can choose to manually re-review instead of
-- trusting a possibly-stale due date.
SELECT rc.id AS card_id, rc.due,
       lt.id AS target_id, lt.title, lt.domain, lt.difficulty, lt.external_id,
       (rc.last_sync_drift_at IS NOT NULL
        AND rc.last_sync_drift_at > COALESCE(
            (SELECT MAX(attempted_at) FROM learning_attempts la WHERE la.learning_target_id = lt.id),
            'epoch'::timestamptz
        ))::bool AS drift_suspect,
       rc.last_drift_reason
FROM review_cards rc
JOIN learning_targets lt ON lt.id = rc.learning_target_id
WHERE rc.due <= @due_before
  AND (sqlc.narg('domain')::text IS NULL OR lt.domain = sqlc.narg('domain'))
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

-- name: LearningTargetVariations :many
-- Problem relationship graph from learning_target_relations, enriched with
-- per-related-side attempt stats so the coach can decide whether to push the
-- related target next without a second round trip per row.
--
-- related_attempt_count / related_last_outcome / related_last_attempted_at
-- answer the operational question "has Koopa tried this variant, and how did
-- it go?". Anchor stats are omitted because the caller usually has the
-- anchor in context already (it's the problem they just solved); adding both
-- sides doubles the subquery cost for no extra signal in the common flow.
--
-- The LEFT JOIN + GROUP BY shape (instead of correlated scalar subqueries)
-- is deliberate — it gives sqlc the nullability signal it needs for the
-- "no attempts yet" case, so related_last_outcome and related_last_attempted_at
-- generate as nullable pointers instead of blowing up on Scan.
--
-- Used by learning_dashboard variations view.
WITH target_last_attempt AS (
    SELECT DISTINCT ON (learning_target_id)
           learning_target_id,
           outcome,
           attempted_at
    FROM learning_attempts
    ORDER BY learning_target_id, attempted_at DESC
),
target_attempt_counts AS (
    SELECT learning_target_id, COUNT(*) AS attempt_count
    FROM learning_attempts
    GROUP BY learning_target_id
)
SELECT ltr.id AS relation_id, ltr.relation_type,
       anchor.id AS anchor_id, anchor.title AS anchor_title, anchor.domain AS anchor_domain,
       related.id AS related_id, related.title AS related_title, related.domain AS related_domain,
       COALESCE(tc.attempt_count, 0)::bigint AS related_attempt_count,
       tla.outcome AS related_last_outcome,
       tla.attempted_at AS related_last_attempted_at
FROM learning_target_relations ltr
JOIN learning_targets anchor ON anchor.id = ltr.anchor_id
JOIN learning_targets related ON related.id = ltr.related_id
LEFT JOIN target_last_attempt tla ON tla.learning_target_id = related.id
LEFT JOIN target_attempt_counts tc ON tc.learning_target_id = related.id
WHERE (sqlc.narg('domain')::text IS NULL OR anchor.domain = sqlc.narg('domain'))
ORDER BY ltr.created_at DESC
LIMIT @max_results;

-- name: ConceptByDomainSlug :one
-- Get a single concept by domain + slug for drilldown.
SELECT id, slug, name, domain, kind, parent_id, description, created_at, updated_at
FROM concepts
WHERE domain = @domain AND LOWER(slug) = LOWER(@slug);

-- name: ConceptsBySlug :many
-- Batch-resolve concept IDs by slug (cross-domain). Returns one row per matched
-- slug. Unmatched slugs produce no row — callers compare result count vs input
-- count to detect missing slugs.
SELECT id, slug FROM concepts WHERE slug = ANY(@slugs::text[]);

-- name: ObservationsByConcept :many
-- Observations for a concept, newest first. For concept drilldown.
SELECT ao.id, ao.attempt_id, ao.signal_type, ao.category, ao.severity, ao.detail, ao.created_at,
       a.outcome, a.attempted_at,
       lt.title AS target_title
FROM learning_attempt_observations ao
JOIN learning_attempts a ON a.id = ao.attempt_id
JOIN learning_targets lt ON lt.id = a.learning_target_id
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
SELECT id, learning_target_id, session_id, attempt_number, paradigm, outcome,
       duration_minutes, stuck_at, approach_used, attempted_at, metadata,
       target_title, target_external_id, difficulty,
       matched_signal, matched_category, matched_severity, matched_detail
FROM (
    SELECT DISTINCT ON (a.id)
           a.id, a.learning_target_id, a.session_id, a.attempt_number, a.paradigm, a.outcome,
           a.duration_minutes, a.stuck_at, a.approach_used, a.attempted_at, a.metadata,
           lt.title AS target_title, lt.external_id AS target_external_id, lt.difficulty,
           ao.signal_type AS matched_signal,
           ao.category   AS matched_category,
           ao.severity   AS matched_severity,
           ao.detail     AS matched_detail
    FROM learning_attempts a
    JOIN learning_targets lt ON lt.id = a.learning_target_id
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

-- name: LearningTargetsByConcept :many
-- Learning targets linked to a concept. For concept drilldown related targets.
SELECT lt.id, lt.title, lt.domain, lt.difficulty, lt.external_id, ltc.relevance
FROM learning_targets lt
JOIN learning_target_concepts ltc ON ltc.learning_target_id = lt.id
WHERE ltc.concept_id = @concept_id
ORDER BY ltc.relevance, lt.title;

-- ============================================================
-- Learning target writeup junctions (notes + contents)
--
-- Two N:M junctions, intentionally not polymorphic — notes and contents
-- are distinct entities with distinct lifecycles. A target may accumulate
-- many writeups of different kinds over time.
-- ============================================================

-- name: AttachNoteToTarget :exec
-- Idempotent attach. Repeat attaches are no-ops.
INSERT INTO learning_target_notes (target_id, note_id)
VALUES (@target_id, @note_id)
ON CONFLICT DO NOTHING;

-- name: DetachNoteFromTarget :execrows
-- Returns affected row count so the caller can distinguish 'actually
-- detached' from 'was never attached' if needed.
DELETE FROM learning_target_notes
WHERE target_id = @target_id AND note_id = @note_id;

-- name: NotesForTarget :many
-- All notes attached to a target, newest-updated first. Caller can filter
-- by kind in Go if a single-kind view is needed.
SELECT n.id, n.slug, n.title, n.body, n.kind, n.maturity,
       n.created_by, n.metadata, n.created_at, n.updated_at
FROM notes n
JOIN learning_target_notes ltn ON ltn.note_id = n.id
WHERE ltn.target_id = @target_id
ORDER BY n.updated_at DESC;

-- name: CanonicalNoteForTarget :one
-- Resolves the canonical writeup for a target: the most recently updated
-- note whose kind matches the target domain's canonical_writeup_kind.
-- Returns no rows if the domain has no canonical rule or the target has
-- no note of the canonical kind yet.
SELECT n.id, n.slug, n.title, n.body, n.kind, n.maturity,
       n.created_by, n.metadata, n.created_at, n.updated_at
FROM notes n
JOIN learning_target_notes ltn ON ltn.note_id = n.id
JOIN learning_targets lt       ON lt.id = ltn.target_id
JOIN learning_domains ld       ON ld.slug = lt.domain
WHERE ltn.target_id = @target_id
  AND ld.canonical_writeup_kind IS NOT NULL
  AND n.kind = ld.canonical_writeup_kind
ORDER BY n.updated_at DESC
LIMIT 1;

-- name: AttachContentToTarget :exec
-- Idempotent attach of a content row (article/essay/etc) to a target.
INSERT INTO learning_target_contents (target_id, content_id)
VALUES (@target_id, @content_id)
ON CONFLICT DO NOTHING;

-- name: DetachContentFromTarget :execrows
DELETE FROM learning_target_contents
WHERE target_id = @target_id AND content_id = @content_id;

-- name: ContentsForTarget :many
-- All contents attached to a target.
SELECT c.id, c.slug, c.title, c.type, c.status, c.is_public,
       c.published_at, c.created_at, c.updated_at
FROM contents c
JOIN learning_target_contents ltc ON ltc.content_id = c.id
WHERE ltc.target_id = @target_id
ORDER BY c.updated_at DESC;

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
