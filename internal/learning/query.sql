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
-- target does not exist OR is archived — used by attempt_history which
-- must NOT create new targets (it would silently pollute the catalog from
-- a read tool). Archived targets surface via attempt_history's archived
-- branch (resolved=false, reason='archived'); this query is for live-only
-- resolution.
SELECT id, domain, title, external_id, difficulty, created_at, updated_at
FROM learning_targets
WHERE domain = @domain AND title = @title AND archived_at IS NULL
LIMIT 1;

-- name: TargetByID :one
-- Full-row lookup by primary key including archive state. Used by
-- archive_learning_target for ownership/archive-eligibility checks. Does NOT
-- filter archived rows — the caller branches on archived_at to decide
-- whether to reject or proceed (unarchive path).
SELECT id, domain, title, external_id, difficulty, metadata,
       created_by, archived_at, archive_batch_id, created_at, updated_at
FROM learning_targets
WHERE id = @id;

-- name: ArchiveTargetReturn :one
-- Soft-deletes a target, marking archived_at and tagging it with
-- archive_batch_id. The batch id ties the target to the relations
-- archived in the same call (see ArchiveRelationsForTarget) so a
-- future unarchive_target call can restore exactly the cascade
-- group, not every relation involving the target. Returns the
-- updated row.
UPDATE learning_targets
SET archived_at = now(), archive_batch_id = @batch_id, updated_at = now()
WHERE id = @id AND archived_at IS NULL
RETURNING id, domain, title, external_id, difficulty, metadata,
          created_by, archived_at, archive_batch_id, created_at, updated_at;

-- name: ArchiveRelationsForTarget :many
-- Cascades archive onto every live relation that references the target
-- as anchor OR related, tagging them with the same batch id. The
-- symmetric-relation reverse edge (auto-inserted by the
-- enforce_learning_target_relation_symmetry trigger for same_pattern /
-- similar_structure) is the same row pattern with anchor/related
-- swapped, so it gets caught by the OR clause naturally — no separate
-- query needed. Returns the affected rows so the handler can include
-- them in the cascaded_relations response.
UPDATE learning_target_relations
SET archived_at = now(), archive_batch_id = @batch_id
WHERE (anchor_id = @target_id OR related_id = @target_id)
  AND archived_at IS NULL
RETURNING id, anchor_id, related_id, relation_type, created_by,
          archived_at, archive_batch_id, created_at;

-- name: FindOrCreateLearningTarget :one
-- Upsert a learning target by domain + external_id (if present) or domain + title.
-- created_by is captured on INSERT; ON CONFLICT preserves the original creator
-- (the column is intentionally absent from the UPDATE list). This matters for
-- the §B U2 self-bound archive rule — the row's first-touch agent retains
-- archival authority regardless of which agent later re-resolves the target.
INSERT INTO learning_targets (domain, title, external_id, difficulty, created_by)
VALUES (@domain, @title, @external_id, @difficulty, @created_by)
ON CONFLICT (domain, external_id) WHERE external_id IS NOT NULL
DO UPDATE SET title = EXCLUDED.title, difficulty = COALESCE(EXCLUDED.difficulty, learning_targets.difficulty), updated_at = now()
RETURNING id, domain, title, external_id, difficulty, metadata, created_by, archived_at, archive_batch_id, created_at, updated_at;

-- name: InsertLearningTargetRelation :exec
-- Idempotent insert into learning_target_relations. Conflicts on
-- (anchor_id, related_id, relation_type) are ignored so re-recording
-- the same relationship during a later session is safe. created_by is
-- captured on first insert; conflicts preserve the original author (the
-- column is absent from the UPDATE clause, and DO NOTHING means no
-- UPDATE runs at all). The symmetry trigger propagates created_by onto
-- the auto-inserted reverse edge so both directions trace to the same
-- author.
INSERT INTO learning_target_relations (anchor_id, related_id, relation_type, created_by)
VALUES (@anchor_id, @related_id, @relation_type, @created_by)
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
INSERT INTO learning_attempt_observations (attempt_id, concept_id, signal_type, category, severity, detail, confidence, position)
VALUES (@attempt_id, @concept_id, @signal_type, @category, @severity, @detail, @confidence, @position)
RETURNING id, attempt_id, concept_id, signal_type, category, severity, detail, confidence, position, created_at;

-- name: ObservationCategoriesByDomain :many
-- Lists valid observation_categories.slug values for a given domain. Used
-- by record_attempt to pre-validate obs.category at the MCP boundary so
-- a typo produces an actionable error ("category 'X' not valid for domain
-- 'leetcode'; valid: ...") instead of a raw 23503 FK violation from the
-- INSERT. Domain filter is required — the closed taxonomy is per-domain.
SELECT slug
FROM observation_categories
WHERE domain = @domain
ORDER BY slug;

-- name: FindOrCreateConcept :one
-- Upsert a concept by domain + slug. created_by captured on first
-- INSERT; ON CONFLICT preserves the original author (column absent from
-- the UPDATE list). The U2 archive rule reads created_by, so a re-
-- resolved concept never loses its first-touch agent.
INSERT INTO concepts (slug, name, domain, kind, created_by)
VALUES (@slug, @name, @domain, @kind, @created_by)
ON CONFLICT (domain, LOWER(slug))
DO UPDATE SET updated_at = now()
RETURNING id, slug, name, domain, kind, parent_id, description, created_by, archived_at, archive_batch_id, created_at, updated_at;

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

-- name: ObservationsByAttemptIDs :many
-- Batched observation fetch for attempt_history — all three modes
-- (target / concept_slug / session_id) use this after loading attempts
-- to populate Attempt.Observations. Returns one row per observation,
-- ordered by (attempt_id, position ASC) so each attempt's observations
-- come in the coach-recorded insertion order. Empty @attempt_ids
-- array produces zero rows cleanly.
SELECT ao.id, ao.attempt_id, ao.concept_id, ao.signal_type, ao.category, ao.severity, ao.detail,
       ao.confidence, ao.position,
       c.slug AS concept_slug, c.name AS concept_name
FROM learning_attempt_observations ao
JOIN concepts c ON c.id = ao.concept_id
WHERE ao.attempt_id = ANY(@attempt_ids::uuid[])
ORDER BY ao.attempt_id, ao.position ASC;

-- name: ConceptMastery :many
-- Per-concept mastery with signal counts from attempt_observations
-- within (@since, @until]. Used by learning_dashboard mastery view
-- (@until=NULL → "up to now") and weekly_summary (@until=weekEnd → "as
-- of end of that week"; without an upper bound a historical week_of
-- request would eat data from later weeks).
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
WHERE c.archived_at IS NULL
  AND (sqlc.narg('domain')::text IS NULL OR c.domain = sqlc.narg('domain'))
  AND a.attempted_at >= @since
  AND (sqlc.narg('until')::timestamptz IS NULL OR a.attempted_at < sqlc.narg('until')::timestamptz)
  AND (@confidence_filter::text = 'all' OR ao.confidence = 'high')
GROUP BY c.id
ORDER BY total_observations DESC;

-- name: ConceptsTouchedBetween :one
-- Counts distinct concepts observed in attempts within [start_at, end_at).
-- Returns both high-confidence-only and all-confidence counts so the caller
-- (weekly_summary) can show both metrics. The difference is the number of
-- low-confidence observations not yet behavior-validated.
SELECT
    COUNT(DISTINCT ao.concept_id) FILTER (WHERE ao.confidence = 'high')::int AS concepts_touched_high,
    COUNT(DISTINCT ao.concept_id)::int                                       AS concepts_touched_all
FROM learning_attempt_observations ao
JOIN learning_attempts a ON a.id = ao.attempt_id
JOIN concepts c          ON c.id = ao.concept_id
WHERE a.attempted_at >= @start_at
  AND a.attempted_at < @end_at
  AND c.archived_at IS NULL;

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
  AND c.archived_at IS NULL
  AND (sqlc.narg('domain')::text IS NULL OR c.domain = sqlc.narg('domain'))
  AND a.attempted_at >= @since
  AND (@confidence_filter::text = 'all' OR ao.confidence = 'high')
GROUP BY c.slug, c.name, c.domain, ao.category
ORDER BY critical_count DESC, occurrence_count DESC;

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
WHERE ltr.archived_at IS NULL
  AND anchor.archived_at IS NULL
  AND related.archived_at IS NULL
  AND (sqlc.narg('domain')::text IS NULL OR anchor.domain = sqlc.narg('domain'))
ORDER BY ltr.created_at DESC
LIMIT @max_results;

-- name: ConceptByDomainSlug :one
-- Get a single concept by domain + slug for drilldown. Live-only — an
-- archived concept surfaces through attempt_history's archived branch,
-- not through this lookup.
SELECT id, slug, name, domain, kind, parent_id, description, created_at, updated_at
FROM concepts
WHERE domain = @domain AND LOWER(slug) = LOWER(@slug) AND archived_at IS NULL;

-- name: ConceptsBySlug :many
-- Batch-resolve concept IDs by slug (cross-domain). Returns one row per matched
-- slug. Unmatched slugs produce no row — callers compare result count vs input
-- count to detect missing slugs. Archived concepts are NOT returned so an
-- archived concept slug looks identical to "never existed" — callers may
-- need to disambiguate via the live ConceptByDomainSlug + a follow-up
-- archived lookup if necessary.
SELECT id, slug FROM concepts WHERE slug = ANY(@slugs::text[]) AND archived_at IS NULL;

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

-- name: ConceptsForList :many
-- One row per non-archived concept matching the domain/kind/q filters.
-- LEFT JOIN against learning_attempt_observations so concepts with zero
-- observations in the (since, now) window still appear with all counts
-- zero — this is the catalog view, not the dashboard's
-- observation-backed shape.
--
-- @confidence_filter ('high' default | 'all') is applied inside the
-- LEFT JOIN's ON clause so unmatched-by-filter observations are simply
-- not joined, instead of eliminating the concept from the result set.
--
-- next_due_target_* come from concept_earliest_card, a CTE that picks the
-- earliest-due review card across every live learning_target linked to
-- the concept. NULL on every column when the concept has no linked
-- targets with cards.
--
-- parent_slug is the concept's parent slug, NULL for root concepts.
WITH concept_earliest_card AS (
    SELECT DISTINCT ON (ltc.concept_id)
           ltc.concept_id,
           lt.id    AS target_id,
           lt.title AS target_title,
           rc.due   AS due_at
    FROM learning_target_concepts ltc
    JOIN review_cards rc      ON rc.learning_target_id = ltc.learning_target_id
    JOIN learning_targets lt  ON lt.id = ltc.learning_target_id
    WHERE lt.archived_at IS NULL
    ORDER BY ltc.concept_id, rc.due ASC
)
SELECT c.id, c.slug, c.name, c.domain, c.kind,
       parent.slug AS parent_slug,
       COUNT(ao.id) FILTER (WHERE ao.signal_type = 'weakness')    AS weakness_count,
       COUNT(ao.id) FILTER (WHERE ao.signal_type = 'improvement') AS improvement_count,
       COUNT(ao.id) FILTER (WHERE ao.signal_type = 'mastery')     AS mastery_count,
       COUNT(ao.id)                                               AS total_observations,
       cec.target_id    AS next_due_target_id,
       cec.target_title AS next_due_target_title,
       cec.due_at       AS next_due_at
FROM concepts c
LEFT JOIN concepts parent ON parent.id = c.parent_id
LEFT JOIN learning_attempt_observations ao
       ON ao.concept_id = c.id
      AND (@confidence_filter::text = 'all' OR ao.confidence = 'high')
LEFT JOIN learning_attempts a
       ON a.id = ao.attempt_id
      AND a.attempted_at >= @since
LEFT JOIN concept_earliest_card cec ON cec.concept_id = c.id
WHERE c.archived_at IS NULL
  AND (sqlc.narg('domain')::text IS NULL OR c.domain = sqlc.narg('domain'))
  AND (sqlc.narg('kind')::text   IS NULL OR c.kind::text = sqlc.narg('kind'))
  AND (sqlc.narg('q')::text      IS NULL
       OR c.name ILIKE '%' || sqlc.narg('q')::text || '%'
       OR c.slug ILIKE '%' || sqlc.narg('q')::text || '%')
GROUP BY c.id, parent.slug, cec.target_id, cec.target_title, cec.due_at
ORDER BY c.domain ASC, c.slug ASC;

-- name: ConceptMasteryCountsForConcept :one
-- Two-axis signal counts for a single concept, returned in one round
-- trip. Filtered counts honour the caller's confidence_filter
-- ('high' default | 'all') and drive mastery_stage via
-- DeriveMasteryStage. Low-only counts are independent of the filter so
-- the dashboard's "low_confidence_counts" field is always populated
-- with the same number regardless of confidence_filter.
SELECT
    COUNT(*) FILTER (WHERE (@confidence_filter::text = 'all' OR ao.confidence = 'high')
                       AND ao.signal_type = 'weakness')    AS weakness_count,
    COUNT(*) FILTER (WHERE (@confidence_filter::text = 'all' OR ao.confidence = 'high')
                       AND ao.signal_type = 'improvement') AS improvement_count,
    COUNT(*) FILTER (WHERE (@confidence_filter::text = 'all' OR ao.confidence = 'high')
                       AND ao.signal_type = 'mastery')     AS mastery_count,
    COUNT(*) FILTER (WHERE ao.confidence = 'low'
                       AND ao.signal_type = 'weakness')    AS low_weakness_count,
    COUNT(*) FILTER (WHERE ao.confidence = 'low'
                       AND ao.signal_type = 'improvement') AS low_improvement_count,
    COUNT(*) FILTER (WHERE ao.confidence = 'low'
                       AND ao.signal_type = 'mastery')     AS low_mastery_count
FROM learning_attempt_observations ao
WHERE ao.concept_id = @concept_id;

-- name: ConceptParentChildren :many
-- Returns one row per linked concept tagged by role: 'parent' (zero or
-- one row, from concepts.parent_id) and 'child' (zero or more rows, the
-- inverse). Single round trip via UNION ALL. Both sides skip archived
-- rows so a soft-deleted parent or child does not surface in the UI.
SELECT 'parent'::text AS role, p.slug, p.name
FROM concepts c
JOIN concepts p ON p.id = c.parent_id
WHERE c.id = @concept_id AND p.archived_at IS NULL
UNION ALL
SELECT 'child'::text AS role, ch.slug, ch.name
FROM concepts ch
WHERE ch.parent_id = @concept_id AND ch.archived_at IS NULL
ORDER BY role ASC, slug ASC;

-- name: RecentObservationsByConcept :many
-- Concept-scoped recent observations with the dashboard's wire field
-- shape (signal_type/detail get renamed to signal/body in Go). Joins
-- concepts for the slug + domain side fields so the response carries
-- everything a §4.1 recent_observations row needs without a second
-- lookup. COALESCE collapses NULL detail to '' since body is
-- non-nullable on the wire.
SELECT ao.id,
       ao.signal_type,
       ao.category,
       COALESCE(ao.detail, '')::text AS body,
       c.domain,
       c.slug AS concept_slug,
       ao.confidence,
       ao.created_at
FROM learning_attempt_observations ao
JOIN concepts c ON c.id = ao.concept_id
WHERE ao.concept_id = @concept_id
ORDER BY ao.created_at DESC
LIMIT @max_results;

-- name: RecentAttemptsByConceptSlim :many
-- Slim attempt projection for /concepts/:slug detail. Returns just
-- (id, target_title, outcome, attempted_at) — no metadata, no
-- external_id, no paradigm — so the wire payload stays small.
-- DISTINCT ON dedups attempts that recorded multiple observations on
-- the same concept; priority within an attempt is weakness > improvement
-- > mastery so the surfaced row matches the highest-signal observation.
SELECT id, target_title, outcome, attempted_at
FROM (
    SELECT DISTINCT ON (a.id)
           a.id,
           lt.title AS target_title,
           a.outcome,
           a.attempted_at,
           ao.signal_type
    FROM learning_attempts a
    JOIN learning_targets lt              ON lt.id = a.learning_target_id
    JOIN learning_attempt_observations ao ON ao.attempt_id = a.id
    WHERE ao.concept_id = @concept_id
    ORDER BY a.id,
             CASE ao.signal_type WHEN 'weakness' THEN 0 WHEN 'improvement' THEN 1 WHEN 'mastery' THEN 2 END
) deduped
ORDER BY attempted_at DESC
LIMIT @max_results;

-- name: DashboardConceptRows :many
-- Per-concept mastery rows for /learning/dashboard concepts.rows.
-- INNER JOIN against learning_attempt_observations keeps the dashboard
-- observation-backed — concepts with zero observations in the (since, now)
-- window do not appear (separate decision from /concepts list which
-- LEFT-JOINs to include unobserved concepts).
--
-- next_due is the earliest review_cards.due across every learning_target
-- linked to the concept via learning_target_concepts. NULL when the
-- concept has no live targets with cards. Pre-aggregated in the
-- concept_next_due CTE then LEFT JOINed so sqlc infers nullability —
-- sqlc cannot infer NULLability from a bare correlated subquery, but a
-- LEFT JOIN against a CTE with a casted aggregate gives it a *time.Time
-- in Go.
--
-- @confidence_filter mirrors ConceptMastery: 'high' (default) or 'all'.
-- Stage derivation lives in Go (mastery.DeriveMasteryStage), and the
-- floor applies only to the stage — mastery_value is a raw ratio derived
-- in Go (mastery.MasteryValue).
WITH concept_next_due AS (
    SELECT ltc.concept_id, MIN(rc.due)::timestamptz AS next_due
    FROM learning_target_concepts ltc
    JOIN review_cards rc     ON rc.learning_target_id = ltc.learning_target_id
    JOIN learning_targets lt ON lt.id = ltc.learning_target_id
    WHERE lt.archived_at IS NULL
    GROUP BY ltc.concept_id
)
SELECT c.id, c.slug, c.name, c.domain, c.kind,
       COUNT(*) FILTER (WHERE ao.signal_type = 'weakness')    AS weakness_count,
       COUNT(*) FILTER (WHERE ao.signal_type = 'improvement') AS improvement_count,
       COUNT(*) FILTER (WHERE ao.signal_type = 'mastery')     AS mastery_count,
       COUNT(*)                                               AS total_observations,
       cnd.next_due
FROM concepts c
JOIN learning_attempt_observations ao ON ao.concept_id = c.id
JOIN learning_attempts a              ON a.id = ao.attempt_id
LEFT JOIN concept_next_due cnd        ON cnd.concept_id = c.id
WHERE c.archived_at IS NULL
  AND (sqlc.narg('domain')::text IS NULL OR c.domain = sqlc.narg('domain'))
  AND a.attempted_at >= @since
  AND (@confidence_filter::text = 'all' OR ao.confidence = 'high')
GROUP BY c.id, cnd.next_due
ORDER BY total_observations DESC, c.slug ASC;

-- name: DashboardDueReviews :many
-- Due review cards for /learning/dashboard due_today.items.
-- Per-row fields:
--   card_state — opaque FSRS state JSONB; the Go layer extracts Stability
--                and computes retrievability via fsrs.Store.Retention.
--   last_reviewed_at — MAX(review_logs.reviewed_at) for the card.
--                NULL when the card has never been reviewed (fresh card
--                inserted by a record_attempt flow without an immediate
--                review log).
-- last_reviewed_at is pre-aggregated in the card_last_review CTE then
-- LEFT JOINed. Same reason as DashboardConceptRows.next_due — the
-- LEFT-JOIN-against-CTE shape is what makes sqlc emit *time.Time
-- instead of falling back to interface{}.
WITH card_last_review AS (
    SELECT rl.card_id, MAX(rl.reviewed_at)::timestamptz AS last_reviewed_at
    FROM review_logs rl
    GROUP BY rl.card_id
)
SELECT rc.id                AS card_id,
       rc.due,
       rc.card_state,
       lt.id                AS target_id,
       lt.title             AS target_title,
       lt.domain            AS domain,
       clr.last_reviewed_at
FROM review_cards rc
JOIN learning_targets lt        ON lt.id = rc.learning_target_id
LEFT JOIN card_last_review clr  ON clr.card_id = rc.id
WHERE rc.due <= @due_before
  AND lt.archived_at IS NULL
  AND (sqlc.narg('domain')::text IS NULL OR lt.domain = sqlc.narg('domain'))
ORDER BY rc.due ASC
LIMIT @max_results;

-- name: DashboardRecentObservations :many
-- Recent observations for /learning/dashboard recent_observations.
-- Field renames at the wire boundary (signal_type → signal, detail →
-- body) happen in Go — the SQL preserves the schema names so this query
-- can also feed non-dashboard paths if needed. COALESCE on detail
-- collapses NULL → '' to match the wire contract that 'body' is a
-- non-nullable string.
SELECT ao.id,
       ao.signal_type,
       ao.category,
       COALESCE(ao.detail, '')::text AS body,
       c.domain,
       c.slug AS concept_slug,
       ao.confidence,
       ao.created_at
FROM learning_attempt_observations ao
JOIN concepts c          ON c.id = ao.concept_id
JOIN learning_attempts a ON a.id = ao.attempt_id
WHERE c.archived_at IS NULL
  AND (sqlc.narg('domain')::text IS NULL OR c.domain = sqlc.narg('domain'))
  AND (@confidence_filter::text = 'all' OR ao.confidence = 'high')
ORDER BY ao.created_at DESC
LIMIT @max_results;

-- name: AttemptsByConcept :many
-- Attempts that produced an observation about the given concept, newest
-- first. Each row carries a matched_observation_id pointer — the id of
-- the highest-priority observation on that attempt that linked it to
-- the queried concept. The caller uses this pointer to locate which
-- observation in Attempt.Observations drove the match.
--
-- Shape note: the full set of observations (including the matched one)
-- is fetched separately via ObservationsByAttemptIDs and assembled in
-- Go. This query intentionally does NOT duplicate observation payload
-- here — one authoritative shape (Observation) across all code paths,
-- no MatchedObservation parallel struct.
--
-- The inner SELECT uses DISTINCT ON (a.id) to keep one row per attempt
-- even when a single attempt recorded multiple observations on the same
-- concept; the picked observation is highest-priority by signal (weakness
-- > improvement > mastery) then severity (critical > moderate > minor).
-- The outer SELECT re-sorts by attempted_at DESC because DISTINCT ON
-- forces the inner ORDER BY to lead with a.id.
--
-- Priority order when an attempt has multiple observations on the
-- concept: weakness signals first, then improvement, then mastery.
-- Within the same signal, classified severities beat NULL (NULL =
-- unclassified, which can only happen for weakness since the schema
-- CHECK forbids non-NULL severity on improvement/mastery rows).
SELECT id, learning_target_id, session_id, attempt_number, paradigm, outcome,
       duration_minutes, stuck_at, approach_used, attempted_at, metadata,
       target_title, target_external_id, difficulty,
       matched_observation_id
FROM (
    SELECT DISTINCT ON (a.id)
           a.id, a.learning_target_id, a.session_id, a.attempt_number, a.paradigm, a.outcome,
           a.duration_minutes, a.stuck_at, a.approach_used, a.attempted_at, a.metadata,
           lt.title AS target_title, lt.external_id AS target_external_id, lt.difficulty,
           ao.id AS matched_observation_id
    FROM learning_attempts a
    JOIN learning_targets lt ON lt.id = a.learning_target_id
    JOIN learning_attempt_observations ao ON ao.attempt_id = a.id
    WHERE ao.concept_id = @concept_id
    ORDER BY a.id,
             CASE ao.signal_type WHEN 'weakness' THEN 0 WHEN 'improvement' THEN 1 WHEN 'mastery' THEN 2 END,
             CASE ao.severity WHEN 'critical' THEN 0 WHEN 'moderate' THEN 1 WHEN 'minor' THEN 2 ELSE 3 END
) deduped
ORDER BY attempted_at DESC
LIMIT @max_results;

-- name: LearningTargetsByConcept :many
-- Learning targets linked to a concept. For concept drilldown related
-- targets — live-only. Archived targets stay attached to the concept
-- (the junction row is preserved) but don't surface in the drilldown.
SELECT lt.id, lt.title, lt.domain, lt.difficulty, lt.external_id, ltc.relevance
FROM learning_targets lt
JOIN learning_target_concepts ltc ON ltc.learning_target_id = lt.id
WHERE ltc.concept_id = @concept_id
  AND lt.archived_at IS NULL
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

-- ============================================================
-- session_progress — in-session aggregate queries for the
-- currently-active learning session. Backs MCP session_progress
-- tool. Per-session rowset is tiny (2-10 attempts / 5-30
-- observations); queries rely on idx_learning_attempts_session +
-- idx_learning_attempt_observations_attempt for filter/join.
-- ============================================================

-- name: SessionProgressStats :one
-- Single-row aggregate for the session: attempt count, paradigm split
-- (problem_solving vs immersive), and total minutes per paradigm.
-- Returns a row even with zero attempts (all counts zero).
SELECT
    COUNT(*)::bigint AS attempt_count,
    COUNT(*) FILTER (WHERE paradigm = 'problem_solving')::bigint AS problem_solving_count,
    COUNT(*) FILTER (WHERE paradigm = 'immersive')::bigint       AS immersive_count,
    COALESCE(SUM(duration_minutes) FILTER (WHERE paradigm = 'problem_solving'), 0)::bigint AS problem_solving_minutes,
    COALESCE(SUM(duration_minutes) FILTER (WHERE paradigm = 'immersive'), 0)::bigint       AS immersive_minutes
FROM learning_attempts
WHERE session_id = @session_id;

-- name: SessionProgressConceptDist :many
-- Observation rollup by specific concept for the session. One row per
-- (slug, name, kind) touched. Sorted count DESC, slug ASC so ties are
-- deterministic.
SELECT c.slug, c.name, c.kind::text AS kind, COUNT(*)::bigint AS observation_count
FROM learning_attempt_observations ao
JOIN learning_attempts a ON a.id = ao.attempt_id
JOIN concepts c          ON c.id = ao.concept_id
WHERE a.session_id = @session_id
GROUP BY c.slug, c.name, c.kind
ORDER BY observation_count DESC, c.slug ASC;

-- name: SessionProgressCategoryDist :many
-- Observation rollup by (signal_type, category) for the session. Sort
-- order: weakness first (dashboards emphasize weaknesses), then
-- improvement, then mastery; within each signal, count DESC; within
-- each count, category ASC.
--
-- observation_count in ORDER BY is an alias reference, not a column name —
-- PostgreSQL permits alias references in ORDER BY as a non-standard
-- extension. ELSE 99 routes any future signal_type enum value to the end
-- of the sort rather than silently dropping it.
SELECT ao.signal_type, ao.category, COUNT(*)::bigint AS observation_count
FROM learning_attempt_observations ao
JOIN learning_attempts a ON a.id = ao.attempt_id
WHERE a.session_id = @session_id
GROUP BY ao.signal_type, ao.category
ORDER BY
    CASE ao.signal_type
        WHEN 'weakness'    THEN 1
        WHEN 'improvement' THEN 2
        WHEN 'mastery'     THEN 3
        ELSE 99
    END,
    observation_count DESC,
    ao.category ASC;

-- name: LastEndedSession :one
-- Most recent ended session for the {active: false} affordance path of
-- session_progress — lets the caller pivot to
-- attempt_history(session_id=...) without a separate lookup. Returns
-- pgx.ErrNoRows if no session was ever ended.
SELECT id, domain, session_mode, agent_note_id, daily_plan_item_id, started_at, ended_at, metadata, created_at, updated_at
FROM learning_sessions
WHERE ended_at IS NOT NULL
ORDER BY ended_at DESC
LIMIT 1;

-- ============================================================
-- weekly_summary self_audit — verification metrics for the Phase 2 fixes
-- (CF-04 skip-reason audit, CF-06 solved_after_solution mapping). Scope
-- is intentionally narrow: counts that prove "behavior is changing" or
-- "force/anti-pattern usage is rare". See learning-studio audit
-- decisions memo §E for the P0 metric rationale; recommendation
-- acceptance rate is deliberately NOT here because it needs new
-- tracking infrastructure (memo §E.4).
-- ============================================================

-- name: SelfAuditAttemptOutcomeRate :one
-- Returns solved_after_solution numerator + problem_solving denominator
-- for [start, end). The denominator is paradigm-scoped to
-- problem_solving because solved_after_solution is a paradigm-scoped
-- outcome (chk_learning_attempts_paradigm_outcome). Mixing in immersive
-- attempts would dilute the rate artificially.
SELECT
    COUNT(*) FILTER (WHERE outcome = 'solved_after_solution')::bigint AS solved_after_solution_count,
    COUNT(*)::bigint                                                   AS problem_solving_attempt_count
FROM learning_attempts
WHERE paradigm = 'problem_solving'
  AND attempted_at >= @start_at
  AND attempted_at < @end_at;

-- name: SelfAuditRepeatedConcepts :many
-- Concepts touched by >= @min_count distinct attempts in [start, end).
-- Counting unit is distinct attempts (NOT observations) because a
-- single attempt with multiple observations on the same concept should
-- count once — the metric is "did the user repeatedly practise this
-- concept", not "how chatty are the observations".
-- Excludes archived concepts. Sorted attempt_count DESC then slug ASC
-- for deterministic ordering on ties.
-- min_count is cast to bigint explicitly because the project sqlc.yaml
-- maps the default `uuid` override onto any unannotated named parameter
-- — without the cast sqlc would resolve @min_count as uuid.UUID and the
-- query wouldn't even compile in Go.
SELECT c.slug AS concept_slug,
       COUNT(DISTINCT a.id)::bigint AS attempt_count
FROM learning_attempt_observations ao
JOIN learning_attempts a ON a.id = ao.attempt_id
JOIN concepts c          ON c.id = ao.concept_id
WHERE a.attempted_at >= @start_at
  AND a.attempted_at < @end_at
  AND c.archived_at IS NULL
GROUP BY c.slug
HAVING COUNT(DISTINCT a.id) >= @min_count::bigint
ORDER BY attempt_count DESC, c.slug ASC;
