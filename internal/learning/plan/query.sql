-- name: CreatePlan :one
INSERT INTO learning_plans (title, description, domain, goal_id, status, target_count, plan_config, created_by)
VALUES (@title, @description, @domain, @goal_id, @status, @target_count, @plan_config, @created_by)
RETURNING *;

-- name: Plan :one
SELECT * FROM learning_plans WHERE id = @id;

-- name: PlanGoalName :one
-- Goal title for the plan-detail meta strip. LEFT JOIN + COALESCE yields an
-- empty string when the plan has no goal (goal_id IS NULL); zero rows only
-- when the plan itself does not exist.
SELECT COALESCE(g.title, '')::text AS goal_name
FROM learning_plans lp
LEFT JOIN goals g ON g.id = lp.goal_id
WHERE lp.id = @id;

-- name: PlansByDomain :many
-- Filter plans by domain, optionally by status. Carries per-plan entry
-- counts (total + completed) for the admin list's Entries/Progress columns.
SELECT lp.id, lp.title, lp.description, lp.domain, lp.goal_id, lp.status,
       lp.target_count, lp.plan_config, lp.created_by, lp.created_at, lp.updated_at,
       (SELECT count(*) FROM learning_plan_entries e WHERE e.plan_id = lp.id) AS entry_total,
       (SELECT count(*) FROM learning_plan_entries e WHERE e.plan_id = lp.id AND e.status = 'completed') AS entry_done
FROM learning_plans lp
WHERE lp.domain = @domain
  AND (sqlc.narg('status')::text IS NULL OR lp.status = sqlc.narg('status'))
ORDER BY lp.created_at DESC;

-- name: PlansInManagement :many
-- Plans visible to the management UI: draft + active. Name reflects the
-- actual semantic (a draft plan is not "active" but is in the management
-- backlog), replacing the old ActivePlans lie. Carries per-plan entry
-- counts (total + completed) for the admin list's Entries/Progress columns.
SELECT lp.id, lp.title, lp.description, lp.domain, lp.goal_id, lp.status,
       lp.target_count, lp.plan_config, lp.created_by, lp.created_at, lp.updated_at,
       (SELECT count(*) FROM learning_plan_entries e WHERE e.plan_id = lp.id) AS entry_total,
       (SELECT count(*) FROM learning_plan_entries e WHERE e.plan_id = lp.id AND e.status = 'completed') AS entry_done
FROM learning_plans lp
WHERE lp.status IN ('draft', 'active')
ORDER BY lp.updated_at DESC;

-- name: UpdatePlanStatus :one
UPDATE learning_plans SET status = @status, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: AddPlanEntry :one
INSERT INTO learning_plan_entries (plan_id, learning_target_id, position, phase)
VALUES (@plan_id, @learning_target_id, @position, @phase)
RETURNING *;

-- name: PlanEntry :one
SELECT * FROM learning_plan_entries WHERE id = @id;

-- name: PlanEntries :many
-- All entries in a plan, ordered by position.
SELECT * FROM learning_plan_entries WHERE plan_id = @plan_id
ORDER BY position;

-- name: PlanEntriesDetailed :many
-- Plan entries joined with the learning_targets table, ordered by position.
-- Used by manage_plan(progress) so the caller has plan_entry_id + display title
-- available without a second round-trip.
SELECT lpe.id, lpe.plan_id, lpe.learning_target_id, lpe.position, lpe.status, lpe.phase,
       lpe.substituted_by, lpe.completed_by_attempt_id, lpe.reason, lpe.added_at, lpe.completed_at,
       lt.title       AS target_title,
       lt.domain      AS target_domain,
       lt.difficulty  AS target_difficulty,
       lt.external_id AS target_external_id
FROM learning_plan_entries lpe
JOIN learning_targets lt ON lt.id = lpe.learning_target_id
WHERE lpe.plan_id = @plan_id
ORDER BY lpe.position;

-- name: PlanEntriesByLearningTarget :many
-- Find plan entries for a learning target across ACTIVE plans only.
-- Used by record_attempt to provide plan context. Excludes draft/paused/completed/abandoned.
SELECT lpe.id, lpe.plan_id, lpe.learning_target_id, lpe.position, lpe.status, lpe.phase,
       lpe.substituted_by, lpe.completed_by_attempt_id, lpe.reason, lpe.added_at, lpe.completed_at,
       lp.title AS plan_title
FROM learning_plan_entries lpe
JOIN learning_plans lp ON lp.id = lpe.plan_id
WHERE lpe.learning_target_id = @learning_target_id
  AND lp.status = 'active';

-- name: UpdatePlanEntryStatus :one
UPDATE learning_plan_entries
SET status = @status, reason = @reason, completed_at = @completed_at,
    substituted_by = @substituted_by, completed_by_attempt_id = @completed_by_attempt_id
WHERE id = @id
RETURNING *;

-- name: UpdatePlanEntryPosition :execrows
UPDATE learning_plan_entries SET position = @position WHERE id = @id;

-- name: PlanProgress :one
-- Aggregate progress stats for a plan.
SELECT
    count(*)::int AS total,
    count(*) FILTER (WHERE status = 'completed')::int AS completed,
    count(*) FILTER (WHERE status = 'skipped')::int AS skipped,
    count(*) FILTER (WHERE status = 'substituted')::int AS substituted,
    count(*) FILTER (WHERE status = 'planned')::int AS remaining
FROM learning_plan_entries WHERE plan_id = @plan_id;

-- name: DeletePlanEntries :exec
-- Batch delete plan entries by plan_id and entry IDs (for remove_entries action on draft plans).
DELETE FROM learning_plan_entries WHERE plan_id = @plan_id AND id = ANY(@entry_ids::uuid[]);
