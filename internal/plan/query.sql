-- name: CreatePlan :one
INSERT INTO plans (title, description, domain, goal_id, status, target_count, plan_config, created_by)
VALUES (@title, @description, @domain, @goal_id, @status, @target_count, @plan_config, @created_by)
RETURNING *;

-- name: Plan :one
SELECT * FROM plans WHERE id = @id;

-- name: PlansByDomain :many
-- Filter plans by domain, optionally by status.
SELECT * FROM plans
WHERE domain = @domain
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
ORDER BY created_at DESC;

-- name: PlansByGoal :many
SELECT * FROM plans WHERE goal_id = @goal_id
ORDER BY created_at DESC;

-- name: ActivePlans :many
-- Plans that are draft or active (for plan management views).
SELECT * FROM plans WHERE status IN ('draft', 'active')
ORDER BY updated_at DESC;

-- name: UpdatePlanStatus :one
UPDATE plans SET status = @status, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: AddPlanItem :one
INSERT INTO plan_items (plan_id, learning_item_id, position, phase)
VALUES (@plan_id, @learning_item_id, @position, @phase)
RETURNING *;

-- name: PlanItem :one
SELECT * FROM plan_items WHERE id = @id;

-- name: PlanItems :many
-- All items in a plan, ordered by position.
SELECT * FROM plan_items WHERE plan_id = @plan_id
ORDER BY position;

-- name: PlanItemsDetailed :many
-- Plan items joined with the items table, ordered by position.
-- Used by manage_plan(progress) so the caller has plan_item_id + display title
-- available without a second round-trip.
SELECT lpi.id, lpi.plan_id, lpi.learning_item_id, lpi.position, lpi.status, lpi.phase,
       lpi.substituted_by, lpi.completed_by_attempt_id, lpi.reason, lpi.added_at, lpi.completed_at,
       li.title       AS item_title,
       li.domain      AS item_domain,
       li.difficulty  AS item_difficulty,
       li.external_id AS item_external_id
FROM plan_items lpi
JOIN items li ON li.id = lpi.learning_item_id
WHERE lpi.plan_id = @plan_id
ORDER BY lpi.position;

-- name: PlanItemsByLearningItem :many
-- Find plan items for a learning_item across ACTIVE plans only.
-- Used by record_attempt to provide plan context. Excludes draft/paused/completed/abandoned.
SELECT lpi.id, lpi.plan_id, lpi.learning_item_id, lpi.position, lpi.status, lpi.phase,
       lpi.substituted_by, lpi.completed_by_attempt_id, lpi.reason, lpi.added_at, lpi.completed_at,
       lp.title AS plan_title
FROM plan_items lpi
JOIN plans lp ON lp.id = lpi.plan_id
WHERE lpi.learning_item_id = @learning_item_id
  AND lp.status = 'active';

-- name: UpdatePlanItemStatus :one
UPDATE plan_items
SET status = @status, reason = @reason, completed_at = @completed_at,
    substituted_by = @substituted_by, completed_by_attempt_id = @completed_by_attempt_id
WHERE id = @id
RETURNING *;

-- name: UpdatePlanItemPosition :execrows
UPDATE plan_items SET position = @position WHERE id = @id;

-- name: PlanProgress :one
-- Aggregate progress stats for a plan.
SELECT
    count(*)::int AS total,
    count(*) FILTER (WHERE status = 'completed')::int AS completed,
    count(*) FILTER (WHERE status = 'skipped')::int AS skipped,
    count(*) FILTER (WHERE status = 'substituted')::int AS substituted,
    count(*) FILTER (WHERE status = 'planned')::int AS remaining
FROM plan_items WHERE plan_id = @plan_id;

-- name: DeletePlanItem :exec
DELETE FROM plan_items WHERE id = @id;

-- name: DeletePlanItems :exec
-- Batch delete plan items by plan_id and item IDs (for remove_items action on draft plans).
DELETE FROM plan_items WHERE plan_id = @plan_id AND id = ANY(@item_ids::uuid[]);
