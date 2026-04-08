-- name: CreatePlan :one
INSERT INTO plans (title, description, domain, goal_id, status, target_count, plan_config, created_by)
VALUES (@title, @description, @domain, @goal_id, @status, @target_count, @plan_config, @created_by)
RETURNING id, title, description, domain, goal_id, status, target_count, plan_config, created_by, created_at, updated_at;

-- name: Plan :one
SELECT id, title, description, domain, goal_id, status, target_count, plan_config, created_by, created_at, updated_at
FROM plans WHERE id = @id;

-- name: PlansByDomain :many
-- Filter plans by domain, optionally by status.
SELECT id, title, description, domain, goal_id, status, target_count, plan_config, created_by, created_at, updated_at
FROM plans
WHERE domain = @domain
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
ORDER BY created_at DESC;

-- name: PlansByGoal :many
SELECT id, title, description, domain, goal_id, status, target_count, plan_config, created_by, created_at, updated_at
FROM plans WHERE goal_id = @goal_id
ORDER BY created_at DESC;

-- name: ActivePlans :many
-- Plans that are draft or active (for plan management views).
SELECT id, title, description, domain, goal_id, status, target_count, plan_config, created_by, created_at, updated_at
FROM plans WHERE status IN ('draft', 'active')
ORDER BY updated_at DESC;

-- name: UpdatePlanStatus :one
UPDATE plans SET status = @status, updated_at = now()
WHERE id = @id
RETURNING id, title, description, domain, goal_id, status, target_count, plan_config, created_by, created_at, updated_at;

-- name: AddPlanItem :one
INSERT INTO plan_items (plan_id, learning_item_id, position, phase)
VALUES (@plan_id, @learning_item_id, @position, @phase)
RETURNING id, plan_id, learning_item_id, position, status, phase, substituted_by, reason, added_at, completed_at;

-- name: PlanItem :one
SELECT id, plan_id, learning_item_id, position, status, phase, substituted_by, reason, added_at, completed_at
FROM plan_items WHERE id = @id;

-- name: PlanItems :many
-- All items in a plan, ordered by position.
SELECT id, plan_id, learning_item_id, position, status, phase, substituted_by, reason, added_at, completed_at
FROM plan_items WHERE plan_id = @plan_id
ORDER BY position;

-- name: PlanItemsByLearningItem :many
-- Find plan items for a learning_item across ACTIVE plans only.
-- Used by record_attempt to provide plan context. Excludes draft/paused/completed/abandoned.
SELECT lpi.id, lpi.plan_id, lpi.learning_item_id, lpi.position, lpi.status, lpi.phase,
       lpi.substituted_by, lpi.reason, lpi.added_at, lpi.completed_at,
       lp.title AS plan_title
FROM plan_items lpi
JOIN plans lp ON lp.id = lpi.plan_id
WHERE lpi.learning_item_id = @learning_item_id
  AND lp.status = 'active';

-- name: UpdatePlanItemStatus :one
UPDATE plan_items
SET status = @status, reason = @reason, completed_at = @completed_at, substituted_by = @substituted_by
WHERE id = @id
RETURNING id, plan_id, learning_item_id, position, status, phase, substituted_by, reason, added_at, completed_at;

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
