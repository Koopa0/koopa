-- name: CreateItem :one
-- Insert a daily plan item.
INSERT INTO daily_plan_items (plan_date, todo_id, selected_by, position, reason, agent_note_id)
VALUES (@plan_date, @todo_id, @selected_by, @position, @reason, @agent_note_id)
ON CONFLICT (plan_date, todo_id) DO UPDATE SET
    selected_by = EXCLUDED.selected_by,
    position = EXCLUDED.position,
    reason = EXCLUDED.reason,
    agent_note_id = EXCLUDED.agent_note_id,
    status = 'planned',
    updated_at = now()
RETURNING id, plan_date, todo_id, selected_by, position, reason, agent_note_id, status, created_at, updated_at;

-- name: ItemsByDate :many
-- Get all daily plan items for a specific date, joined with todo item details.
SELECT
    dpi.id, dpi.plan_date, dpi.todo_id, dpi.selected_by, dpi.position,
    dpi.reason, dpi.agent_note_id, dpi.status, dpi.created_at, dpi.updated_at,
    t.title AS todo_title, t.state AS todo_state, t.due AS todo_due,
    t.energy AS todo_energy, t.priority AS todo_priority,
    COALESCE(p.title, '') AS project_title, COALESCE(p.slug, '') AS project_slug
FROM daily_plan_items dpi
JOIN todos t ON t.id = dpi.todo_id
LEFT JOIN projects p ON p.id = t.project_id
WHERE dpi.plan_date = @plan_date
ORDER BY dpi.position;

-- name: UpdateItemStatus :one
-- Update the status of a daily plan item.
UPDATE daily_plan_items
SET status = @status, updated_at = now()
WHERE id = @id
RETURNING id, plan_date, todo_id, selected_by, position, reason, agent_note_id, status, created_at, updated_at;

-- name: UpdateItemStatusByTodo :execrows
-- Update the status of a daily plan item by todo_id and date.
-- Used when advance_work completes a todo item to auto-update today's plan item.
-- Returns rows affected so caller can distinguish "updated" from "no matching item".
UPDATE daily_plan_items
SET status = @status, updated_at = now()
WHERE todo_id = @todo_id AND plan_date = @plan_date;

-- name: ItemsByDateRange :many
-- Get daily plan items for a date range (e.g., yesterday's unfinished for morning_context).
SELECT
    dpi.id, dpi.plan_date, dpi.todo_id, dpi.selected_by, dpi.position,
    dpi.reason, dpi.agent_note_id, dpi.status, dpi.created_at, dpi.updated_at,
    t.title AS todo_title, t.state AS todo_state,
    COALESCE(p.title, '') AS project_title
FROM daily_plan_items dpi
JOIN todos t ON t.id = dpi.todo_id
LEFT JOIN projects p ON p.id = t.project_id
WHERE dpi.plan_date >= @start_date AND dpi.plan_date <= @end_date
ORDER BY dpi.plan_date DESC, dpi.position;

-- name: ItemByID :one
-- Get a single daily plan item by ID.
SELECT id, plan_date, todo_id, selected_by, position, reason, agent_note_id, status, created_at, updated_at
FROM daily_plan_items WHERE id = @id;

-- name: DeletePlannedItemsByDate :many
-- Remove only 'planned' items for a date (used when re-planning).
-- Preserves done/deferred/dropped items as historical records.
-- Returns the removed rows so callers can surface "what was displaced"
-- when plan_day idempotently replaces an existing plan; the JOIN to
-- todos exposes the title without forcing a second round-trip.
WITH deleted AS (
    DELETE FROM daily_plan_items
    WHERE plan_date = @plan_date AND status = 'planned'
    RETURNING id, todo_id
)
SELECT d.id, d.todo_id, t.title AS todo_title
FROM deleted d
JOIN todos t ON t.id = d.todo_id;
