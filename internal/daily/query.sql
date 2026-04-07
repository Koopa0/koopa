-- name: CreateItem :one
-- Insert a daily plan item.
INSERT INTO daily_plan_items (plan_date, task_id, selected_by, position, reason, journal_id)
VALUES (@plan_date, @task_id, @selected_by, @position, @reason, @journal_id)
ON CONFLICT (plan_date, task_id) DO UPDATE SET
    selected_by = EXCLUDED.selected_by,
    position = EXCLUDED.position,
    reason = EXCLUDED.reason,
    journal_id = EXCLUDED.journal_id,
    status = 'planned',
    updated_at = now()
RETURNING id, plan_date, task_id, selected_by, position, reason, journal_id, status, created_at, updated_at;

-- name: ItemsByDate :many
-- Get all daily plan items for a specific date, joined with task details.
SELECT
    dpi.id, dpi.plan_date, dpi.task_id, dpi.selected_by, dpi.position,
    dpi.reason, dpi.journal_id, dpi.status, dpi.created_at, dpi.updated_at,
    t.title AS task_title, t.status AS task_status, t.due AS task_due,
    t.energy AS task_energy, t.priority AS task_priority, t.assignee AS task_assignee,
    COALESCE(p.title, '') AS project_title, COALESCE(p.slug, '') AS project_slug
FROM daily_plan_items dpi
JOIN tasks t ON t.id = dpi.task_id
LEFT JOIN projects p ON p.id = t.project_id
WHERE dpi.plan_date = @plan_date
ORDER BY dpi.position;

-- name: UpdateItemStatus :one
-- Update the status of a daily plan item.
UPDATE daily_plan_items
SET status = @status, updated_at = now()
WHERE id = @id
RETURNING id, plan_date, task_id, selected_by, position, reason, journal_id, status, created_at, updated_at;

-- name: UpdateItemStatusByTask :exec
-- Update the status of a daily plan item by task_id and date.
-- Used when advance_work completes a task to auto-update today's plan item.
UPDATE daily_plan_items
SET status = @status, updated_at = now()
WHERE task_id = @task_id AND plan_date = @plan_date;

-- name: ItemsByDateRange :many
-- Get daily plan items for a date range (e.g., yesterday's unfinished for morning_context).
SELECT
    dpi.id, dpi.plan_date, dpi.task_id, dpi.selected_by, dpi.position,
    dpi.reason, dpi.journal_id, dpi.status, dpi.created_at, dpi.updated_at,
    t.title AS task_title, t.status AS task_status,
    COALESCE(p.title, '') AS project_title
FROM daily_plan_items dpi
JOIN tasks t ON t.id = dpi.task_id
LEFT JOIN projects p ON p.id = t.project_id
WHERE dpi.plan_date >= @start_date AND dpi.plan_date <= @end_date
ORDER BY dpi.plan_date DESC, dpi.position;

-- name: DeleteItemsByDate :exec
-- Remove all plan items for a date (used when re-planning).
DELETE FROM daily_plan_items WHERE plan_date = @plan_date;
