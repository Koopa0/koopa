-- name: CreateItem :one
-- Insert a daily plan item, or reorder it when it is still 'planned' for the
-- date. The ON CONFLICT guard (WHERE status = 'planned') refuses to touch a
-- row that already reached a terminal state (done/deferred/dropped): the
-- conflicting UPDATE matches no row, so RETURNING is empty and the driver
-- yields pgx.ErrNoRows. The store maps that to ErrItemResolved so re-planning
-- cannot silently resurrect a resolved item. A fresh insert (no conflict)
-- always returns its row, defaulting status to 'planned'.
INSERT INTO daily_plan_items (plan_date, todo_id, selected_by, position, reason)
VALUES (@plan_date, @todo_id, @selected_by, @position, @reason)
ON CONFLICT (plan_date, todo_id) DO UPDATE SET
    selected_by = EXCLUDED.selected_by,
    position = EXCLUDED.position,
    reason = EXCLUDED.reason,
    updated_at = now()
WHERE daily_plan_items.status = 'planned'
RETURNING id, plan_date, todo_id, selected_by, position, reason, status, created_at, updated_at;

-- name: ItemsByDate :many
-- Get all daily plan items for a specific date, joined with todo item details.
-- created_at breaks position ties so the order is deterministic when a terminal
-- row and a planned row share a position slot (position is unique among
-- 'planned' rows only).
SELECT
    dpi.id, dpi.plan_date, dpi.todo_id, dpi.selected_by, dpi.position,
    dpi.reason, dpi.status, dpi.created_at, dpi.updated_at,
    t.title AS todo_title, t.state AS todo_state, t.due AS todo_due,
    t.energy AS todo_energy, t.priority AS todo_priority,
    COALESCE(p.title, '') AS project_title, COALESCE(p.slug, '') AS project_slug
FROM daily_plan_items dpi
JOIN todos t ON t.id = dpi.todo_id
LEFT JOIN projects p ON p.id = t.project_id
WHERE dpi.plan_date = @plan_date
ORDER BY dpi.position, dpi.created_at;

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
