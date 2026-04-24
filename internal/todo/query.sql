-- name: CreateTodoItem :one
-- Create a new todo item.
INSERT INTO todos (title, state, due, project_id, energy, priority, description, created_by)
VALUES (@title, @state::todo_state, @due, @project_id, @energy, @priority, @description, @created_by)
RETURNING id, title, state, due, project_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          description, created_by, created_at, updated_at;

-- name: OverdueTodoItems :many
-- Todo items past due that are not done (for morning_context).
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM todos t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.state NOT IN ('done', 'someday', 'inbox')
  AND t.due IS NOT NULL AND t.due < @today
ORDER BY t.due, t.priority NULLS LAST;

-- name: TodoItemsDueOn :many
-- Todo items due on a specific date (for morning_context today section).
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM todos t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.state NOT IN ('done', 'someday', 'inbox')
  AND t.due = @target_date
ORDER BY t.priority NULLS LAST, t.created_at;

-- name: TodoItemsDueInRange :many
-- Todo items due within a date range (for morning_context upcoming section).
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM todos t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.state NOT IN ('done', 'someday', 'inbox')
  AND t.due > @start_date AND t.due <= @end_date
ORDER BY t.due, t.priority NULLS LAST;

-- name: TodoItems :many
-- List all todo items ordered by state and due date.
SELECT id, title, state, due, project_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, created_by, created_at, updated_at
FROM todos ORDER BY state, due NULLS LAST, created_at DESC;

-- name: PendingTodoItems :many
-- List todo items that are not done, ordered by due date.
SELECT id, title, state, due, project_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, created_by, created_at, updated_at
FROM todos WHERE state != 'done'
ORDER BY due NULLS LAST, created_at;

-- name: PendingTodoItemsWithProject :many
-- List pending todo items with project info.
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM todos t
LEFT JOIN projects p ON t.project_id = p.id
WHERE t.state != 'done'
  AND (sqlc.narg('project_slug')::text IS NULL OR p.slug = sqlc.narg('project_slug'))
ORDER BY
    (t.due IS NOT NULL) DESC,
    t.due ASC NULLS LAST,
    t.updated_at ASC
LIMIT sqlc.arg('max_results');

-- name: TodoItemByID :one
-- Get a todo item by ID.
SELECT id, title, state, due, project_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, created_by, created_at, updated_at
FROM todos WHERE id = @id;

-- name: PendingTodoItemsByTitle :many
-- Find pending todo items matching a title (case-insensitive contains).
SELECT id, title, state, due, project_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, created_by, created_at, updated_at
FROM todos
WHERE state != 'done' AND title ILIKE '%' || @search_title || '%'
ORDER BY due NULLS LAST, updated_at ASC
LIMIT 10;

-- name: UpdateTodoItemState :one
-- Update a todo item's state. Sets completed_at on transition to done.
UPDATE todos SET
    state        = @state::todo_state,
    completed_at = CASE
        WHEN @state::todo_state = 'done' AND completed_at IS NULL THEN now()
        ELSE completed_at
    END,
    updated_at = now()
WHERE id = @id
RETURNING id, title, state, due, project_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          description, created_by, created_at, updated_at;

-- name: TodoDailySummaryHint :one
-- Compute completion metrics hint for a single day.
SELECT
    (SELECT count(*)::int FROM daily_plan_items WHERE plan_date = @plan_date::date) AS planned_total,
    (SELECT count(*)::int FROM daily_plan_items WHERE plan_date = @plan_date::date AND status = 'done') AS planned_completed,
    count(*) FILTER (WHERE state = 'done'
        AND completed_at >= @day_start AND completed_at < @day_end)::int AS total_completed
FROM todos
WHERE state = 'done' AND completed_at >= @day_start AND completed_at < @day_end;

-- name: CompletedTodoTitlesSince :many
-- Get titles of todo items completed since a given time.
SELECT title FROM todos
WHERE state = 'done' AND completed_at >= @since
ORDER BY completed_at DESC
LIMIT 20;

-- name: CompletedTodoDetailSince :many
-- Get todo items completed since a given time with project context.
SELECT t.id, t.title, t.completed_at, t.project_id,
       COALESCE(p.title, '') AS project_title
FROM todos t
LEFT JOIN projects p ON t.project_id = p.id
WHERE t.state = 'done' AND t.completed_at >= @since
ORDER BY t.completed_at DESC;

-- name: TodoItemsCreatedSince :many
-- Get todo items created since a given time with project context.
SELECT t.id, t.title, t.created_at, t.project_id,
       COALESCE(p.title, '') AS project_title
FROM todos t
LEFT JOIN projects p ON t.project_id = p.id
WHERE t.created_at >= @since
ORDER BY t.created_at DESC;

-- name: RecurringTodoItemByProject :one
-- Find a recurring pending todo item under a given project that is due today or overdue.
SELECT id, title, state, due, project_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, created_by, created_at, updated_at
FROM todos
WHERE project_id = @project_id
  AND state != 'done'
  AND recur_interval IS NOT NULL AND recur_interval > 0
  AND due <= @today
ORDER BY due ASC NULLS LAST
LIMIT 1;

-- name: UpdateTodoItem :one
-- Update arbitrary todo item fields. Only non-null parameters are applied.
UPDATE todos SET
    title        = COALESCE(sqlc.narg('new_title'), title),
    state        = COALESCE(sqlc.narg('state')::todo_state, state),
    due          = COALESCE(sqlc.narg('due'), due),
    energy       = COALESCE(sqlc.narg('energy'), energy),
    priority     = COALESCE(sqlc.narg('priority'), priority),
    project_id   = COALESCE(sqlc.narg('new_project_id'), project_id),
    description  = COALESCE(sqlc.narg('new_description'), description),
    completed_at = CASE
        WHEN sqlc.narg('state')::todo_state = 'done' AND completed_at IS NULL THEN now()
        ELSE completed_at
    END,
    updated_at = now()
WHERE id = @id
RETURNING id, title, state, due, project_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          description, created_by, created_at, updated_at;

-- name: SearchTodoItems :many
-- Search todo items by title/description with optional filters.
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.completed_at, t.description, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM todos t
LEFT JOIN projects p ON t.project_id = p.id
WHERE (sqlc.narg('query')::text IS NULL OR (t.title ILIKE '%' || sqlc.narg('query') || '%' OR t.description ILIKE '%' || sqlc.narg('query') || '%'))
  AND (sqlc.narg('project_slug')::text IS NULL OR p.slug = sqlc.narg('project_slug'))
  AND (sqlc.narg('state_filter')::text IS NULL OR
       CASE sqlc.narg('state_filter')
           WHEN 'pending' THEN t.state != 'done'
           WHEN 'done' THEN t.state = 'done'
           ELSE true
       END)
  AND (sqlc.narg('completed_after')::timestamptz IS NULL OR t.completed_at >= sqlc.narg('completed_after'))
  AND (sqlc.narg('completed_before')::timestamptz IS NULL OR t.completed_at < sqlc.narg('completed_before'))
ORDER BY
    CASE WHEN t.state != 'done' THEN 0 ELSE 1 END,
    CASE WHEN t.state != 'done' THEN
        CASE WHEN t.due IS NOT NULL THEN 0 ELSE 1 END
    ELSE 2 END,
    t.due ASC NULLS LAST,
    t.completed_at DESC NULLS LAST,
    t.updated_at ASC
LIMIT sqlc.arg('max_results');

-- === Recurring todo item queries ===

-- name: OverdueRecurringTodoItems :many
-- Get all overdue recurring todo items (due < today, not done).
SELECT id, title, state, due, project_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, created_by, created_at, updated_at
FROM todos
WHERE state != 'done'
  AND recur_interval IS NOT NULL AND recur_interval > 0
  AND due < @today
ORDER BY due ASC;

-- name: RecurringTodoItemsDueToday :many
-- Get recurring todo items due on or before today.
SELECT id, title, state, due, project_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, created_by, created_at, updated_at
FROM todos
WHERE state != 'done'
  AND recur_interval IS NOT NULL AND recur_interval > 0
  AND due <= @today
ORDER BY due ASC;

-- name: UpdateTodoItemDue :execrows
-- Update only the due date for a todo item.
UPDATE todos SET due = @due, updated_at = now() WHERE id = @id;

-- name: ResetRecurringTodoItem :one
-- Reset a recurring todo item after completion: advance due, reset state to todo.
UPDATE todos SET
    due = @due,
    state = 'todo',
    updated_at = now()
WHERE id = @id
RETURNING id, title, state, due, project_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          description, created_by, created_at, updated_at;

-- === Skip log queries ===

-- name: CreateTodoSkipRecord :exec
-- Insert a single skip record. ON CONFLICT ensures idempotency on cron re-run.
INSERT INTO todo_skips (todo_id, original_due, skipped_date, reason)
VALUES (@todo_id, @original_due, @skipped_date, @reason)
ON CONFLICT (todo_id, skipped_date) DO NOTHING;

-- name: TodoSkipHistoryByItem :many
-- Get skip history for a specific todo item within a date range.
SELECT id, todo_id, original_due, skipped_date, reason, created_at
FROM todo_skips
WHERE todo_id = @todo_id
  AND skipped_date >= @since
ORDER BY skipped_date DESC;

-- name: TodoSkipCountByItem :one
-- Count skips for a specific todo item within a date range.
SELECT count(*)::int FROM todo_skips
WHERE todo_id = @todo_id AND skipped_date >= @since;

-- name: TodoSkipHistoryByProject :many
-- Get skip history for all todo items under a project within a date range.
SELECT sl.id, sl.todo_id, sl.original_due, sl.skipped_date, sl.reason, sl.created_at,
       t.title AS item_title
FROM todo_skips sl
JOIN todos t ON t.id = sl.todo_id
WHERE t.project_id = @project_id
  AND sl.skipped_date >= @since
ORDER BY sl.skipped_date DESC;

-- name: TodoInboxCount :one
-- Count of todo items in inbox state (for needs_attention badge).
SELECT count(*)::int FROM todos WHERE state = 'inbox';

-- name: StaleSomedayTodoCount :one
-- Count of someday todo items not updated in N days (GTD review signal).
SELECT count(*)::int FROM todos
WHERE state = 'someday' AND updated_at < @stale_before;

-- name: InboxTodoItems :many
-- List all inbox todo items, newest first.
SELECT * FROM todos WHERE state = 'inbox' ORDER BY created_at DESC;

-- name: ClarifyTodoItem :one
-- Promote inbox todo item to todo state with clarification fields.
UPDATE todos
SET state = 'todo',
    priority = COALESCE(sqlc.narg('priority'), priority),
    energy = COALESCE(sqlc.narg('energy'), energy),
    due = COALESCE(sqlc.narg('due'), due),
    updated_at = now()
WHERE id = @id AND state = 'inbox'
RETURNING *;

-- name: DeleteTodoItem :execrows
-- Hard delete an inbox todo item. State guard prevents accidental deletion.
DELETE FROM todos WHERE id = @id AND state = 'inbox';

-- name: BacklogTodoItems :many
-- Filtered todo item list for admin backlog view.
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM todos t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.state = @state::todo_state
  AND (sqlc.narg('project_id')::uuid IS NULL OR t.project_id = sqlc.narg('project_id'))
  AND (sqlc.narg('energy')::text IS NULL OR t.energy = sqlc.narg('energy'))
  AND (sqlc.narg('priority')::text IS NULL OR t.priority = sqlc.narg('priority'))
  AND (sqlc.narg('search')::text IS NULL OR t.title ILIKE '%' || sqlc.narg('search') || '%')
ORDER BY t.due NULLS LAST, t.priority NULLS LAST, t.created_at DESC
LIMIT @max_results;

-- name: TodoItemsByProjectGrouped :many
-- Todo items for a project, used for admin project detail grouping by state.
SELECT t.id, t.title, t.state, t.due, t.energy, t.priority,
       t.created_at, t.updated_at
FROM todos t
WHERE t.project_id = @project_id
ORDER BY
    CASE t.state
        WHEN 'in_progress' THEN 0
        WHEN 'todo' THEN 1
        WHEN 'inbox' THEN 2
        WHEN 'someday' THEN 3
        WHEN 'done' THEN 4
        ELSE 5
    END,
    t.due NULLS LAST, t.created_at DESC;
