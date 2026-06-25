-- name: CreateTodoItem :one
-- Create a new todo item.
INSERT INTO todos (title, state, due, project_id, energy, priority, description, created_by)
VALUES (@title, @state::todo_state, @due, @project_id, @energy, @priority, @description, @created_by)
RETURNING id, title, state, due, project_id,
          completed_at, energy, priority, recur_interval, recur_unit, recur_weekdays, last_completed_on,
          description, created_by, created_at, updated_at;

-- name: OverdueTodoItems :many
-- Todo items past due that are still active (for brief(morning) + Today). Excludes the
-- terminal states (done, archived, dismissed) plus the non-date-relevant
-- someday/inbox holding states, so a self-closed todo never reappears as active.
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit, t.recur_weekdays, t.last_completed_on,
       t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM todos t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.state NOT IN ('done', 'someday', 'inbox', 'archived', 'dismissed')
  AND t.due IS NOT NULL AND t.due < @today
ORDER BY t.due, t.priority NULLS LAST;

-- name: TodoItemsDueOn :many
-- Todo items due on a specific date (for brief(morning) + the Today aggregate, due-today section).
-- Excludes terminal states (done, archived, dismissed) and the someday/inbox
-- holding states so a self-closed todo never reappears in the Today view.
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit, t.recur_weekdays, t.last_completed_on,
       t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM todos t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.state NOT IN ('done', 'someday', 'inbox', 'archived', 'dismissed')
  AND t.due = @target_date
ORDER BY t.priority NULLS LAST, t.created_at;

-- name: TodoItemsDueInRange :many
-- Todo items due within a date range (for brief(morning) + the Today aggregate, upcoming section).
-- Excludes terminal states (done, archived, dismissed) and the someday/inbox
-- holding states so a self-closed todo never reappears in the upcoming view.
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit, t.recur_weekdays, t.last_completed_on,
       t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM todos t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.state NOT IN ('done', 'someday', 'inbox', 'archived', 'dismissed')
  AND t.due > @start_date AND t.due <= @end_date
ORDER BY t.due, t.priority NULLS LAST;

-- name: TodoItems :many
-- List all todo items ordered by state and due date.
SELECT id, title, state, due, project_id,
       completed_at, energy, priority, recur_interval, recur_unit, recur_weekdays, last_completed_on,
       description, created_by, created_at, updated_at
FROM todos ORDER BY state, due NULLS LAST, created_at DESC;

-- name: TodoItemByID :one
-- Get a todo item by ID.
SELECT id, title, state, due, project_id,
       completed_at, energy, priority, recur_interval, recur_unit, recur_weekdays, last_completed_on,
       description, created_by, created_at, updated_at
FROM todos WHERE id = @id;

-- name: TodosByCreator :many
-- List todos created by a given agent, newest first. Powers the list_todos
-- MCP readback loop: an agent reads the disposition of the todos it created.
-- created_by is the resolved caller identity (caller-scoped), never a
-- client-supplied filter. Uses idx_todos_created_by (created_by, created_at DESC).
SELECT id, title, state
FROM todos
WHERE created_by = @created_by
ORDER BY created_at DESC;

-- name: ResolveTodoByCreator :one
-- Caller-scoped terminal close for the resolve_todo MCP readback loop: an agent
-- moves a todo IT created to a terminal state (done/archived/dismissed). The
-- created_by predicate scopes the write to the caller's own rows — a mismatched
-- creator (or unknown id) matches 0 rows, surfacing as pgx.ErrNoRows → not-found,
-- never another agent's todo. completed_at follows chk_todo_completed_at_consistency:
-- now() for done (preserving any existing stamp), cleared to NULL otherwise.
-- created_by is the resolved caller identity, never a client-supplied filter.
UPDATE todos SET
    state = @state::todo_state,
    completed_at = CASE
        WHEN @state::todo_state = 'done' THEN COALESCE(completed_at, now())
        ELSE NULL
    END,
    updated_at = now()
WHERE id = @id AND created_by = @created_by
RETURNING id, state;

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
          completed_at, energy, priority, recur_interval, recur_unit, recur_weekdays, last_completed_on,
          description, created_by, created_at, updated_at;

-- name: CompletedTodoDetailSince :many
-- Get todo items completed since a given time with project context.
SELECT t.id, t.title, t.completed_at, t.project_id,
       COALESCE(p.title, '') AS project_title
FROM todos t
LEFT JOIN projects p ON t.project_id = p.id
WHERE t.state = 'done' AND t.completed_at >= @since
ORDER BY t.completed_at DESC;

-- name: UpdateTodoItem :one
-- Update editable todo item fields. State transitions go through
-- UpdateTodoItemState, never here. Only non-null parameters are applied.
UPDATE todos SET
    title        = COALESCE(sqlc.narg('new_title'), title),
    due          = COALESCE(sqlc.narg('due'), due),
    energy       = COALESCE(sqlc.narg('energy'), energy),
    priority     = COALESCE(sqlc.narg('priority'), priority),
    project_id   = COALESCE(sqlc.narg('new_project_id'), project_id),
    description  = COALESCE(sqlc.narg('new_description'), description),
    updated_at = now()
WHERE id = @id
RETURNING id, title, state, due, project_id,
          completed_at, energy, priority, recur_interval, recur_unit, recur_weekdays, last_completed_on,
          description, created_by, created_at, updated_at;

-- name: SearchTodoItems :many
-- Search todo items by title/description with optional filters.
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit, t.recur_weekdays, t.last_completed_on,
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

-- name: RecurringTodoItemsDueToday :many
-- Recurring todos whose occurrence is due on @today, computed on read (no stored
-- next-due, no scheduler). A todo qualifies when it is recurring, active, not
-- already completed today, and the rule matches: weekday-mode → today's ISODOW
-- bit is set in recur_weekdays; interval-mode → @today is at least
-- recur_interval × recur_unit past last_completed_on (or it was never completed).
SELECT id, title, state, due, project_id,
       completed_at, energy, priority, recur_interval, recur_unit, recur_weekdays, last_completed_on,
       description, created_by, created_at, updated_at
FROM todos
WHERE state NOT IN ('done', 'someday', 'inbox', 'archived', 'dismissed')
  AND (recur_weekdays IS NOT NULL OR recur_interval IS NOT NULL)
  AND (last_completed_on IS NULL OR last_completed_on < @today::date)
  AND (
        (recur_weekdays IS NOT NULL
         AND (recur_weekdays & (1 << (EXTRACT(ISODOW FROM @today::date)::int - 1))) <> 0)
     OR (recur_interval IS NOT NULL
         AND (last_completed_on IS NULL
              OR @today::date >= last_completed_on + (recur_interval::text || ' ' || recur_unit)::interval))
      )
ORDER BY priority NULLS LAST, title;

-- name: SetTodoRecurrence :execrows
-- Set (or clear) a todo's recurrence, scoped to the caller's own todos. Pass
-- recur_weekdays for weekday-mode, recur_interval+recur_unit for interval-mode,
-- or all-null to clear. chk_todo_recurrence rejects an invalid combination.
UPDATE todos
SET recur_weekdays = sqlc.narg('recur_weekdays'),
    recur_interval = sqlc.narg('recur_interval'),
    recur_unit     = sqlc.narg('recur_unit'),
    updated_at     = now()
WHERE id = @id AND created_by = @created_by;

-- name: CompleteRecurringOccurrence :execrows
-- Stamp last_completed_on for today's occurrence of a recurring todo WITHOUT
-- moving it to a terminal state (it keeps recurring). Scoped to the caller's own
-- todos and only applies to recurring rows; a non-recurring or non-caller row
-- affects zero rows.
UPDATE todos
SET last_completed_on = @completed_on::date,
    updated_at        = now()
WHERE id = @id AND created_by = @created_by
  AND (recur_weekdays IS NOT NULL OR recur_interval IS NOT NULL);

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

-- name: ActivateTodoItem :one
-- Promote a someday todo item back to todo state. State guard mirrors
-- ClarifyTodoItem: only someday rows transition; anything else is a
-- no-row miss.
UPDATE todos
SET state = 'todo',
    updated_at = now()
WHERE id = @id AND state = 'someday'
RETURNING *;

-- name: DeleteTodoItem :execrows
-- Hard delete an inbox todo item. State guard prevents accidental deletion.
DELETE FROM todos WHERE id = @id AND state = 'inbox';

-- name: BacklogTodoItems :many
-- Filtered todo item list for admin backlog view. states is a text[] of
-- todo_state values (NULL = no state filter); elements are validated at
-- the handler boundary.
SELECT t.id, t.title, t.state, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit, t.recur_weekdays, t.last_completed_on,
       t.description, t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM todos t
LEFT JOIN projects p ON p.id = t.project_id
WHERE (sqlc.narg('states')::text[] IS NULL OR t.state::text = ANY(sqlc.narg('states')::text[]))
  AND (sqlc.narg('project_id')::uuid IS NULL OR t.project_id = sqlc.narg('project_id'))
  AND (sqlc.narg('energy')::text IS NULL OR t.energy = sqlc.narg('energy'))
  AND (sqlc.narg('priority')::text IS NULL OR t.priority = sqlc.narg('priority'))
  AND (sqlc.narg('search')::text IS NULL OR t.title ILIKE '%' || sqlc.narg('search') || '%')
ORDER BY
  CASE WHEN sqlc.narg('sort')::text = 'priority' THEN
    CASE t.priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END
  END NULLS LAST,
  CASE WHEN sqlc.narg('sort')::text = 'created_at' THEN t.created_at::timestamptz END DESC NULLS LAST,
  t.due NULLS LAST, t.priority NULLS LAST, t.created_at DESC
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
