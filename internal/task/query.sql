-- name: CreateTask :one
-- Create a new task (v2: PostgreSQL-native, no Notion dependency).
INSERT INTO tasks (title, status, due, project_id, energy, priority, description, assignee, created_by)
VALUES (@title, @status::task_status, @due, @project_id, @energy, @priority, @description, @assignee, @created_by)
RETURNING id, title, status, due, project_id, notion_page_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          description, assignee, created_by, created_at, updated_at;

-- name: OverdueTasks :many
-- Tasks past due that are not done (for morning_context).
SELECT t.id, t.title, t.status, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.assignee, t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM tasks t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.status NOT IN ('done', 'someday', 'inbox')
  AND t.due IS NOT NULL AND t.due < @today
ORDER BY t.due, t.priority NULLS LAST;

-- name: TasksDueOn :many
-- Tasks due on a specific date that are not done (for morning_context today_tasks).
SELECT t.id, t.title, t.status, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.assignee, t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM tasks t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.status NOT IN ('done', 'someday', 'inbox')
  AND t.due = @target_date
ORDER BY t.priority NULLS LAST, t.created_at;

-- name: TasksDueInRange :many
-- Tasks due within a date range (for morning_context upcoming_tasks).
SELECT t.id, t.title, t.status, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.assignee, t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM tasks t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.status NOT IN ('done', 'someday', 'inbox')
  AND t.due > @start_date AND t.due <= @end_date
ORDER BY t.due, t.priority NULLS LAST;

-- name: Tasks :many
-- List all tasks ordered by status and due date.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, assignee, created_by, created_at, updated_at
FROM tasks ORDER BY status, due NULLS LAST, created_at DESC;

-- name: PendingTasks :many
-- List tasks that are not done, ordered by due date.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, assignee, created_by, created_at, updated_at
FROM tasks WHERE status != 'done'
ORDER BY due NULLS LAST, created_at;

-- name: UpsertTaskByNotionPageID :one
-- Upsert a task from Notion sync. completed_at is set by the DB on first transition to done.
INSERT INTO tasks (title, status, due, project_id, notion_page_id, completed_at,
                   energy, priority, recur_interval, recur_unit, description, assignee)
VALUES (@title, @status::task_status, @due, @project_id, @notion_page_id,
        CASE WHEN @status::task_status = 'done' THEN now() ELSE NULL END,
        @energy, @priority, @recur_interval, @recur_unit, @description, @assignee)
ON CONFLICT (notion_page_id) DO UPDATE SET
    title          = EXCLUDED.title,
    status         = EXCLUDED.status,
    due            = CASE
        -- For recurring tasks, don't overwrite local due if it's ahead of incoming Notion due.
        -- This prevents hourly SyncAll from reverting cron's due date advance.
        WHEN tasks.recur_interval IS NOT NULL AND tasks.recur_interval > 0
             AND tasks.due IS NOT NULL AND EXCLUDED.due IS NOT NULL
             AND tasks.due > EXCLUDED.due
        THEN tasks.due
        ELSE EXCLUDED.due
    END,
    project_id     = EXCLUDED.project_id,
    completed_at   = CASE
        WHEN EXCLUDED.status = 'done' AND tasks.completed_at IS NULL THEN now()
        ELSE tasks.completed_at
    END,
    energy         = EXCLUDED.energy,
    priority       = EXCLUDED.priority,
    recur_interval = EXCLUDED.recur_interval,
    recur_unit     = EXCLUDED.recur_unit,
    description    = EXCLUDED.description,
    assignee       = EXCLUDED.assignee,
    updated_at     = now()
RETURNING id, title, status, due, project_id, notion_page_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          description, assignee, created_by, created_at, updated_at;

-- name: NotionTaskPageIDs :many
-- List all Notion page IDs for tasks.
SELECT notion_page_id FROM tasks WHERE notion_page_id IS NOT NULL ORDER BY title;

-- name: ArchiveTaskByNotionPageID :execrows
-- Mark a single non-recurring task as done by its Notion page ID (used when Notion page is trashed).
-- Recurring tasks are excluded — they should never be archived by sync.
UPDATE tasks SET status = 'done', completed_at = COALESCE(completed_at, now()), updated_at = now()
WHERE notion_page_id = $1 AND status != 'done'
  AND (recur_interval IS NULL OR recur_interval <= 0);

-- name: ArchiveOrphanNotionTasks :execrows
-- Mark non-recurring tasks as done if their notion_page_id is not in the active set.
-- Recurring tasks are excluded — they should never be archived by sync.
UPDATE tasks SET status = 'done', completed_at = COALESCE(completed_at, now()), updated_at = now()
WHERE notion_page_id IS NOT NULL
  AND notion_page_id != ALL(@active_ids::text[])
  AND status != 'done'
  AND (recur_interval IS NULL OR recur_interval <= 0);


-- name: PendingTasksWithProject :many
-- List pending tasks with project info, sorted by deadline priority then last-touched.
SELECT t.id, t.title, t.status, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.assignee, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM tasks t
LEFT JOIN projects p ON t.project_id = p.id
WHERE t.status != 'done'
  AND (sqlc.narg('project_slug')::text IS NULL OR p.slug = sqlc.narg('project_slug'))
  AND (sqlc.narg('assignee')::text IS NULL OR t.assignee = sqlc.narg('assignee'))
ORDER BY
    (t.due IS NOT NULL) DESC,
    t.due ASC NULLS LAST,
    t.updated_at ASC
LIMIT sqlc.arg('max_results');


-- name: TaskByID :one
-- Get a task by ID.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, assignee, created_by, created_at, updated_at
FROM tasks WHERE id = @id;

-- name: TaskByNotionPageID :one
-- Get a task by its Notion page ID.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, assignee, created_by, created_at, updated_at
FROM tasks WHERE notion_page_id = @notion_page_id;

-- name: PendingTasksByTitle :many
-- Find pending tasks matching a title (case-insensitive contains).
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, assignee, created_by, created_at, updated_at
FROM tasks
WHERE status != 'done' AND title ILIKE '%' || @search_title || '%'
ORDER BY due NULLS LAST, updated_at ASC
LIMIT 10;

-- name: UpdateTaskStatus :one
-- Update a task's status. Sets completed_at on transition to done.
UPDATE tasks SET
    status       = @status::task_status,
    completed_at = CASE
        WHEN @status::task_status = 'done' AND completed_at IS NULL THEN now()
        ELSE completed_at
    END,
    updated_at = now()
WHERE id = @id
RETURNING id, title, status, due, project_id, notion_page_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          description, assignee, created_by, created_at, updated_at;

-- name: DailySummaryHint :one
-- Compute task metrics hint for a single day (completed counts).
-- Uses daily_plan_items for "planned" counts and tasks for completed counts.
SELECT
    (SELECT count(*)::int FROM daily_plan_items WHERE plan_date = @plan_date::date) AS planned_total,
    (SELECT count(*)::int FROM daily_plan_items WHERE plan_date = @plan_date::date AND status = 'done') AS planned_completed,
    count(*) FILTER (WHERE status = 'done'
        AND completed_at >= @day_start AND completed_at < @day_end)::int AS total_completed
FROM tasks
WHERE status = 'done' AND completed_at >= @day_start AND completed_at < @day_end;

-- name: CompletedTitlesSince :many
-- Get titles of tasks completed since a given time (for metrics hint).
SELECT title FROM tasks
WHERE status = 'done' AND completed_at >= @since
ORDER BY completed_at DESC
LIMIT 20;

-- name: CompletedTasksDetailSince :many
-- Get tasks completed since a given time with project context.
SELECT t.id, t.title, t.completed_at, t.project_id,
       COALESCE(p.title, '') AS project_title
FROM tasks t
LEFT JOIN projects p ON t.project_id = p.id
WHERE t.status = 'done' AND t.completed_at >= @since
ORDER BY t.completed_at DESC;

-- name: TasksCreatedSince :many
-- Get tasks created since a given time with project context.
SELECT t.id, t.title, t.created_at, t.project_id,
       COALESCE(p.title, '') AS project_title
FROM tasks t
LEFT JOIN projects p ON t.project_id = p.id
WHERE t.created_at >= @since
ORDER BY t.created_at DESC;

-- name: RecurringTaskByProject :one
-- Find a recurring pending task under a given project that is due today or overdue.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, assignee, created_by, created_at, updated_at
FROM tasks
WHERE project_id = @project_id
  AND status != 'done'
  AND recur_interval IS NOT NULL AND recur_interval > 0
  AND due <= @today
ORDER BY due ASC NULLS LAST
LIMIT 1;

-- name: UpdateTask :one
-- Update arbitrary task fields. Only non-null parameters are applied.
UPDATE tasks SET
    title        = COALESCE(sqlc.narg('new_title'), title),
    status       = COALESCE(sqlc.narg('status')::task_status, status),
    due          = COALESCE(sqlc.narg('due'), due),
    energy       = COALESCE(sqlc.narg('energy'), energy),
    priority     = COALESCE(sqlc.narg('priority'), priority),
    project_id   = COALESCE(sqlc.narg('new_project_id'), project_id),
    description  = COALESCE(sqlc.narg('new_description'), description),
    assignee     = COALESCE(sqlc.narg('assignee'), assignee),
    completed_at = CASE
        WHEN sqlc.narg('status')::task_status = 'done' AND completed_at IS NULL THEN now()
        ELSE completed_at
    END,
    updated_at = now()
WHERE id = @id
RETURNING id, title, status, due, project_id, notion_page_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          description, assignee, created_by, created_at, updated_at;

-- name: SearchTasks :many
-- Search tasks by title/description with optional filters. Used by search_tasks MCP tool.
SELECT t.id, t.title, t.status, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.assignee, t.completed_at, t.description, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM tasks t
LEFT JOIN projects p ON t.project_id = p.id
WHERE (sqlc.narg('query')::text IS NULL OR (t.title ILIKE '%' || sqlc.narg('query') || '%' OR t.description ILIKE '%' || sqlc.narg('query') || '%'))
  AND (sqlc.narg('project_slug')::text IS NULL OR p.slug = sqlc.narg('project_slug'))
  AND (sqlc.narg('status_filter')::text IS NULL OR
       CASE sqlc.narg('status_filter')
           WHEN 'pending' THEN t.status != 'done'
           WHEN 'done' THEN t.status = 'done'
           ELSE true
       END)
  AND (sqlc.narg('assignee')::text IS NULL OR t.assignee = sqlc.narg('assignee'))
  AND (sqlc.narg('completed_after')::timestamptz IS NULL OR t.completed_at >= sqlc.narg('completed_after'))
  AND (sqlc.narg('completed_before')::timestamptz IS NULL OR t.completed_at < sqlc.narg('completed_before'))
ORDER BY
    CASE WHEN t.status != 'done' THEN 0 ELSE 1 END,
    CASE WHEN t.status != 'done' THEN
        CASE WHEN t.due IS NOT NULL THEN 0 ELSE 1 END
    ELSE 2 END,
    t.due ASC NULLS LAST,
    t.completed_at DESC NULLS LAST,
    t.updated_at ASC
LIMIT sqlc.arg('max_results');

-- === Recurring Task System Queries ===

-- name: OverdueRecurringTasks :many
-- Get all overdue recurring tasks (due < today, not done).
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, assignee, created_by, created_at, updated_at
FROM tasks
WHERE status != 'done'
  AND recur_interval IS NOT NULL AND recur_interval > 0
  AND due < @today
ORDER BY due ASC;

-- name: RecurringTasksDueToday :many
-- Get recurring tasks due on or before today.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       description, assignee, created_by, created_at, updated_at
FROM tasks
WHERE status != 'done'
  AND recur_interval IS NOT NULL AND recur_interval > 0
  AND due <= @today
ORDER BY due ASC;

-- name: UpdateTaskDue :execrows
-- Update only the due date for a task (used by cron advance and complete_task recurring reset).
UPDATE tasks SET due = @due, updated_at = now() WHERE id = @id;

-- name: ResetRecurringTask :one
-- Reset a recurring task after completion: advance due, reset status to todo.
UPDATE tasks SET
    due = @due,
    status = 'todo',
    updated_at = now()
WHERE id = @id
RETURNING id, title, status, due, project_id, notion_page_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          description, assignee, created_by, created_at, updated_at;

-- === Skip Log Queries ===

-- name: CreateSkipRecord :exec
-- Insert a single skip record. ON CONFLICT ensures idempotency on cron re-run.
INSERT INTO task_skips (task_id, original_due, skipped_date, reason)
VALUES (@task_id, @original_due, @skipped_date, @reason)
ON CONFLICT (task_id, skipped_date) DO NOTHING;

-- name: SkipHistoryByTask :many
-- Get skip history for a specific task within a date range.
SELECT id, task_id, original_due, skipped_date, reason, created_at
FROM task_skips
WHERE task_id = @task_id
  AND skipped_date >= @since
ORDER BY skipped_date DESC;

-- name: SkipCountByTask :one
-- Count skips for a specific task within a date range.
SELECT count(*)::int FROM task_skips
WHERE task_id = @task_id AND skipped_date >= @since;

-- name: SkipHistoryByProject :many
-- Get skip history for all tasks under a project within a date range.
SELECT sl.id, sl.task_id, sl.original_due, sl.skipped_date, sl.reason, sl.created_at,
       t.title AS task_title
FROM task_skips sl
JOIN tasks t ON t.id = sl.task_id
WHERE t.project_id = @project_id
  AND sl.skipped_date >= @since
ORDER BY sl.skipped_date DESC;

-- name: InboxCount :one
-- Count of tasks in inbox status (for needs_attention badge).
SELECT count(*)::int FROM tasks WHERE status = 'inbox';

-- name: StaleSomedayCount :one
-- Count of someday tasks not updated in N days (GTD review signal).
SELECT count(*)::int FROM tasks
WHERE status = 'someday' AND updated_at < @stale_before;

-- name: InboxTasks :many
-- List all inbox tasks, newest first.
SELECT * FROM tasks WHERE status = 'inbox' ORDER BY created_at DESC;

-- name: ClarifyTask :one
-- Promote inbox task to todo with clarification fields.
UPDATE tasks
SET status = 'todo',
    priority = COALESCE(sqlc.narg('priority'), priority),
    energy = COALESCE(sqlc.narg('energy'), energy),
    due = COALESCE(sqlc.narg('due'), due),
    updated_at = now()
WHERE id = @id AND status = 'inbox'
RETURNING *;

-- name: DeleteTask :execrows
-- Hard delete an inbox task. Status guard prevents accidental deletion of non-inbox tasks.
DELETE FROM tasks WHERE id = @id AND status = 'inbox';

-- name: BacklogTasks :many
-- Filtered task list for admin backlog view.
SELECT t.id, t.title, t.status, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit,
       t.assignee, t.created_by, t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM tasks t
LEFT JOIN projects p ON p.id = t.project_id
WHERE t.status = @status::task_status
  AND (sqlc.narg('project_id')::uuid IS NULL OR t.project_id = sqlc.narg('project_id'))
  AND (sqlc.narg('energy')::text IS NULL OR t.energy = sqlc.narg('energy'))
  AND (sqlc.narg('priority')::text IS NULL OR t.priority = sqlc.narg('priority'))
  AND (sqlc.narg('search')::text IS NULL OR t.title ILIKE '%' || sqlc.narg('search') || '%')
ORDER BY t.due NULLS LAST, t.priority NULLS LAST, t.created_at DESC
LIMIT @max_results;

-- name: TasksByProjectGrouped :many
-- Tasks for a project, used for admin project detail grouping by status.
SELECT t.id, t.title, t.status, t.due, t.energy, t.priority,
       t.assignee, t.created_at, t.updated_at
FROM tasks t
WHERE t.project_id = @project_id
ORDER BY
    CASE t.status
        WHEN 'in-progress' THEN 0
        WHEN 'todo' THEN 1
        WHEN 'inbox' THEN 2
        WHEN 'someday' THEN 3
        WHEN 'done' THEN 4
        ELSE 5
    END,
    t.due NULLS LAST, t.created_at DESC;

