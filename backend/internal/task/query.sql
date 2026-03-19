-- name: Tasks :many
-- List all tasks ordered by status and due date.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       my_day, description, created_at, updated_at
FROM tasks ORDER BY status, due NULLS LAST, created_at DESC;

-- name: PendingTasks :many
-- List tasks that are not done, ordered by due date.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       my_day, description, created_at, updated_at
FROM tasks WHERE status != 'done'
ORDER BY due NULLS LAST, created_at;

-- name: UpsertTaskByNotionPageID :one
-- Upsert a task from Notion sync. completed_at is set by the DB on first transition to done.
INSERT INTO tasks (title, status, due, project_id, notion_page_id, completed_at,
                   energy, priority, recur_interval, recur_unit, my_day, description)
VALUES (@title, @status::task_status, @due, @project_id, @notion_page_id,
        CASE WHEN @status::task_status = 'done' THEN now() ELSE NULL END,
        @energy, @priority, @recur_interval, @recur_unit, @my_day, @description)
ON CONFLICT (notion_page_id) DO UPDATE SET
    title          = EXCLUDED.title,
    status         = EXCLUDED.status,
    due            = EXCLUDED.due,
    project_id     = EXCLUDED.project_id,
    completed_at   = CASE
        WHEN EXCLUDED.status = 'done' AND tasks.completed_at IS NULL THEN now()
        ELSE tasks.completed_at
    END,
    energy         = EXCLUDED.energy,
    priority       = EXCLUDED.priority,
    recur_interval = EXCLUDED.recur_interval,
    recur_unit     = EXCLUDED.recur_unit,
    my_day         = EXCLUDED.my_day,
    description    = EXCLUDED.description,
    updated_at     = now()
RETURNING id, title, status, due, project_id, notion_page_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          my_day, description, created_at, updated_at;

-- name: NotionTaskPageIDs :many
-- List all Notion page IDs for tasks.
SELECT notion_page_id FROM tasks WHERE notion_page_id IS NOT NULL ORDER BY title;

-- name: ArchiveTaskByNotionPageID :execrows
-- Mark a single task as done by its Notion page ID (used when Notion page is trashed).
UPDATE tasks SET status = 'done', completed_at = COALESCE(completed_at, now()), updated_at = now()
WHERE notion_page_id = $1 AND status != 'done';

-- name: ArchiveOrphanNotionTasks :execrows
-- Mark tasks as done if their notion_page_id is not in the active set.
UPDATE tasks SET status = 'done', completed_at = COALESCE(completed_at, now()), updated_at = now()
WHERE notion_page_id IS NOT NULL
  AND notion_page_id != ALL(@active_ids::text[])
  AND status != 'done';

-- name: CompletedTasksSince :one
-- Count tasks completed since a given time.
SELECT count(*) FROM tasks WHERE status = 'done' AND completed_at >= @since;

-- name: PendingTasksWithProject :many
-- List pending tasks with project info, sorted by deadline priority then last-touched.
SELECT t.id, t.title, t.status, t.due, t.project_id,
       t.energy, t.priority, t.recur_interval, t.recur_unit, t.my_day,
       t.created_at, t.updated_at,
       COALESCE(p.title, '') AS project_title,
       COALESCE(p.slug, '') AS project_slug
FROM tasks t
LEFT JOIN projects p ON t.project_id = p.id
WHERE t.status != 'done'
  AND (sqlc.narg('project_slug')::text IS NULL OR p.slug = sqlc.narg('project_slug'))
ORDER BY
    (t.due IS NOT NULL) DESC,
    t.due ASC NULLS LAST,
    t.updated_at ASC
LIMIT sqlc.arg('max_results');

-- name: CompletedTasksByProjectSince :many
-- Count tasks completed per project since a given time. NULL project grouped as '(no project)'.
SELECT COALESCE(p.title, '(no project)') AS project_title, count(*) AS completed
FROM tasks t
LEFT JOIN projects p ON t.project_id = p.id
WHERE t.status = 'done' AND t.completed_at >= @since
GROUP BY p.title
ORDER BY completed DESC;

-- name: TaskByID :one
-- Get a task by ID.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       my_day, description, created_at, updated_at
FROM tasks WHERE id = @id;

-- name: TaskByNotionPageID :one
-- Get a task by its Notion page ID.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       my_day, description, created_at, updated_at
FROM tasks WHERE notion_page_id = @notion_page_id;

-- name: PendingTasksByTitle :many
-- Find pending tasks matching a title (case-insensitive contains).
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, energy, priority, recur_interval, recur_unit,
       my_day, description, created_at, updated_at
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
          my_day, description, created_at, updated_at;

-- name: UpdateTaskMyDay :execrows
-- Set or clear My Day for a task.
UPDATE tasks SET my_day = @my_day, updated_at = now()
WHERE id = @id AND status != 'done';

-- name: ClearAllMyDay :execrows
-- Clear My Day for all pending tasks.
UPDATE tasks SET my_day = false, updated_at = now()
WHERE my_day = true AND status != 'done';

-- name: UpdateTask :one
-- Update arbitrary task fields. Only non-null parameters are applied.
UPDATE tasks SET
    status       = COALESCE(sqlc.narg('status')::task_status, status),
    due          = COALESCE(sqlc.narg('due'), due),
    energy       = COALESCE(sqlc.narg('energy'), energy),
    priority     = COALESCE(sqlc.narg('priority'), priority),
    my_day       = COALESCE(sqlc.narg('my_day'), my_day),
    project_id   = COALESCE(sqlc.narg('new_project_id'), project_id),
    description  = COALESCE(sqlc.narg('new_description'), description),
    completed_at = CASE
        WHEN sqlc.narg('status')::task_status = 'done' AND completed_at IS NULL THEN now()
        ELSE completed_at
    END,
    updated_at = now()
WHERE id = @id
RETURNING id, title, status, due, project_id, notion_page_id,
          completed_at, energy, priority, recur_interval, recur_unit,
          my_day, description, created_at, updated_at;
