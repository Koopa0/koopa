-- name: Tasks :many
-- List all tasks ordered by status and due date.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, created_at, updated_at
FROM tasks ORDER BY status, due NULLS LAST, created_at DESC;

-- name: PendingTasks :many
-- List tasks that are not done, ordered by due date.
SELECT id, title, status, due, project_id, notion_page_id,
       completed_at, created_at, updated_at
FROM tasks WHERE status != 'done'
ORDER BY due NULLS LAST, created_at;

-- name: UpsertTaskByNotionPageID :one
-- Upsert a task from Notion sync. completed_at is set by the DB on first transition to done.
INSERT INTO tasks (title, status, due, project_id, notion_page_id, completed_at)
VALUES (@title, @status::task_status, @due, @project_id, @notion_page_id,
        CASE WHEN @status::task_status = 'done' THEN now() ELSE NULL END)
ON CONFLICT (notion_page_id) DO UPDATE SET
    title        = EXCLUDED.title,
    status       = EXCLUDED.status,
    due          = EXCLUDED.due,
    project_id   = EXCLUDED.project_id,
    completed_at = CASE
        WHEN EXCLUDED.status = 'done' AND tasks.completed_at IS NULL THEN now()
        ELSE tasks.completed_at
    END,
    updated_at   = now()
RETURNING id, title, status, due, project_id, notion_page_id,
          completed_at, created_at, updated_at;

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
