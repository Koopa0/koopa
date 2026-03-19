-- name: Goals :many
SELECT id, title, description, status, area, quarter, deadline,
       notion_page_id, created_at, updated_at
FROM goals ORDER BY status, deadline NULLS LAST, created_at DESC;

-- name: GoalByNotionPageID :one
SELECT id, title, description, status, area, quarter, deadline,
       notion_page_id, created_at, updated_at
FROM goals WHERE notion_page_id = @notion_page_id;

-- name: NotionGoalPageIDs :many
SELECT notion_page_id FROM goals WHERE notion_page_id IS NOT NULL ORDER BY title;

-- name: UpsertGoalByNotionPageID :one
INSERT INTO goals (title, description, status, area, quarter, deadline, notion_page_id)
VALUES (@title, @description, @status::goal_status, @area, @quarter, @deadline, @notion_page_id)
ON CONFLICT (notion_page_id) DO UPDATE SET
    title       = EXCLUDED.title,
    description = EXCLUDED.description,
    status      = EXCLUDED.status,
    area        = EXCLUDED.area,
    quarter     = EXCLUDED.quarter,
    deadline    = EXCLUDED.deadline,
    updated_at  = now()
RETURNING id, title, description, status, area, quarter, deadline,
          notion_page_id, created_at, updated_at;

-- name: ArchiveGoalByNotionPageID :execrows
-- Archive a single goal by its Notion page ID (used when Notion page is trashed).
UPDATE goals SET status = 'abandoned', updated_at = now()
WHERE notion_page_id = $1 AND status != 'abandoned';

-- name: ArchiveOrphanNotionGoals :execrows
UPDATE goals SET status = 'abandoned', updated_at = now()
WHERE notion_page_id IS NOT NULL
  AND notion_page_id != ALL(@active_ids::text[])
  AND status != 'abandoned';
