-- name: Goals :many
SELECT * FROM goals ORDER BY status, deadline NULLS LAST, created_at DESC;

-- name: GoalByNotionPageID :one
SELECT * FROM goals WHERE notion_page_id = @notion_page_id;

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
RETURNING *;
