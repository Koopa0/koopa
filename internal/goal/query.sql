-- name: Goals :many
SELECT id, title, description, status, area_id, quarter, deadline,
       notion_page_id, created_at, updated_at
FROM goals ORDER BY status, deadline NULLS LAST, created_at DESC;

-- name: UpdateGoalStatus :one
-- Update a goal's status.
UPDATE goals SET
    status = @status::goal_status,
    updated_at = now()
WHERE id = @id
RETURNING id, title, description, status, area_id, quarter, deadline,
          notion_page_id, created_at, updated_at;

-- name: GoalByTitle :one
-- Find a goal by case-insensitive title match.
SELECT id, title, description, status, area_id, quarter, deadline,
       notion_page_id, created_at, updated_at
FROM goals WHERE LOWER(title) = LOWER(@title);

-- name: CreateGoal :one
-- Create a new goal (v2: PostgreSQL-native).
INSERT INTO goals (title, description, status, area_id, quarter, deadline)
VALUES (@title, @description, @status::goal_status, @area_id, @quarter, @deadline)
RETURNING id, title, description, status, area_id, quarter, deadline,
          notion_page_id, created_at, updated_at;

-- name: GoalByID :one
SELECT id, title, description, status, area_id, quarter, deadline,
       notion_page_id, created_at, updated_at
FROM goals WHERE id = @id;

-- name: ActiveGoals :many
-- Goals that are in-progress, with milestone counts.
SELECT g.id, g.title, g.description, g.status, g.area_id, g.quarter, g.deadline,
       g.created_at, g.updated_at,
       COALESCE(a.name, '') AS area_name,
       (SELECT count(*) FROM milestones m WHERE m.goal_id = g.id) AS milestone_total,
       (SELECT count(*) FROM milestones m WHERE m.goal_id = g.id AND m.completed_at IS NOT NULL) AS milestone_done
FROM goals g
LEFT JOIN areas a ON a.id = g.area_id
WHERE g.status = 'in-progress'
ORDER BY g.deadline NULLS LAST, g.created_at;

-- name: CreateMilestone :one
INSERT INTO milestones (goal_id, title, description, target_deadline)
VALUES (@goal_id, @title, @description, @target_deadline)
RETURNING id, goal_id, title, description, target_deadline, completed_at, created_at, updated_at;
