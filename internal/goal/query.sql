-- name: UpdateGoalStatus :one
-- Update a goal's status.
UPDATE goals SET
    status = @status::goal_status,
    updated_at = now()
WHERE id = @id
RETURNING id, title, description, status, area_id, quarter, deadline,
          created_at, updated_at;

-- name: GoalByTitle :one
-- Find a goal by case-insensitive title match.
SELECT id, title, description, status, area_id, quarter, deadline,
       created_at, updated_at
FROM goals WHERE LOWER(title) = LOWER(@title);

-- name: CreateGoal :one
-- Create a new goal (v2: PostgreSQL-native).
INSERT INTO goals (title, description, status, area_id, quarter, deadline)
VALUES (@title, @description, @status::goal_status, @area_id, @quarter, @deadline)
RETURNING id, title, description, status, area_id, quarter, deadline,
          created_at, updated_at;

-- name: GoalByID :one
SELECT id, title, description, status, area_id, quarter, deadline,
       created_at, updated_at
FROM goals WHERE id = @id;

-- name: ActiveGoals :many
-- Goals that are in_progress, with milestone counts.
SELECT g.id, g.title, g.description, g.status, g.area_id, g.quarter, g.deadline,
       g.created_at, g.updated_at,
       COALESCE(a.name, '') AS area_name,
       (SELECT count(*) FROM milestones m WHERE m.goal_id = g.id) AS milestone_total,
       (SELECT count(*) FROM milestones m WHERE m.goal_id = g.id AND m.completed_at IS NOT NULL) AS milestone_done
FROM goals g
LEFT JOIN areas a ON a.id = g.area_id
WHERE g.status = 'in_progress'
ORDER BY g.deadline NULLS LAST, g.created_at;

-- name: GoalsByOptionalStatus :many
-- Goals filtered by optional status, with milestone counts.
-- Pass NULL to return all statuses.
SELECT g.id, g.title, g.description, g.status, g.area_id, g.quarter, g.deadline,
       g.created_at, g.updated_at,
       COALESCE(a.name, '') AS area_name,
       (SELECT count(*) FROM milestones m WHERE m.goal_id = g.id) AS milestone_total,
       (SELECT count(*) FROM milestones m WHERE m.goal_id = g.id AND m.completed_at IS NOT NULL) AS milestone_done
FROM goals g
LEFT JOIN areas a ON a.id = g.area_id
WHERE (sqlc.narg('status')::text IS NULL OR g.status::text = sqlc.narg('status'))
ORDER BY g.deadline NULLS LAST, g.created_at;

-- name: CreateMilestone :one
-- Appends to the goal's milestone list: position = current max + 1, 0 when
-- the goal has none (position carries UNIQUE(goal_id, position)).
INSERT INTO milestones (goal_id, title, description, target_deadline, position)
VALUES (@goal_id, @title, @description, @target_deadline,
        (SELECT COALESCE(MAX(position) + 1, 0) FROM milestones WHERE goal_id = @goal_id))
RETURNING id, goal_id, title, description, target_deadline, completed_at, position, created_at, updated_at;

-- name: GoalByIDWithArea :one
-- Get a single goal with its area name.
SELECT g.id, g.title, g.description, g.status, g.area_id, g.quarter, g.deadline,
       g.created_at, g.updated_at,
       COALESCE(a.name, '') AS area_name
FROM goals g
LEFT JOIN areas a ON a.id = g.area_id
WHERE g.id = @id;

-- name: MilestonesByGoal :many
-- List milestones for a goal, ordered by position.
SELECT id, goal_id, title, description, target_deadline, completed_at, position, created_at, updated_at
FROM milestones
WHERE goal_id = @goal_id
ORDER BY position, created_at;

-- name: ToggleMilestone :one
-- Toggle a milestone's completed_at (set to now if null, null if set).
UPDATE milestones SET
    completed_at = CASE WHEN completed_at IS NULL THEN now() ELSE NULL END,
    updated_at = now()
WHERE id = @id
RETURNING id, goal_id, title, description, target_deadline, completed_at, position, created_at, updated_at;

-- name: CreateMilestoneWithPosition :one
-- Create a milestone with an explicit position.
INSERT INTO milestones (goal_id, title, position)
VALUES (@goal_id, @title, @position)
RETURNING id, goal_id, title, description, target_deadline, completed_at, position, created_at, updated_at;

-- name: GoalRecentActivity :many
-- Recent activity for a single goal — UNION across milestones, tasks (via project),
-- and contents (via project). Each row carries a typed activity_type that the admin
-- frontend can dispatch on for icons / colors.
--
-- Sources:
--   milestone_completed     — milestones.completed_at where milestone.goal_id = @goal_id
--   todo_completed          — todos.completed_at where todos.project_id ∈ (projects under this goal)
--   content_published       — contents.published_at where contents.project_id ∈ (projects under this goal)
SELECT
    activity_type::text AS activity_type,
    title,
    ref_id,
    ref_slug,
    ts
FROM (
    SELECT
        'milestone_completed' AS activity_type,
        m.title               AS title,
        m.id::text            AS ref_id,
        NULL::text            AS ref_slug,
        m.completed_at        AS ts
    FROM milestones m
    WHERE m.goal_id = @goal_id AND m.completed_at IS NOT NULL

    UNION ALL

    SELECT
        'todo_completed' AS activity_type,
        t.title          AS title,
        t.id::text       AS ref_id,
        NULL::text       AS ref_slug,
        t.completed_at   AS ts
    FROM todos t
    JOIN projects p ON p.id = t.project_id
    WHERE p.goal_id = @goal_id AND t.completed_at IS NOT NULL

    UNION ALL

    SELECT
        'content_published' AS activity_type,
        c.title             AS title,
        c.id::text          AS ref_id,
        c.slug              AS ref_slug,
        c.published_at      AS ts
    FROM contents c
    JOIN projects p ON p.id = c.project_id
    WHERE p.goal_id = @goal_id
      AND c.status = 'published'
      AND c.published_at IS NOT NULL
) AS activity
ORDER BY ts DESC NULLS LAST
LIMIT @max_results;

-- name: AreaIDBySlugOrName :one
-- Resolve an area identifier (slug or display name, case-insensitive on
-- name) to its UUID. Used by propose_goal / propose_project when
-- wiring an area without forcing the caller to know UUIDs.
SELECT id FROM areas
WHERE slug = @identifier OR LOWER(name) = LOWER(@identifier)
LIMIT 1;

-- name: Areas :many
-- List every PARA area for the admin area selector (goal classification).
SELECT id, slug, name, sort_order
FROM areas
ORDER BY sort_order, name;

-- name: UpdateGoal :one
-- Partial update of a goal's shaping fields. NULL parameters leave the
-- column unchanged. Status is not touched here — it has its own
-- UpdateGoalStatus transition.
UPDATE goals SET
    title       = COALESCE(sqlc.narg('new_title'), title),
    description = COALESCE(sqlc.narg('new_description'), description),
    quarter     = COALESCE(sqlc.narg('new_quarter'), quarter),
    deadline    = COALESCE(sqlc.narg('new_deadline'), deadline),
    area_id     = COALESCE(sqlc.narg('new_area_id'), area_id),
    updated_at  = now()
WHERE id = @id
RETURNING id, title, description, status, area_id, quarter, deadline,
          created_at, updated_at;

-- name: UpdateMilestone :one
-- Partial update of a milestone, bound to its parent goal: the WHERE
-- clause enforces membership, so a {goal_id, id} mismatch is a no-row
-- miss rather than a cross-goal write.
UPDATE milestones SET
    title           = COALESCE(sqlc.narg('new_title'), title),
    description     = COALESCE(sqlc.narg('new_description'), description),
    target_deadline = COALESCE(sqlc.narg('new_target_deadline'), target_deadline),
    updated_at      = now()
WHERE id = @id AND goal_id = @goal_id
RETURNING id, goal_id, title, description, target_deadline, completed_at, position, created_at, updated_at;

-- name: DeleteMilestone :execrows
-- Delete a milestone, bound to its parent goal (same membership guard as
-- UpdateMilestone). Completed milestones are deletable; position gaps in
-- the remaining siblings are left as-is.
DELETE FROM milestones WHERE id = @id AND goal_id = @goal_id;
