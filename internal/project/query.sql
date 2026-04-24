-- name: ProjectByID :one
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE id = $1;

-- name: ProjectDetailByID :one
-- Admin detail view: project row plus the goal breadcrumb via LEFT JOIN.
-- goal_id is nullable (project may have no goal); goal_title is null when
-- goal_id is null OR when the referenced goal was deleted. The goals table
-- has no slug column, so the breadcrumb is title-only.
SELECT
    p.id, p.slug, p.title, p.description, p.status, p.repo,
    p.area_id, p.goal_id, p.deadline, p.last_activity_at,
    p.expected_cadence, p.created_at, p.updated_at,
    g.title AS goal_title
FROM projects p
LEFT JOIN goals g ON g.id = p.goal_id
WHERE p.id = $1;

-- name: Projects :many
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects ORDER BY title;

-- name: PublicProjects :many
-- Public projects join project_profiles; portfolio flags live there.
SELECT p.id, p.slug, p.title, p.description, p.status, p.repo, p.area_id, p.goal_id,
       p.deadline, p.last_activity_at, p.expected_cadence, p.created_at, p.updated_at
FROM projects p
JOIN project_profiles pp ON pp.project_id = p.id
WHERE pp.is_public = true
ORDER BY pp.featured DESC, pp.sort_order, p.title;

-- name: ProjectBySlug :one
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE slug = $1;

-- name: ProjectByRepo :one
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE repo = $1;

-- name: CreateProject :one
INSERT INTO projects (slug, title, description, status)
VALUES ($1, $2, $3, $4)
RETURNING id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
          expected_cadence, created_at, updated_at;

-- name: UpdateProject :one
UPDATE projects SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    title = COALESCE(sqlc.narg('title'), title),
    description = COALESCE(sqlc.narg('description'), description),
    status = COALESCE(sqlc.narg('status')::project_status, status),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
          expected_cadence, created_at, updated_at;

-- name: ActiveProjects :many
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE status IN ('in_progress', 'maintained')
ORDER BY updated_at DESC;

-- name: DeleteProject :exec
DELETE FROM projects WHERE id = $1;

-- name: ProjectByAlias :one
-- Resolve a project alias to a project via the project_aliases table.
SELECT p.id, p.slug, p.title, p.description,
       p.status, p.repo, p.area_id, p.goal_id, p.deadline, p.last_activity_at,
       p.expected_cadence, p.created_at, p.updated_at
FROM project_aliases pa
JOIN projects p ON p.id = pa.project_id
WHERE LOWER(pa.alias) = LOWER(@alias);

-- name: ProjectByTitle :one
-- Resolve a project by case-insensitive title match.
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE LOWER(title) = LOWER($1);

-- name: UpdateProjectStatus :one
-- Update a project's status and optionally its description and expected
-- cadence. Returns the new row plus the previous status so the caller can
-- detect a transition into archived and demote the project_profile in the
-- same transaction (business coupling the archive_project_profile trigger
-- used to own). See project.Store.UpdateStatus.
WITH prev AS (
    SELECT status AS old_status FROM projects WHERE id = @id
)
UPDATE projects SET
    status = @status::project_status,
    description = COALESCE(sqlc.narg('description'), description),
    expected_cadence = COALESCE(sqlc.narg('expected_cadence'), expected_cadence),
    updated_at = now()
FROM prev
WHERE projects.id = @id
RETURNING projects.id, projects.slug, projects.title, projects.description,
          projects.status, projects.repo, projects.area_id, projects.goal_id,
          projects.deadline, projects.last_activity_at, projects.expected_cadence,
          projects.created_at, projects.updated_at,
          prev.old_status AS old_status;

-- name: DemoteProjectProfileOnArchive :exec
-- Demote the project_profile from public display. Used by
-- project.Store.UpdateStatus when a project transitions to archived.
-- Replaces the former archive_project_profile() trigger; business logic
-- belongs in Go (per .claude/rules/postgres-patterns.md).
UPDATE project_profiles
   SET is_public = FALSE,
       featured  = FALSE,
       updated_at = now()
 WHERE project_id = $1;

-- name: ListByStatus :many
-- List projects filtered by status. "active" maps to in_progress + maintained.
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects
WHERE CASE @status_filter::text
    WHEN 'active' THEN status IN ('in_progress', 'maintained')
    WHEN 'all' THEN true
    ELSE status = @status_filter::project_status
END
ORDER BY title;

-- name: ProjectSummariesByGoalIDs :many
-- Lightweight project info for goal_progress output.
SELECT id, slug, title, status, goal_id, last_activity_at
FROM projects
WHERE goal_id = ANY(@goal_ids::uuid[])
  AND status NOT IN ('archived')
ORDER BY goal_id;

-- name: ProfileByProjectID :one
SELECT project_id, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       cover_image, featured, is_public, sort_order, created_at, updated_at
FROM project_profiles WHERE project_id = $1;

-- name: UpsertProfile :one
INSERT INTO project_profiles (
    project_id, long_description, role, tech_stack, highlights,
    problem, solution, architecture, results, github_url, live_url,
    cover_image, featured, is_public, sort_order
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (project_id) DO UPDATE SET
    long_description = EXCLUDED.long_description,
    role = EXCLUDED.role,
    tech_stack = EXCLUDED.tech_stack,
    highlights = EXCLUDED.highlights,
    problem = EXCLUDED.problem,
    solution = EXCLUDED.solution,
    architecture = EXCLUDED.architecture,
    results = EXCLUDED.results,
    github_url = EXCLUDED.github_url,
    live_url = EXCLUDED.live_url,
    cover_image = EXCLUDED.cover_image,
    featured = EXCLUDED.featured,
    is_public = EXCLUDED.is_public,
    sort_order = EXCLUDED.sort_order,
    updated_at = now()
RETURNING project_id, long_description, role, tech_stack, highlights,
          problem, solution, architecture, results, github_url, live_url,
          cover_image, featured, is_public, sort_order, created_at, updated_at;

-- name: DeleteProfile :exec
DELETE FROM project_profiles WHERE project_id = $1;

-- name: PublicProfiles :many
-- List public project profiles joined with their projects for the portfolio page.
SELECT p.id, p.slug, p.title, p.description, p.status, p.repo,
       p.deadline, p.last_activity_at, p.created_at AS project_created_at,
       pp.long_description, pp.role, pp.tech_stack, pp.highlights,
       pp.problem, pp.solution, pp.architecture, pp.results,
       pp.github_url, pp.live_url, pp.cover_image,
       pp.featured, pp.sort_order, pp.updated_at
FROM projects p
JOIN project_profiles pp ON pp.project_id = p.id
WHERE pp.is_public = true
ORDER BY pp.featured DESC, pp.sort_order, p.title;
