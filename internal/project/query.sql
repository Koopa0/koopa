-- name: ProjectByID :one
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE id = $1;

-- name: Projects :many
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects ORDER BY featured DESC, sort_order, title;

-- name: PublicProjects :many
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE is_public = true
ORDER BY featured DESC, sort_order, title;

-- name: ProjectBySlug :one
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE slug = $1;

-- name: ProjectByRepo :one
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE repo = $1;

-- name: CreateProject :one
INSERT INTO projects (slug, title, description, long_description, role, tech_stack, highlights,
                      problem, solution, architecture, results, github_url, live_url, featured, is_public, sort_order, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
RETURNING id, slug, title, description, long_description, role, tech_stack, highlights,
          problem, solution, architecture, results, github_url, live_url,
          featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
          expected_cadence, created_at, updated_at;

-- name: UpdateProject :one
UPDATE projects SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    title = COALESCE(sqlc.narg('title'), title),
    description = COALESCE(sqlc.narg('description'), description),
    long_description = COALESCE(sqlc.narg('long_description'), long_description),
    role = COALESCE(sqlc.narg('role'), role),
    tech_stack = COALESCE(sqlc.narg('tech_stack'), tech_stack),
    highlights = COALESCE(sqlc.narg('highlights'), highlights),
    problem = COALESCE(sqlc.narg('problem'), problem),
    solution = COALESCE(sqlc.narg('solution'), solution),
    architecture = COALESCE(sqlc.narg('architecture'), architecture),
    results = COALESCE(sqlc.narg('results'), results),
    github_url = COALESCE(sqlc.narg('github_url'), github_url),
    live_url = COALESCE(sqlc.narg('live_url'), live_url),
    featured = COALESCE(sqlc.narg('featured'), featured),
    is_public = COALESCE(sqlc.narg('is_public'), is_public),
    sort_order = COALESCE(sqlc.narg('sort_order'), sort_order),
    status = COALESCE(sqlc.narg('status')::project_status, status),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, description, long_description, role, tech_stack, highlights,
          problem, solution, architecture, results, github_url, live_url,
          featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
          expected_cadence, created_at, updated_at;

-- name: ActiveProjects :many
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE status IN ('in-progress', 'maintained')
ORDER BY updated_at DESC;

-- name: DeleteProject :exec
DELETE FROM projects WHERE id = $1;

-- name: ProjectByAlias :one
-- Resolve a project alias to a project via the project_aliases table.
SELECT p.id, p.slug, p.title, p.description, p.long_description, p.role,
       p.tech_stack, p.highlights, p.problem, p.solution, p.architecture,
       p.results, p.github_url, p.live_url, p.featured, p.is_public, p.sort_order,
       p.status, p.external_provider, external_ref, p.repo, p.area_id, p.goal_id, p.deadline, p.last_activity_at,
       p.expected_cadence, p.created_at, p.updated_at
FROM project_aliases pa
JOIN projects p ON p.id = pa.project_id
WHERE LOWER(pa.alias) = LOWER(@alias);

-- name: ProjectByTitle :one
-- Resolve a project by case-insensitive title match.
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects WHERE LOWER(title) = LOWER($1);

-- name: UpdateProjectStatus :one
-- Update a project's status and optionally its description and expected cadence.
UPDATE projects SET
    status = @status::project_status,
    description = COALESCE(sqlc.narg('description'), description),
    expected_cadence = COALESCE(sqlc.narg('expected_cadence'), expected_cadence),
    updated_at = now()
WHERE id = @id
RETURNING id, slug, title, description, long_description, role, tech_stack, highlights,
          problem, solution, architecture, results, github_url, live_url,
          featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
          expected_cadence, created_at, updated_at;

-- name: ListByStatus :many
-- List projects filtered by status. "active" maps to in-progress + maintained.
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, is_public, sort_order, status, external_provider, external_ref, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_at, updated_at
FROM projects
WHERE CASE @status_filter::text
    WHEN 'active' THEN status IN ('in-progress', 'maintained')
    WHEN 'all' THEN true
    ELSE status = @status_filter::project_status
END
ORDER BY featured DESC, sort_order, title;

-- name: ProjectSummariesByGoalIDs :many
-- Lightweight project info for goal_progress output.
SELECT id, slug, title, status, goal_id, last_activity_at
FROM projects
WHERE goal_id = ANY(@goal_ids::uuid[])
  AND status NOT IN ('archived')
ORDER BY goal_id, sort_order;
