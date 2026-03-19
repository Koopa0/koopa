-- name: Projects :many
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, public, sort_order, status, notion_page_id, repo, area, deadline, last_activity_at,
       created_at, updated_at
FROM projects ORDER BY featured DESC, sort_order, title;

-- name: PublicProjects :many
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, public, sort_order, status, notion_page_id, repo, area, deadline, last_activity_at,
       created_at, updated_at
FROM projects WHERE public = true
ORDER BY featured DESC, sort_order, title;

-- name: ProjectBySlug :one
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, public, sort_order, status, notion_page_id, repo, area, deadline, last_activity_at,
       created_at, updated_at
FROM projects WHERE slug = $1;

-- name: ProjectByRepo :one
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, public, sort_order, status, notion_page_id, repo, area, deadline, last_activity_at,
       created_at, updated_at
FROM projects WHERE repo = $1;

-- name: CreateProject :one
INSERT INTO projects (slug, title, description, long_description, role, tech_stack, highlights,
                      problem, solution, architecture, results, github_url, live_url, featured, public, sort_order, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
RETURNING id, slug, title, description, long_description, role, tech_stack, highlights,
          problem, solution, architecture, results, github_url, live_url,
          featured, public, sort_order, status, notion_page_id, repo, area, deadline, last_activity_at,
          created_at, updated_at;

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
    public = COALESCE(sqlc.narg('public'), public),
    sort_order = COALESCE(sqlc.narg('sort_order'), sort_order),
    status = COALESCE(sqlc.narg('status')::project_status, status),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, description, long_description, role, tech_stack, highlights,
          problem, solution, architecture, results, github_url, live_url,
          featured, public, sort_order, status, notion_page_id, repo, area, deadline, last_activity_at,
          created_at, updated_at;

-- name: ActiveProjects :many
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, public, sort_order, status, notion_page_id, repo, area, deadline, last_activity_at,
       created_at, updated_at
FROM projects WHERE status IN ('in-progress', 'maintained')
ORDER BY updated_at DESC;

-- name: ProjectSlugByNotionPageID :one
-- Resolve a Notion page ID to a project slug.
SELECT slug FROM projects WHERE notion_page_id = $1;

-- name: ProjectIDByNotionPageID :one
-- Resolve a Notion page ID to a project UUID.
SELECT id FROM projects WHERE notion_page_id = $1;

-- name: ActiveProjectSlugsWithRepo :many
-- List slugs of active projects that have a linked repository.
SELECT slug FROM projects
WHERE status IN ('in-progress', 'maintained') AND repo IS NOT NULL AND repo != ''
ORDER BY title;

-- name: DeleteProject :exec
DELETE FROM projects WHERE id = $1;

-- name: UpsertProjectByNotionPageID :one
INSERT INTO projects (slug, title, description, status, area, deadline, notion_page_id)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (notion_page_id) DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    status = EXCLUDED.status,
    area = EXCLUDED.area,
    deadline = EXCLUDED.deadline,
    updated_at = now()
RETURNING id, slug, title, description, long_description, role, tech_stack, highlights,
          problem, solution, architecture, results, github_url, live_url,
          featured, public, sort_order, status, notion_page_id, repo, area, deadline, last_activity_at,
          created_at, updated_at;

-- name: UpdateProjectLastActivity :exec
UPDATE projects SET last_activity_at = now(), updated_at = now()
WHERE notion_page_id = $1;

-- name: NotionProjectPageIDs :many
SELECT notion_page_id FROM projects WHERE notion_page_id IS NOT NULL ORDER BY title;

-- name: ArchiveProjectByNotionPageID :execrows
-- Archive a single project by its Notion page ID (used when Notion page is trashed).
UPDATE projects SET status = 'archived', updated_at = now()
WHERE notion_page_id = $1 AND status != 'archived';

-- name: ArchiveOrphanNotionProjects :execrows
UPDATE projects SET status = 'archived', updated_at = now()
WHERE notion_page_id IS NOT NULL
  AND notion_page_id != ALL(@active_ids::text[])
  AND status != 'archived';

-- name: ProjectByAlias :one
-- Resolve a project alias to a project via the project_aliases table.
SELECT p.id, p.slug, p.title, p.description, p.long_description, p.role,
       p.tech_stack, p.highlights, p.problem, p.solution, p.architecture,
       p.results, p.github_url, p.live_url, p.featured, p.public, p.sort_order,
       p.status, p.notion_page_id, p.repo, p.area, p.deadline, p.last_activity_at,
       p.created_at, p.updated_at
FROM project_aliases pa
JOIN projects p ON LOWER(p.title) = LOWER(pa.canonical_name)
WHERE LOWER(pa.alias) = LOWER(@alias);

-- name: ProjectByTitle :one
-- Resolve a project by case-insensitive title match.
SELECT id, slug, title, description, long_description, role, tech_stack, highlights,
       problem, solution, architecture, results, github_url, live_url,
       featured, public, sort_order, status, notion_page_id, repo, area, deadline, last_activity_at,
       created_at, updated_at
FROM projects WHERE LOWER(title) = LOWER($1);
