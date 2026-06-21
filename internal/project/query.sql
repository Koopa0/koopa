-- name: ProjectByID :one
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_by, proposal_rationale, created_at, updated_at
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
-- Admin project list. Excludes proposed projects — an agent-proposed project
-- is an inert draft that surfaces only in the admin proposals triage, never
-- the normal project list or picker.
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_by, proposal_rationale, created_at, updated_at
FROM projects WHERE status <> 'proposed' ORDER BY title;

-- name: PublicProjects :many
-- Public projects join project_profiles; portfolio flags live there. Proposed
-- projects are inert drafts and are never publicly listed — the is_public join
-- already excludes them (a proposed project has no profile), and the explicit
-- status guard keeps that invariant true even if a profile is created out of band.
SELECT p.id, p.slug, p.title, p.description, p.status, p.repo, p.area_id, p.goal_id,
       p.deadline, p.last_activity_at, p.expected_cadence, p.created_by, p.proposal_rationale,
       p.created_at, p.updated_at
FROM projects p
JOIN project_profiles pp ON pp.project_id = p.id
WHERE pp.is_public = true AND p.status <> 'proposed'
ORDER BY pp.featured DESC, pp.sort_order, p.title;

-- name: ProjectBySlug :one
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_by, proposal_rationale, created_at, updated_at
FROM projects WHERE slug = $1;

-- name: PublicProjectBySlug :one
-- Public project lookup by slug. Gated to publicly-visible projects only:
-- the project must have a project_profiles row with is_public = true and a
-- non-proposed status. This is the same publicity model as PublicProjects /
-- PublicProfiles — a proposed inert draft or a private project must NOT be
-- reachable through the unauthenticated /api/projects/{slug} route.
SELECT p.id, p.slug, p.title, p.description, p.status, p.repo, p.area_id, p.goal_id,
       p.deadline, p.last_activity_at, p.expected_cadence, p.created_by, p.proposal_rationale,
       p.created_at, p.updated_at
FROM projects p
JOIN project_profiles pp ON pp.project_id = p.id
WHERE p.slug = $1 AND pp.is_public = true AND p.status <> 'proposed';

-- name: CreateProject :one
-- Insert a new project. goal_id and area_id are optional links to the
-- parent goal / area; when supplied at create time the project shows up
-- under goal_progress.projects on the next read without needing a
-- separate UpdateProject call.
INSERT INTO projects (slug, title, description, status, goal_id, area_id)
VALUES ($1, $2, $3, $4, sqlc.narg('goal_id'), sqlc.narg('area_id'))
RETURNING id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
          expected_cadence, created_by, proposal_rationale, created_at, updated_at;

-- name: UpdateProject :one
UPDATE projects SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    title = COALESCE(sqlc.narg('title'), title),
    description = COALESCE(sqlc.narg('description'), description),
    status = COALESCE(sqlc.narg('status')::project_status, status),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
          expected_cadence, created_by, proposal_rationale, created_at, updated_at;

-- name: DeleteProject :exec
DELETE FROM projects WHERE id = $1;

-- name: ProjectByAlias :one
-- Resolve a project alias to a project via the project_aliases table. Resolves
-- regardless of status (including proposed) so capture_inbox can link a todo to
-- a just-proposed project before activation.
SELECT p.id, p.slug, p.title, p.description,
       p.status, p.repo, p.area_id, p.goal_id, p.deadline, p.last_activity_at,
       p.expected_cadence, p.created_by, p.proposal_rationale, p.created_at, p.updated_at
FROM project_aliases pa
JOIN projects p ON p.id = pa.project_id
WHERE LOWER(pa.alias) = LOWER(@alias);

-- name: ProjectByTitle :one
-- Resolve a project by case-insensitive title match.
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_by, proposal_rationale, created_at, updated_at
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

-- name: ProjectSummariesByGoalIDs :many
-- Lightweight project info for goal_progress output. Proposed projects are
-- inert drafts excluded from the goal's project view (they also carry no
-- goal_id today, so the exclusion is belt-and-suspenders against future linking).
SELECT id, slug, title, status, goal_id, last_activity_at
FROM projects
WHERE goal_id = ANY(@goal_ids::uuid[])
  AND status NOT IN ('proposed', 'archived')
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
-- List public project profiles joined with their projects for the portfolio
-- page. Proposed projects are inert drafts, never publicly listed (same guard
-- as PublicProjects).
SELECT p.id, p.slug, p.title, p.description, p.status, p.repo,
       p.deadline, p.last_activity_at, p.created_at AS project_created_at,
       pp.long_description, pp.role, pp.tech_stack, pp.highlights,
       pp.problem, pp.solution, pp.architecture, pp.results,
       pp.github_url, pp.live_url, pp.cover_image,
       pp.featured, pp.sort_order, pp.updated_at
FROM projects p
JOIN project_profiles pp ON pp.project_id = p.id
WHERE pp.is_public = true AND p.status <> 'proposed'
ORDER BY pp.featured DESC, pp.sort_order, p.title;

-- ============================================================
-- Proposals — agent-proposed inert project drafts (propose_project)
-- and the owner's admin-side triage (activate / reject / list / count).
-- ============================================================

-- name: ProposeProject :one
-- Insert an agent-proposed project as an inert draft (status='proposed').
-- created_by is the proposing agent. The project is excluded from every
-- list/picker until the owner activates it, but slug/alias/title/id resolvers
-- still match it so capture_inbox can link a todo before activation.
INSERT INTO projects (slug, title, description, status, created_by, proposal_rationale)
VALUES (@slug, @title, @description, 'proposed', @created_by, @proposal_rationale)
RETURNING id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
          expected_cadence, created_by, proposal_rationale, created_at, updated_at;

-- name: ActivateProject :one
-- Owner stamp on a proposed project: proposed → in_progress. The state-scoped
-- WHERE makes the transition atomic; zero rows means the row is missing or not
-- proposed (the store disambiguates with a follow-up read).
UPDATE projects SET status = 'in_progress', updated_at = now()
WHERE id = @id AND status = 'proposed'
RETURNING id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
          expected_cadence, created_by, proposal_rationale, created_at, updated_at;

-- name: DeleteProposedProject :execrows
-- Reject (hard DELETE) a proposed project. Proposed-only: a non-proposed project
-- is a real planning record and must never be deleted by this path. Linked todos
-- and contents survive unclassified (their project_id is ON DELETE SET NULL); the
-- project_profile CASCADEs.
DELETE FROM projects WHERE id = @id AND status = 'proposed';

-- name: ProposedProjects :many
-- Every proposed project awaiting owner triage, newest first. Feeds the
-- proposals triage surface. proposal_rationale is the agent's why-now
-- justification, shown on the triage card.
SELECT id, slug, title, description, created_by, proposal_rationale, created_at
FROM projects
WHERE status = 'proposed'
ORDER BY created_at DESC;

-- name: ProposedProjectsCount :one
-- Count of proposed projects awaiting owner triage (the project component of the
-- nav-badge proposals count; goals and areas are counted in the goal package).
SELECT count(*)::bigint AS proposed_projects FROM projects WHERE status = 'proposed';
