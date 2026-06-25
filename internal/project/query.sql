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

-- name: ProjectsOverview :many
-- Admin project-list view: each non-proposed project with its parent area name,
-- goal breadcrumb, todo progress, and last activity. Powers the projects-list
-- page (todo_done/todo_total progress bar + staleness badge). area_name/goal_*
-- are NULL when unfiled; todo_total/todo_done count the project's todos.
SELECT p.id, p.slug, p.title, p.status,
       a.name AS area_name,
       p.goal_id, g.title AS goal_title,
       p.last_activity_at,
       COUNT(t.id) AS todo_total,
       COUNT(t.id) FILTER (WHERE t.state = 'done') AS todo_done
FROM projects p
LEFT JOIN areas a ON a.id = p.area_id
LEFT JOIN goals g ON g.id = p.goal_id
LEFT JOIN todos t ON t.project_id = p.id
WHERE p.status <> 'proposed'
GROUP BY p.id, a.name, g.title
ORDER BY p.title;

-- name: ProjectBySlug :one
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_by, proposal_rationale, created_at, updated_at
FROM projects WHERE slug = $1;

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

-- name: ProjectByTitle :one
-- Resolve a project by case-insensitive title match.
SELECT id, slug, title, description, status, repo, area_id, goal_id, deadline, last_activity_at,
       expected_cadence, created_by, proposal_rationale, created_at, updated_at
FROM projects WHERE LOWER(title) = LOWER($1);

-- name: UpdateProjectStatus :one
-- Update a project's status and optionally its description and expected
-- cadence. See project.Store.UpdateStatus.
UPDATE projects SET
    status = @status::project_status,
    description = COALESCE(sqlc.narg('description'), description),
    expected_cadence = COALESCE(sqlc.narg('expected_cadence'), expected_cadence),
    updated_at = now()
WHERE projects.id = @id
RETURNING projects.id, projects.slug, projects.title, projects.description,
          projects.status, projects.repo, projects.area_id, projects.goal_id,
          projects.deadline, projects.last_activity_at, projects.expected_cadence,
          projects.created_at, projects.updated_at;

-- name: ProjectSummariesByGoalIDs :many
-- Lightweight project info for goal_progress output. Proposed projects are
-- inert drafts excluded from the goal's project view (they also carry no
-- goal_id today, so the exclusion is belt-and-suspenders against future linking).
SELECT id, slug, title, status, goal_id, last_activity_at
FROM projects
WHERE goal_id = ANY(@goal_ids::uuid[])
  AND status NOT IN ('proposed', 'archived')
ORDER BY goal_id;

-- name: ProjectsByArea :many
-- Lightweight project info for the admin area-detail page. Excludes proposed
-- (inert drafts) and archived projects — same active-read filter as
-- ProjectSummariesByGoalIDs. Indexed by idx_projects_area on projects.area_id.
SELECT id, slug, title, status, goal_id, last_activity_at
FROM projects
WHERE area_id = @area_id
  AND status NOT IN ('proposed', 'archived')
ORDER BY title;

-- ============================================================
-- project_progress — owner PARA momentum/stalled intelligence.
-- Read-only, computed LIVE at read time. Nothing is stored: there is
-- no momentum/stalled column and no snapshot table; activity_events is
-- the single source of truth for "what happened, by whom".
-- ============================================================

-- name: ProjectMomentum :many
-- Per-project momentum row for the project_progress tool. One row per
-- candidate project (status in_progress|planned AND expected_cadence set —
-- proposed/archived/cadence-less projects are excluded because a project
-- without a cadence has no "expected frequency" to be stalled against).
--
-- HUMAN ACTIVITY ONLY: last_human_activity_at is the latest
-- activity_events.occurred_at for an event scoped to this project
-- (activity_events.project_id = p.id) where actor = 'human'. Agent/system
-- actors (planner, hermes, codex, claude, system, …) never count as owner
-- progress, so the correlated subquery filters actor = 'human'. We compute
-- this live rather than trusting projects.last_activity_at, which is a cron
-- denormalisation that records ANY actor.
--
-- open_next_action is true when the project has at least one OPEN todo
-- (state in inbox|todo|someday — anything not done) OR at least one
-- INCOMPLETE milestone on its goal (completed_at IS NULL). A project with no
-- open next action is "待規劃", never stalled — the handler decides stalled.
--
-- milestone_done/milestone_total count the project's GOAL's milestones (0/0
-- when the project has no goal). The decision of WHAT counts as stalled lives
-- in Go (project.Stalled), not in SQL: this query only surfaces the inputs.
SELECT
    p.id,
    p.slug,
    p.title,
    p.goal_id,
    g.title AS goal_title,
    p.expected_cadence,
    ha.last_human_activity_at,
    (
        EXISTS (
            SELECT 1 FROM todos t
            WHERE t.project_id = p.id
              AND t.state <> 'done'
        )
        OR EXISTS (
            SELECT 1 FROM milestones m
            WHERE m.goal_id = p.goal_id
              AND m.completed_at IS NULL
        )
    ) AS open_next_action,
    (
        SELECT count(*) FROM milestones m
        WHERE m.goal_id = p.goal_id AND m.completed_at IS NOT NULL
    )::bigint AS milestone_done,
    (
        SELECT count(*) FROM milestones m
        WHERE m.goal_id = p.goal_id
    )::bigint AS milestone_total
FROM projects p
LEFT JOIN goals g ON g.id = p.goal_id
LEFT JOIN (
    SELECT ae.project_id, max(ae.occurred_at) AS last_human_activity_at
    FROM activity_events ae
    WHERE ae.actor = 'human'
    GROUP BY ae.project_id
) ha ON ha.project_id = p.id
WHERE p.status IN ('in_progress', 'planned')
  AND p.expected_cadence IS NOT NULL
ORDER BY p.title;

-- name: ActiveGoalMilestones :many
-- Milestone counts for every active (in_progress) goal, for the goals[]
-- rollup in project_progress. The projects' momentum rollup is assembled in
-- Go by grouping ProjectMomentum rows on goal_id — this query supplies the
-- per-goal milestone progress that has no project to hang off.
SELECT
    g.id,
    g.title,
    (
        SELECT count(*) FROM milestones m
        WHERE m.goal_id = g.id AND m.completed_at IS NOT NULL
    )::bigint AS milestone_done,
    (
        SELECT count(*) FROM milestones m
        WHERE m.goal_id = g.id
    )::bigint AS milestone_total
FROM goals g
WHERE g.status = 'in_progress'
ORDER BY g.title;

-- name: ActiveAreaActivity :many
-- One row per active PARA area for the areas[] neglect rollup in
-- project_progress. last_human_activity_at is the latest human-actor
-- activity_events.occurred_at across every project filed under the area
-- (NULL when the area has no human activity at all). The handler applies the
-- 14-day neglect threshold (project.AreaNeglectedThreshold); this query only
-- surfaces the live signal.
SELECT
    a.slug,
    a.name,
    ha.last_human_activity_at
FROM areas a
LEFT JOIN (
    SELECT p.area_id, max(ae.occurred_at) AS last_human_activity_at
    FROM activity_events ae
    JOIN projects p ON p.id = ae.project_id
    WHERE ae.actor = 'human'
    GROUP BY p.area_id
) ha ON ha.area_id = a.id
WHERE a.status = 'active'
ORDER BY a.sort_order, a.name;

-- ============================================================
-- review_period — windowed owner retrospective. Read-only, computed LIVE
-- from activity_events (the canonical "what happened, by whom" log) over a
-- [since, until] window. HUMAN ACTIVITY ONLY for the owner-progress rows:
-- actor = 'human' — IDENTICAL to ProjectMomentum. The window bounds are
-- whole-day-inclusive instants passed by the handler ([since 00:00,
-- until 23:59:59] in the owner's timezone).
-- ============================================================

-- name: CompletedTodosInWindow :many
-- Todos the owner completed in the window, for review_period.completed_todos.
-- Sourced from activity_events (entity_type='todo', change_kind='completed',
-- actor='human'); title is the write-time entity_title snapshot so a
-- since-deleted todo still reports. project/area resolved via the event's
-- project_id (LEFT JOIN, null when the event had no project association).
SELECT
    ae.entity_title AS title,
    ae.occurred_at  AS completed_at,
    p.title         AS project_title,
    a.name          AS area_name
FROM activity_events ae
LEFT JOIN projects p ON p.id = ae.project_id
LEFT JOIN areas a ON a.id = p.area_id
WHERE ae.entity_type = 'todo'
  AND ae.change_kind = 'completed'
  AND ae.actor = 'human'
  AND ae.occurred_at >= @since AND ae.occurred_at <= @until
ORDER BY ae.occurred_at DESC;

-- name: CompletedMilestonesInWindow :many
-- Milestones the owner completed in the window, for
-- review_period.completed_milestones. Sourced from activity_events
-- (entity_type='milestone', change_kind='completed', actor='human'). goal/area
-- are resolved by joining the live milestone row (entity_id → milestones → goals
-- → areas); a hard-deleted milestone falls back to the entity_title snapshot
-- with null goal/area.
SELECT
    ae.entity_title AS title,
    ae.occurred_at  AS completed_at,
    g.title         AS goal_title,
    a.name          AS area_name
FROM activity_events ae
LEFT JOIN milestones m ON m.id = ae.entity_id
LEFT JOIN goals g ON g.id = m.goal_id
LEFT JOIN areas a ON a.id = g.area_id
WHERE ae.entity_type = 'milestone'
  AND ae.change_kind = 'completed'
  AND ae.actor = 'human'
  AND ae.occurred_at >= @since AND ae.occurred_at <= @until
ORDER BY ae.occurred_at DESC;

-- name: ActiveGoalsAdvancedInWindow :many
-- Every active (in_progress) goal with milestone progress and an "advanced"
-- flag for review_period.goals. milestone_done/total mirror ActiveGoalMilestones;
-- advanced is true when a HUMAN completed at least one of the goal's milestones
-- within the window. It joins each milestone to its 'completed' audit event by
-- entity_id and gates on actor='human' — the same human-only actor model the
-- rest of review_period uses — so an agent/system milestone completion never
-- counts as the owner's progress. milestone_done/total are overall progress and
-- stay actor-agnostic.
SELECT
    g.id,
    g.title,
    a.name AS area_name,
    (
        SELECT count(*) FROM milestones m
        WHERE m.goal_id = g.id AND m.completed_at IS NOT NULL
    )::bigint AS milestone_done,
    (
        SELECT count(*) FROM milestones m
        WHERE m.goal_id = g.id
    )::bigint AS milestone_total,
    EXISTS (
        SELECT 1
        FROM milestones m
        JOIN activity_events ae
            ON ae.entity_type = 'milestone' AND ae.entity_id = m.id
        WHERE m.goal_id = g.id
          AND ae.change_kind = 'completed'
          AND ae.actor = 'human'
          AND ae.occurred_at >= @since AND ae.occurred_at <= @until
    ) AS advanced
FROM goals g
LEFT JOIN areas a ON a.id = g.area_id
WHERE g.status = 'in_progress'
ORDER BY g.title;

-- name: AreaActivityInWindow :many
-- Per-active-area owner-activity count over the window, for review_period.areas.
-- activity_count is the number of activity_events (actor='human', occurred_at in
-- window) attributable to the area via project_id → projects.area_id. neglected
-- is derived by the handler as activity_count = 0.
SELECT
    a.name,
    count(ae.id)::bigint AS activity_count
FROM areas a
LEFT JOIN projects p ON p.area_id = a.id
LEFT JOIN activity_events ae
    ON ae.project_id = p.id
   AND ae.actor = 'human'
   AND ae.occurred_at >= @since AND ae.occurred_at <= @until
WHERE a.status = 'active'
GROUP BY a.id, a.name
ORDER BY a.sort_order, a.name;

-- name: TodosOpenedCountInWindow :one
-- Count of todos CREATED in the window across ALL actors (backlog inflow), for
-- review_period.counts.todos_opened. No actor filter: inflow is inflow whoever
-- captured it.
SELECT count(*)::bigint AS todos_opened
FROM activity_events ae
WHERE ae.entity_type = 'todo'
  AND ae.change_kind = 'created'
  AND ae.occurred_at >= @since AND ae.occurred_at <= @until;

-- name: ActiveDaysInWindow :one
-- Count of DISTINCT calendar days on which the owner had any activity in the
-- window, for review_period.counts.active_days. Human actor only; date() uses
-- the database session timezone, matching the whole-day window bounds the
-- handler supplies.
SELECT count(DISTINCT date(ae.occurred_at))::bigint AS active_days
FROM activity_events ae
WHERE ae.actor = 'human'
  AND ae.occurred_at >= @since AND ae.occurred_at <= @until;

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
-- and contents survive unclassified (their project_id is ON DELETE SET NULL).
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
