CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================
-- Enums
-- ============================================================

CREATE TYPE content_type AS ENUM (
    'article', 'essay', 'build-log', 'til', 'digest'
);

CREATE TYPE content_status AS ENUM (
    'draft', 'review', 'published', 'archived'
);

CREATE TYPE feed_entry_status AS ENUM (
    'unread', 'read', 'curated', 'ignored'
);

CREATE TYPE goal_status AS ENUM (
    'proposed', 'not_started', 'in_progress', 'done', 'abandoned', 'on_hold'
);

CREATE TYPE project_status AS ENUM (
    'proposed', 'planned', 'in_progress', 'on_hold', 'completed', 'maintained', 'archived'
);

CREATE TYPE todo_state AS ENUM (
    'inbox', 'todo', 'in_progress', 'done', 'someday', 'archived', 'dismissed'
);

CREATE TYPE agent_status AS ENUM ('active', 'retired');

-- ============================================================
-- Identity model: agents (registry projection)
--
-- Source of truth lives in Go: internal/agent/registry.go::BuiltinAgents().
-- This table is a DB projection of that registry — rows are upserted at
-- application startup by internal/agent/sync.go::SyncToTable. It stores
-- identity only (name, platform, status); the registry carries any
-- additional in-process metadata.
--
-- The table exists so that provenance columns (created_by on todos,
-- areas, goals, projects) can maintain referential integrity to a known agent
-- identity, and so that retiring an agent leaves an auditable trace
-- (status='retired', retired_at).
-- ============================================================

CREATE TABLE agents (
    name         TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    platform     TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    status       agent_status NOT NULL DEFAULT 'active',
    synced_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_agent_name_format
        CHECK (name ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_agent_display_name_not_blank
        CHECK (btrim(display_name) <> ''),
    CONSTRAINT chk_agent_platform
        CHECK (platform IN ('claude-cowork', 'claude-code', 'claude-web', 'codex', 'human', 'system')),
    CONSTRAINT chk_agent_status_retired CHECK (
        (status = 'active'  AND retired_at IS NULL) OR
        (status = 'retired' AND retired_at IS NOT NULL)
    )
);

COMMENT ON TABLE agents IS 'DB projection of the Go BuiltinAgents() registry. Rows are upserted at startup by agent.SyncToTable. Stores identity only (name, platform, status). Provenance columns (created_by on todos/areas/goals/projects) use ON DELETE RESTRICT so historical records cannot dangle. Removed registry entries transition to status=retired rather than being deleted.';
COMMENT ON COLUMN agents.name IS 'Unique agent identifier. Used as the caller identity (as: field) in MCP tool calls and as FK target for created_by / assignee / curated_by columns. Format: lowercase, must start with a letter, alphanumeric + hyphens.';
COMMENT ON COLUMN agents.display_name IS 'Human-readable label for admin UI and logs. Non-blank (chk_agent_display_name_not_blank).';
COMMENT ON COLUMN agents.platform IS 'Execution context. Closed set: claude-cowork, claude-code, claude-web, codex, human, system (chk_agent_platform). The system value is reserved for the database-level fallback agent registered by BuiltinAgents — it attributes writes that bypass the Go actor middleware (pg_cron, manual psql ops, bug safety net). Routing decisions are driven by agent registry lookups, not this column.';
COMMENT ON COLUMN agents.description IS 'Short role description. Empty string = no description.';
COMMENT ON COLUMN agents.status IS 'active = currently present in BuiltinAgents(). retired = previously registered but no longer in the Go literal. chk_agent_status_retired ties retired_at to status=retired.';
COMMENT ON COLUMN agents.synced_at IS 'When this row was last reconciled with BuiltinAgents() by agent.SyncToTable. Updated on every startup sync.';
COMMENT ON COLUMN agents.retired_at IS 'When this agent was retired (removed from BuiltinAgents). NULL while status=active. Set by SyncToTable when the registry entry disappears.';
COMMENT ON COLUMN agents.created_at IS 'When the row was first upserted. Useful for onboarding audit.';

CREATE INDEX idx_agents_status ON agents (status);

-- ============================================================
-- Core domain: topics, users
-- ============================================================

CREATE TABLE users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_users_email_format
        CHECK (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$' AND length(email) <= 254)
);

COMMENT ON TABLE users IS 'System users. Single admin today; RBAC is a future concern with no current gate consumer.';
COMMENT ON COLUMN users.email IS 'Login identity. Unique. Basic structural validation via chk_users_email_format (full RFC 5322 compliance is enforced at the application layer).';
COMMENT ON COLUMN users.updated_at IS 'Application-managed. Set explicitly in UPDATE queries.';

CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_refresh_token_hash_not_blank
        CHECK (btrim(token_hash) <> '')
);

COMMENT ON TABLE refresh_tokens IS 'JWT refresh token hashes. One user may have multiple active tokens (multi-device).';
COMMENT ON COLUMN refresh_tokens.user_id IS 'Token owner. CASCADE — user deletion invalidates all tokens.';
COMMENT ON COLUMN refresh_tokens.token_hash IS 'Bcrypt or SHA256 hash of the actual token. Never store plaintext.';
COMMENT ON COLUMN refresh_tokens.expires_at IS 'Absolute expiration. Tokens past this time are invalid and eligible for cleanup.';

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

CREATE TABLE topics (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    icon        TEXT,
    sort_order  INT NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_topic_slug_format
        CHECK (slug ~ '^[^[:space:]/-]+(-[^[:space:]/-]+)*$'),
    CONSTRAINT chk_topic_name_not_blank
        CHECK (btrim(name) <> '')
);

COMMENT ON TABLE topics IS 'High-level knowledge domains (Go, AI, System Design). 10-20, manually managed. Used for content categorization and feed association.';
COMMENT ON COLUMN topics.slug IS 'URL-safe identifier (e.g. system-design, or 日本語). Used in feed_topics and content_topics junctions. Format (chk_topic_slug_format): hyphen-separated segments, no whitespace or slash, no leading/trailing/consecutive hyphens. Unicode letters/numbers (incl. CJK) allowed — slugs carry UTF-8 in URLs.';
COMMENT ON COLUMN topics.icon IS 'Optional emoji or icon identifier for UI display.';
COMMENT ON COLUMN topics.sort_order IS 'Priority tier for display ordering (lower = higher priority). Convention: sort_order is for tier-based UI placement that may have gaps; position is for sequence-based 0-based indexing within a parent. See top-of-file ordering convention block.';

-- ============================================================
-- Areas (PARA Areas of Responsibility)
-- ============================================================

CREATE TABLE areas (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    icon        TEXT,
    sort_order  INT NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('proposed', 'active')),
    created_by  TEXT REFERENCES agents(name) ON DELETE RESTRICT,
    proposal_rationale TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_area_slug_format
        CHECK (slug ~ '^[^[:space:]/-]+(-[^[:space:]/-]+)*$'),
    CONSTRAINT chk_area_name_not_blank
        CHECK (btrim(name) <> '')
);

COMMENT ON COLUMN areas.status IS
    'proposed | active. An agent-proposed area lands in ''proposed'' — inert: filtered out of '
    'every area selector / resolver, so it cannot become a real goal''s parent until activated. '
    'The owner activates (→ active) or rejects (DELETE) it in admin triage. Admin/seeded areas '
    'are ''active''. Default active so existing and admin inserts need not set it.';
COMMENT ON COLUMN areas.created_by IS
    'Provenance. NULL = system/seed origin — areas are seeded in 002 before any agents row '
    'exists at startup, so this is NULLABLE with NO default (a NOT NULL or DEFAULT-''human'' FK '
    'would fail the seed with a foreign_key_violation). An agent name marks an area that agent proposed.';
COMMENT ON COLUMN areas.proposal_rationale IS
    'Agent''s why-propose-this-now justification, captured on a proposed row and shown to the owner '
    'in admin triage to support activate/reject. NULL for admin/seeded rows and acceptable to keep '
    'or clear on activation.';

COMMENT ON TABLE areas IS
    'PARA Areas of Responsibility — ongoing domains requiring sustained attention. '
    'Unlike projects (which complete), areas persist indefinitely. '
    'Each area has a standard to maintain, not a goal to achieve. '
    'Goals and projects reference areas via FK.';

COMMENT ON COLUMN areas.slug IS
    'URL-safe identifier (e.g. backend, learning, studio). Used in filters and API.';
COMMENT ON COLUMN areas.name IS
    'Display name (e.g. Backend, Learning, Studio).';
COMMENT ON COLUMN areas.description IS
    'What this area of responsibility covers and what "maintaining the standard" means.';
COMMENT ON COLUMN areas.icon IS
    'Optional emoji or icon identifier for UI display.';
COMMENT ON COLUMN areas.sort_order IS
    'Display ordering. Lower = higher priority.';
COMMENT ON COLUMN areas.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

-- ============================================================
-- Goals (before projects, projects FK to goals)
-- ============================================================

CREATE TABLE goals (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title             TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    status            goal_status NOT NULL DEFAULT 'not_started',
    area_id           UUID REFERENCES areas(id) ON DELETE SET NULL,
    quarter           TEXT,
    deadline          TIMESTAMPTZ,
    created_by        TEXT REFERENCES agents(name) ON DELETE RESTRICT,
    proposal_rationale TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_goal_title_not_blank
        CHECK (btrim(title) <> '')
);

COMMENT ON TABLE goals IS
    'Planning objectives — aspirational outcomes with optional deadlines. '
    'Each goal may have milestones (progress checkpoints) and projects (execution vehicles). '
    'Milestone progress is advisory — goal status is managed manually, not auto-derived.';
COMMENT ON COLUMN goals.status IS
    'Lifecycle: proposed → not_started → in_progress → done | abandoned | on_hold. '
    'proposed = agent-proposed draft, inert — ActiveGoals filters in_progress, so a proposed '
    'goal never reaches brief / alignment; the owner activates it to not_started in admin triage '
    'or rejects (DELETE, milestones CASCADE). on_hold = paused but not abandoned, can resume to '
    'in_progress. abandoned = terminal, will not pursue.';
COMMENT ON COLUMN goals.created_by IS
    'Provenance. NULL = system/admin origin; an agent name marks a goal that agent proposed. '
    'NULLABLE with no default, mirroring areas.created_by.';
COMMENT ON COLUMN goals.proposal_rationale IS
    'Agent''s why-propose-this-now justification, captured on a proposed row and shown to the owner '
    'in admin triage to support activate/reject. NULL for admin/seeded rows and acceptable to keep '
    'or clear on activation.';
COMMENT ON COLUMN goals.area_id IS
    'PARA Area of Responsibility this goal belongs to. FK to areas. '
    'SET NULL on area deletion — goal survives unclassified. NULL = no area assigned.';
COMMENT ON COLUMN goals.quarter IS 'Target quarter (e.g. "Q1 2026"). Free-form text. NULL = no quarter assigned.';
COMMENT ON COLUMN goals.deadline IS 'Hard deadline if any. NULL = no deadline.';
COMMENT ON COLUMN goals.updated_at IS 'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_goals_lower_title ON goals (LOWER(title));
CREATE INDEX idx_goals_area ON goals (area_id) WHERE area_id IS NOT NULL;

-- ============================================================
-- Milestones (goal progress checkpoints)
-- ============================================================

CREATE TABLE milestones (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title             TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    goal_id           UUID NOT NULL REFERENCES goals(id) ON DELETE CASCADE,
    target_deadline   DATE,
    completed_at      TIMESTAMPTZ,
    position          INT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (goal_id, title),
    UNIQUE (goal_id, position),

    CONSTRAINT chk_milestone_title_not_blank
        CHECK (btrim(title) <> '')
);

CREATE INDEX idx_milestones_goal ON milestones (goal_id, position);

COMMENT ON TABLE milestones IS
    'Goal progress checkpoints — binary completion markers within a goal. '
    'Milestones and projects are siblings under a goal: '
    'a project advances a goal through work, a milestone marks progress. '
    'Completion determined by completed_at IS NOT NULL — no separate status column. '
    'Goal progress = completed milestones / total milestones (advisory, not auto-derived). '
    'NOT OKR Key Results — milestones are binary (done/not-done), '
    'not quantitative metrics with target_value/current_value.';

COMMENT ON COLUMN milestones.title IS
    'Descriptive, measurable checkpoint name (e.g. "N3 合格", "API layer complete"). '
    'UNIQUE per goal — no duplicate milestone names within the same goal.';
COMMENT ON COLUMN milestones.description IS
    'Detail on what this milestone means and how to measure achievement. '
    'Empty string = no detail provided.';
COMMENT ON COLUMN milestones.goal_id IS
    'Parent goal. NOT NULL — every milestone must belong to a goal. CASCADE on delete.';
COMMENT ON COLUMN milestones.target_deadline IS
    'Target completion date. NULL = no time target (pure checkpoint). '
    'Enables mid-goal on-track/at-risk analysis in weekly summary.';
COMMENT ON COLUMN milestones.completed_at IS
    'When this milestone was achieved. NULL = not yet completed. '
    'This is the sole completion indicator — no status enum.';
COMMENT ON COLUMN milestones.position IS
    'Sequence position within a goal (0-based). Convention: position is the gap-free '
    'sequence index a row holds inside its parent; sort_order is the priority tier '
    'used for top-level UI ordering. See top-of-file ordering convention block.';
COMMENT ON COLUMN milestones.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

-- ============================================================
-- Projects (PARA execution vehicles) + project_profiles (public portfolio)
--
-- Split rationale: projects is a planning aggregate with PARA lifecycle
-- (status: planned → in_progress → completed | archived). project_profiles
-- is a curated public artifact whose lifecycle is independent — a profile
-- may be edited months after the project completed. One-to-one relationship
-- (project_id is the profile's PRIMARY KEY).
-- ============================================================

CREATE TABLE projects (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug              TEXT NOT NULL UNIQUE,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    status            project_status NOT NULL DEFAULT 'in_progress',
    repo              TEXT,
    area_id           UUID REFERENCES areas(id) ON DELETE SET NULL,
    goal_id           UUID REFERENCES goals(id) ON DELETE SET NULL,
    deadline          TIMESTAMPTZ,
    last_activity_at  TIMESTAMPTZ,
    expected_cadence  TEXT CHECK (expected_cadence IN ('daily', 'weekly', 'biweekly', 'monthly')),
    created_by        TEXT REFERENCES agents(name) ON DELETE RESTRICT,
    proposal_rationale TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_project_slug_format
        CHECK (slug ~ '^[^[:space:]/-]+(-[^[:space:]/-]+)*$'),
    CONSTRAINT chk_project_title_not_blank
        CHECK (btrim(title) <> '')
);

COMMENT ON TABLE projects IS
    'PARA projects — planning aggregate, execution vehicles. Short-term efforts '
    'with clear outcomes. Projects and milestones are siblings under a goal: '
    'a project may advance a goal without mapping to a specific milestone. '
    'Public portfolio/case-study fields live in project_profiles (1:1).';
COMMENT ON COLUMN projects.status IS
    'Lifecycle: proposed → planned | in_progress → on_hold → completed | maintained | archived. '
    'proposed = agent-proposed draft, inert — excluded from the admin project list, the public '
    'portfolio, and the goal project view; the owner activates it to in_progress in admin triage '
    'or rejects (hard DELETE). Slug/alias/title/id resolvers still match a proposed project so '
    'capture_inbox can link a todo to it before activation. archived = no longer active.';
COMMENT ON COLUMN projects.created_by IS
    'Provenance. NULL = system/admin origin; an agent name marks a project that agent proposed. '
    'NULLABLE with no default, mirroring goals.created_by / areas.created_by.';
COMMENT ON COLUMN projects.proposal_rationale IS
    'Agent''s why-propose-this-now justification, captured on a proposed row and shown to the owner '
    'in admin triage to support activate/reject. NULL for admin/seeded rows and acceptable to keep '
    'or clear on activation.';
COMMENT ON COLUMN projects.area_id IS
    'PARA Area of Responsibility. FK to areas. SET NULL on area deletion. NULL = unclassified.';
COMMENT ON COLUMN projects.repo IS 'GitHub repository full name (e.g. Koopa0/koopa0.dev). Informational only — used by activity event resolution.';
COMMENT ON COLUMN projects.expected_cadence IS 'Expected development activity frequency. NULL = not set.';
COMMENT ON COLUMN projects.goal_id IS
    'Which goal this project serves. Nullable — a project can exist without a goal '
    '(PARA: some projects are pure Area maintenance, not goal-driven). SET NULL on goal deletion.';
COMMENT ON COLUMN projects.last_activity_at IS 'Timestamp of most recent activity event for this project. Updated by cron.';
COMMENT ON COLUMN projects.updated_at IS 'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_projects_lower_title ON projects (LOWER(title));
CREATE INDEX idx_projects_repo ON projects (repo) WHERE repo IS NOT NULL;
CREATE INDEX idx_projects_status ON projects (status) WHERE status NOT IN ('completed', 'archived');
CREATE INDEX idx_projects_goal_id ON projects(goal_id) WHERE goal_id IS NOT NULL;
CREATE INDEX idx_projects_area ON projects (area_id) WHERE area_id IS NOT NULL;

CREATE TABLE project_profiles (
    project_id        UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    long_description  TEXT,
    role              TEXT,
    tech_stack        TEXT[] NOT NULL DEFAULT '{}',
    highlights        TEXT[] NOT NULL DEFAULT '{}',
    problem           TEXT,
    solution          TEXT,
    architecture      TEXT,
    results           TEXT,
    github_url        TEXT,
    live_url          TEXT,
    cover_image       TEXT,
    featured          BOOLEAN NOT NULL DEFAULT false,
    is_public         BOOLEAN NOT NULL DEFAULT false,
    sort_order        INT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_project_profile_github_url
        CHECK (github_url IS NULL OR github_url ~ '^https://github\.com/'),
    CONSTRAINT chk_project_profile_live_url
        CHECK (live_url IS NULL OR live_url ~ '^https?://')
);

COMMENT ON TABLE project_profiles IS
    'Public portfolio / case-study facet of a project. 1:1 with projects (project_id PK). '
    'Lifecycle is independent: a profile can be edited long after its project completed. '
    'Existence of a row means the project has been curated for public display (even if is_public=false). '
    'CASCADE on project deletion — orphaned profiles make no sense. '
    'Invariant: is_public=true is only permitted when the owning projects.status != ''archived''. '
    'Enforced by trg_project_profile_not_public_if_archived (structural invariant trigger); '
    'archived→private demote on the project side runs in internal/project.Store.UpdateStatus.';
COMMENT ON COLUMN project_profiles.role IS 'User role in this project (e.g. Lead Engineer, Sole Developer). NULL = not specified.';
COMMENT ON COLUMN project_profiles.long_description IS 'Extended description for project detail page. NULL = use projects.description.';
COMMENT ON COLUMN project_profiles.problem IS 'Case study: what problem this project solves.';
COMMENT ON COLUMN project_profiles.solution IS 'Case study: how the problem was solved.';
COMMENT ON COLUMN project_profiles.architecture IS 'Case study: system architecture description.';
COMMENT ON COLUMN project_profiles.results IS 'Case study: measurable outcomes.';
COMMENT ON COLUMN project_profiles.github_url IS 'Full GitHub repository URL. NULL = no public repo.';
COMMENT ON COLUMN project_profiles.live_url IS 'Production deployment URL. NULL = not deployed.';
COMMENT ON COLUMN project_profiles.cover_image IS 'Cover image URL/path for portfolio cards. NULL = no cover.';
COMMENT ON COLUMN project_profiles.featured IS 'Whether to show on the public portfolio homepage. Requires is_public=true to take effect.';
COMMENT ON COLUMN project_profiles.is_public IS 'Whether this profile is visible on the public website.';
COMMENT ON COLUMN project_profiles.sort_order IS 'Display ordering in portfolio listings. Lower = higher priority.';
COMMENT ON COLUMN project_profiles.updated_at IS 'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_project_profiles_featured ON project_profiles (featured DESC, sort_order) WHERE is_public = true;
CREATE INDEX idx_project_profiles_public ON project_profiles (sort_order) WHERE is_public = true;

-- Structural invariant: a public project_profile must belong to a non-archived
-- project. The reverse direction (project → archived also demotes the profile)
-- is handled by internal/project.Store.UpdateStatus per the no-business-logic-
-- in-triggers rule. This trigger catches the complementary gap: any path that
-- sets project_profiles.is_public=true (INSERT or UPDATE) when the owning
-- project is already archived — e.g. manual psql, admin UI bug, migration
-- backfill. It is read-only (no cross-aggregate side effect); it only raises
-- EXCEPTION when the invariant would be broken.
CREATE OR REPLACE FUNCTION enforce_project_profile_not_public_if_archived() RETURNS TRIGGER AS $$
DECLARE
    owning_status project_status;
BEGIN
    IF NEW.is_public IS NOT TRUE THEN
        RETURN NEW;
    END IF;
    SELECT status INTO owning_status FROM projects WHERE id = NEW.project_id;
    IF owning_status = 'archived' THEN
        RAISE EXCEPTION 'project_profile.is_public=true is not permitted when projects.status=''archived'' (project_id=%). Unarchive the project first, or demote the profile (is_public=false).', NEW.project_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_project_profile_not_public_if_archived
    BEFORE INSERT OR UPDATE OF is_public, project_id ON project_profiles
    FOR EACH ROW EXECUTE FUNCTION enforce_project_profile_not_public_if_archived();

-- ============================================================
-- Contents
-- ============================================================

CREATE TABLE contents (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          TEXT NOT NULL UNIQUE,
    title         TEXT NOT NULL,
    body          TEXT NOT NULL DEFAULT '',
    excerpt       TEXT NOT NULL DEFAULT '',
    type          content_type NOT NULL,
    status        content_status NOT NULL DEFAULT 'draft',
    series_id     TEXT,
    series_order  INT,
    ai_metadata   JSONB,
    reading_time_min INT NOT NULL DEFAULT 0 CHECK (reading_time_min >= 0),
    cover_image   TEXT,
    is_public     BOOLEAN NOT NULL DEFAULT false,
    project_id    UUID REFERENCES projects(id) ON DELETE SET NULL,
    created_by    TEXT REFERENCES agents(name) ON DELETE RESTRICT,
    proposal_rationale TEXT,
    published_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    embedding     vector(1536),
    search_vector TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(left(body, 10000), '')), 'C')
    ) STORED,
    CONSTRAINT chk_contents_series CHECK (
        (series_id IS NULL AND series_order IS NULL) OR
        (series_id IS NOT NULL AND series_order IS NOT NULL)
    ),
    CONSTRAINT chk_content_slug_format
        CHECK (slug ~ '^[^[:space:]/-]+(-[^[:space:]/-]+)*$'),
    CONSTRAINT chk_content_title_not_blank
        CHECK (btrim(title) <> ''),
    CONSTRAINT chk_content_publication
        CHECK ((status = 'published') = (published_at IS NOT NULL)),
    CONSTRAINT chk_content_public_requires_published
        CHECK (NOT is_public OR status = 'published')
);

COMMENT ON TABLE contents IS 'First-party publishable knowledge layer. Five content types (article, essay, build-log, til, digest) share one editorial lifecycle: draft → review → published → archived. The review state is a two-actor handoff signal — Claude marks a draft ready (set_content_review_state), human admin publishes (publish_content). published status and published_at are tied by chk_content_publication; is_public requires published by chk_content_public_requires_published.';
COMMENT ON COLUMN contents.slug IS 'URL-safe identifier. Globally unique. Used in public URLs. Format (chk_content_slug_format): hyphen-separated segments, no whitespace or slash, no leading/trailing/consecutive hyphens. Unicode letters/numbers (incl. CJK) allowed — a 中日文 slug carries UTF-8 in the URL.';
COMMENT ON COLUMN contents.type IS 'Content format: article, essay, build-log, til, digest. All are public-facing first-party content going through the review lifecycle.';
COMMENT ON COLUMN contents.status IS 'Lifecycle: draft → review → published. review = Claude-submitted, awaiting human publish. archived = soft delete. Transition review → published is human-admin only (enforced at MCP tool boundary).';
COMMENT ON COLUMN contents.series_id IS 'Groups content into a series. Paired with series_order (chk_contents_series).';
COMMENT ON COLUMN contents.series_order IS 'Position within the series. Paired with series_id (chk_contents_series).';
COMMENT ON COLUMN contents.reading_time_min IS 'Estimated reading time in minutes. Computed from body word count. Always >= 0.';
COMMENT ON COLUMN contents.ai_metadata IS 'AI pipeline metadata (JSONB). Structure: {summary, keywords, quality_score, review_notes}. Set by background AI enrichment.';
COMMENT ON COLUMN contents.cover_image IS 'Cover image URL or path for content cards and social sharing. NULL = no cover image.';
COMMENT ON COLUMN contents.is_public IS
    'Whether this content is rendered on the public website. Defaults to false '
    '(private-by-default). When true, status MUST be ''published'' '
    '(chk_content_public_requires_published). PublishContent flips status, '
    'published_at, and is_public together — publishing makes public in this system.';
COMMENT ON COLUMN contents.project_id IS 'Associated project. SET NULL on project deletion — content survives independently.';
COMMENT ON COLUMN contents.created_by IS 'Proposing agent for agent-pushed content (references agents(name), e.g. hermes pushing a finished draft via the propose_content MCP tool). NULL for owner/admin-authored content created through the admin UI. ON DELETE RESTRICT — a registered agent that has proposed content cannot be removed while its proposals exist.';
COMMENT ON COLUMN contents.proposal_rationale IS 'The proposing agent''s "why I propose this" note, shown alongside the row in the admin review queue. NULL for admin-authored content (no agent rationale).';
COMMENT ON COLUMN contents.published_at IS 'When content was published. NULL = not yet published.';
COMMENT ON COLUMN contents.search_vector IS
    'Generated tsvector for full-text search. Uses ''simple'' config (no stemming/language-specific '
    'tokenization) for multilingual safety. Weight A = title, C = body (first 10K chars). '
    'Semantic search via embedding compensates for tsvector recall limitations.';
COMMENT ON COLUMN contents.embedding IS 'pgvector embedding (1536d) from gemini-embedding-2. See internal/embedder.Dimension — schema + Go must match exactly or pgvector rejects writes.';
COMMENT ON COLUMN contents.updated_at IS 'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_contents_status ON contents(status);
CREATE INDEX idx_contents_type ON contents(type);
CREATE INDEX idx_contents_published_at ON contents(published_at DESC NULLS LAST);
CREATE INDEX idx_contents_search ON contents USING GIN(search_vector);
CREATE INDEX idx_contents_series ON contents(series_id, series_order) WHERE series_id IS NOT NULL;
CREATE INDEX idx_contents_embedding_hnsw ON contents USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);
CREATE INDEX idx_contents_is_public ON contents(status, is_public)
    WHERE status = 'published' AND is_public = true;
CREATE INDEX idx_contents_project_id ON contents(project_id) WHERE project_id IS NOT NULL;
CREATE INDEX idx_contents_created_at ON contents(created_at DESC);
CREATE INDEX idx_contents_published_at_pub ON contents (published_at DESC NULLS LAST)
    WHERE status = 'published';

-- ============================================================
-- Junction: contents ↔ topics
-- ============================================================

CREATE TABLE content_topics (
    content_id UUID NOT NULL REFERENCES contents(id) ON DELETE CASCADE,
    topic_id   UUID NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    PRIMARY KEY (content_id, topic_id)
);

COMMENT ON TABLE content_topics IS 'Junction: content ↔ topic. Many-to-many. Curated knowledge domain categories.';

CREATE INDEX idx_content_topics_topic_id ON content_topics(topic_id);

-- ============================================================
-- Feeds + feed entries
-- ============================================================

CREATE TABLE feeds (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url                  TEXT NOT NULL UNIQUE,
    name                 TEXT NOT NULL,
    schedule             TEXT NOT NULL,
    enabled              BOOLEAN NOT NULL DEFAULT true,
    priority             TEXT NOT NULL DEFAULT 'normal'
                         CHECK (priority IN ('normal', 'high', 'low')),
    etag                 TEXT,
    last_modified        TEXT,
    last_fetched_at      TIMESTAMPTZ,
    consecutive_failures INT NOT NULL DEFAULT 0,
    last_error           TEXT,
    disabled_reason      TEXT,
    filter_config        JSONB NOT NULL DEFAULT '{}',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_enabled_reason
        CHECK ((enabled = true AND disabled_reason IS NULL) OR (enabled = false)),
    CONSTRAINT chk_feed_url_scheme
        CHECK (url ~ '^https?://'),
    CONSTRAINT chk_feed_name_not_blank
        CHECK (btrim(name) <> ''),
    CONSTRAINT chk_feed_schedule
        CHECK (schedule IN ('hourly', 'daily', 'weekly', 'biweekly', 'monthly'))
);

COMMENT ON TABLE feeds IS 'RSS/Atom feed subscriptions. Fetch pipeline pulls entries on schedule, scores relevance, and surfaces for curation.';
COMMENT ON COLUMN feeds.url IS 'Feed URL (RSS/Atom). Unique — one subscription per URL. Must use http(s) scheme (chk_feed_url_scheme).';
COMMENT ON COLUMN feeds.schedule IS 'Fetch cadence label (hourly | daily | weekly | biweekly | monthly), enforced by chk_feed_schedule. The Go scheduler maps each label to a concrete time interval. NOT a cron expression.';
COMMENT ON COLUMN feeds.priority IS 'Feed importance for relevance scoring: high feeds get boosted scores.';
COMMENT ON COLUMN feeds.etag IS 'HTTP ETag header from last fetch. NULL = never fetched or server did not return ETag.';
COMMENT ON COLUMN feeds.last_modified IS 'HTTP Last-Modified header from last fetch. NULL = never fetched or server did not return it.';
COMMENT ON COLUMN feeds.last_error IS 'Error message from last failed fetch. NULL = no error (last fetch succeeded or never fetched).';
COMMENT ON COLUMN feeds.disabled_reason IS 'Why this feed was disabled. NULL = not disabled or no reason recorded.';
COMMENT ON COLUMN feeds.consecutive_failures IS 'Number of consecutive fetch failures. Reset to 0 on success. Auto-disable threshold in Go.';
COMMENT ON COLUMN feeds.last_fetched_at IS 'When the feed was last successfully fetched. NULL = never fetched.';
COMMENT ON COLUMN feeds.filter_config IS 'Feed-specific filter rules (JSONB). Structure: {deny_paths, deny_title_patterns, deny_tags}. Empty {} = no filtering.';
COMMENT ON COLUMN feeds.updated_at IS 'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_feeds_schedule ON feeds (schedule) WHERE enabled = true;

CREATE TABLE feed_topics (
    feed_id  UUID NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    topic_id UUID NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    PRIMARY KEY (feed_id, topic_id)
);

COMMENT ON TABLE feed_topics IS 'Many-to-many: which topics a feed covers.';

CREATE INDEX idx_feed_topics_topic ON feed_topics(topic_id);

CREATE TABLE feed_entries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_url          TEXT NOT NULL,
    title               TEXT NOT NULL,
    original_content    TEXT NOT NULL DEFAULT '',
    status              feed_entry_status NOT NULL DEFAULT 'unread',
    curated_content_id  UUID REFERENCES contents(id) ON DELETE SET NULL,
    collected_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    url_hash            TEXT NOT NULL,
    feed_id             UUID REFERENCES feeds(id) ON DELETE SET NULL,
    published_at        TIMESTAMPTZ,

    CONSTRAINT chk_feed_entry_url_hash_format
        CHECK (url_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT chk_feed_entry_curated_status
        CHECK (status <> 'curated' OR curated_content_id IS NOT NULL)
);

COMMENT ON TABLE feed_entries IS 'RSS feed items collected by the fetch pipeline. Topic association is read-through feed_topics at query time — changing a feed''s topics retroactively changes its entries'' visible topics. status=curated requires curated_content_id to be set.';
COMMENT ON COLUMN feed_entries.url_hash IS 'SHA256 hex of canonical source_url. Dedup identity. Computed in application code via internal/urlhash before INSERT.';
COMMENT ON COLUMN feed_entries.feed_id IS 'Source feed. SET NULL on feed deletion — entries retained for curation.';
COMMENT ON COLUMN feed_entries.title IS 'Article title from the RSS feed. Raw, not cleaned.';
COMMENT ON COLUMN feed_entries.original_content IS 'RSS entry content/summary as delivered by the feed. Empty string when none.';
COMMENT ON COLUMN feed_entries.source_url IS 'Original article URL.';
COMMENT ON COLUMN feed_entries.status IS 'Curation lifecycle: unread → read → curated | ignored.';
COMMENT ON COLUMN feed_entries.curated_content_id IS 'When curated into first-party content, references the contents row. SET NULL on content deletion. feed_entry → bookmark curation is not supported — use the bookmark UI directly.';
COMMENT ON COLUMN feed_entries.collected_at IS 'When the pipeline first fetched this entry.';
COMMENT ON COLUMN feed_entries.published_at IS 'Original publication date from the feed. NULL if not provided.';

CREATE INDEX idx_feed_entries_status ON feed_entries(status);
CREATE UNIQUE INDEX idx_feed_entries_url_hash ON feed_entries (url_hash);
CREATE INDEX idx_feed_entries_feed_id ON feed_entries (feed_id) WHERE feed_id IS NOT NULL;
CREATE INDEX idx_feed_entries_collected_at ON feed_entries (collected_at DESC);
CREATE INDEX idx_feed_entries_unread_at ON feed_entries (collected_at DESC) WHERE status = 'unread';
CREATE INDEX idx_feed_entries_unread_recent ON feed_entries (feed_id, collected_at DESC) WHERE status = 'unread';

CREATE INDEX idx_feeds_high_priority ON feeds(id) WHERE priority = 'high';

-- ============================================================
-- Process runs
--
-- Run-history records for background processes. Two kinds:
--   crawl          — internal crawl/fetch runs (RSS feed collector, etc.)
--   agent_schedule — external AI scheduler runs (claude-cowork, future hermes-agent)
-- kind-specific fields live in metadata per the JSONB promotion rule.
-- subsystem is the observability dimension for external AI schedulers.
-- ============================================================

CREATE TABLE process_runs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          TEXT NOT NULL CHECK (kind IN ('crawl', 'agent_schedule')),
    subsystem     TEXT,
    name          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    content_id    UUID REFERENCES contents(id) ON DELETE SET NULL,
    input         JSONB,
    output        JSONB,
    error         TEXT,
    attempt       INT NOT NULL DEFAULT 0,
    max_attempts  INT NOT NULL DEFAULT 1,
    started_at    TIMESTAMPTZ,
    ended_at      TIMESTAMPTZ,
    metadata      JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_process_runs_max_attempts_positive
        CHECK (max_attempts > 0),
    CONSTRAINT chk_process_runs_attempt_bounds
        CHECK (attempt >= 0 AND attempt <= max_attempts),
    CONSTRAINT chk_process_runs_error_on_failure
        CHECK ((status = 'failed') = (error IS NOT NULL)),
    CONSTRAINT chk_process_runs_ended_at_consistency
        CHECK (
            (status IN ('pending', 'running') AND ended_at IS NULL) OR
            (status IN ('completed', 'failed', 'skipped') AND ended_at IS NOT NULL)
        ),
    CONSTRAINT chk_process_runs_subsystem_iff_agent_schedule
        CHECK ((kind = 'agent_schedule') = (subsystem IS NOT NULL))
);

COMMENT ON TABLE process_runs IS
    'Run-history records for background processes. kind discriminates: crawl '
    '(internal crawl/fetch runs such as RSS feed collector), agent_schedule '
    '(external AI scheduler runs). Kind-specific fields live in metadata. '
    'subsystem carries the external-AI-scheduler identifier (only when '
    'kind=agent_schedule). RETENTION: 90 days for terminal runs; pending/running '
    'rows are operational state.';
COMMENT ON COLUMN process_runs.kind IS
    'Run category. Closed set: crawl (internal fetch/collector runs), agent_schedule '
    '(external AI scheduler runs). New kinds require CHECK update + Go writer. '
    'Use this column for dashboards, retention scoping, and metric labels.';
COMMENT ON COLUMN process_runs.subsystem IS
    'External AI scheduler identifier. NOT NULL iff kind=''agent_schedule'' '
    '(chk_process_runs_subsystem_iff_agent_schedule). Values mirror agent.Platform '
    'in BuiltinAgents() for agents with non-empty Schedule. Today the only value in '
    'use is ''claude-cowork''. Values are validated at the Go write path, not by a '
    'hardcoded CHECK list — new AI schedulers (e.g. hermes-agent) land without a '
    'schema migration.';
COMMENT ON COLUMN process_runs.name IS
    'Run identifier within its kind. crawl: collector name (e.g. "rss-feed-collector"). '
    'agent_schedule: "<agent_name>:<schedule_name>" composite from the Go dispatcher.';
COMMENT ON COLUMN process_runs.status IS
    'Lifecycle: pending → running → completed | failed | skipped. chk_process_runs_error_on_failure '
    'ties error to failed status. chk_process_runs_ended_at_consistency ties ended_at to terminal states.';
COMMENT ON COLUMN process_runs.content_id IS
    'For kind=crawl runs that process a content row. SET NULL on content deletion — diagnostics retained. '
    'NULL for runs that do not operate on a single content.';
COMMENT ON COLUMN process_runs.input IS
    'Run input payload (JSONB). Structure varies by kind/name. NULL for kinds with no structured input.';
COMMENT ON COLUMN process_runs.output IS
    'Run output payload (JSONB). NULL until run completes. Structure varies by kind/name.';
COMMENT ON COLUMN process_runs.error IS
    'Error message on failure. NULL on non-failed status, enforced by chk_process_runs_error_on_failure.';
COMMENT ON COLUMN process_runs.attempt IS 'Current retry attempt (0-based). Incremented on each retry.';
COMMENT ON COLUMN process_runs.max_attempts IS 'Maximum retry attempts allowed. Must be > 0.';
COMMENT ON COLUMN process_runs.started_at IS 'When execution began. NULL if still pending.';
COMMENT ON COLUMN process_runs.ended_at IS
    'When execution completed/failed/skipped. NULL while pending or running. '
    'NULL + old started_at = abandoned/crashed run.';
COMMENT ON COLUMN process_runs.metadata IS
    'Kind-specific fields not warranting promotion. '
    'crawl: { source_url, item_count, http_status }. '
    'agent_schedule: { produced_task_ids, missed_run_policy }. '
    'Promote to a column when a field needs WHERE/JOIN/GROUP BY ≥ 3 times in queries.';

CREATE INDEX idx_process_runs_kind_status ON process_runs (kind, status);
CREATE INDEX idx_process_runs_created_at ON process_runs (created_at DESC);
CREATE INDEX idx_process_runs_name ON process_runs (kind, name, started_at DESC);
CREATE INDEX idx_process_runs_retry ON process_runs (created_at) WHERE status = 'failed';
CREATE INDEX idx_process_runs_content_id ON process_runs (content_id) WHERE content_id IS NOT NULL;
CREATE INDEX idx_process_runs_dedup ON process_runs (kind, name, content_id, status) WHERE status IN ('pending', 'running');
CREATE INDEX idx_process_runs_completed ON process_runs (kind, name, ended_at DESC) WHERE status = 'completed';
CREATE INDEX idx_process_runs_subsystem_recent ON process_runs (subsystem, status, started_at DESC)
    WHERE subsystem IS NOT NULL;

-- ============================================================
-- Todos (personal GTD work list — NOT inter-agent tasks)
--
-- Named todos (not tasks) to free the bare word "task" for the inter-agent
-- coordination entity (tasks table).
-- Vocabulary discipline: "task" = agent-to-agent work unit, "todo" = personal GTD item.
-- ============================================================

CREATE TABLE todos (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title             TEXT NOT NULL,
    state             todo_state NOT NULL DEFAULT 'todo',
    due               DATE,
    project_id        UUID REFERENCES projects(id) ON DELETE SET NULL,
    completed_at      TIMESTAMPTZ,
    energy            TEXT CHECK (energy IN ('high', 'medium', 'low')),
    priority          TEXT CHECK (priority IN ('high', 'medium', 'low')),
    recur_interval    INT,
    recur_unit        TEXT CHECK (recur_unit IN ('days', 'weeks', 'months', 'years')),
    description       TEXT NOT NULL DEFAULT '',
    created_by        TEXT NOT NULL DEFAULT 'human' REFERENCES agents(name) ON DELETE RESTRICT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_todo_title_not_blank
        CHECK (btrim(title) <> ''),
    CONSTRAINT chk_todo_completed_at_consistency
        CHECK ((state = 'done' AND completed_at IS NOT NULL)
            OR (state <> 'done' AND completed_at IS NULL)),
    CONSTRAINT chk_todo_recurrence_pair
        CHECK ((recur_interval IS NULL AND recur_unit IS NULL)
            OR (recur_interval IS NOT NULL AND recur_unit IS NOT NULL AND recur_interval > 0))
);

COMMENT ON TABLE todos IS
    'Personal GTD work items. Distinct from the tasks coordination entity (inter-agent work units). '
    'Lifecycle: inbox (captured, not clarified) → todo (clarified, actionable) → in_progress → done. '
    'someday = interested but not now, reviewed in Weekly Review. '
    'inbox items lack project/due/priority — clarification promotes them to todo.';

COMMENT ON COLUMN todos.state IS
    'GTD lifecycle: inbox → todo | someday. todo → in_progress → done. '
    'inbox = captured but not clarified (missing project/due/priority). '
    'someday = interested but not acting now — reviewed periodically. '
    'archived | dismissed = terminal self-close states set by an agent via the '
    'resolve_task MCP readback loop on a todo it created (archived = filed away, '
    'dismissed = won''t do); like every non-done state they keep completed_at '
    'NULL, enforced by chk_todo_completed_at_consistency.';
COMMENT ON COLUMN todos.title IS 'Short summary of the todo. Non-blank (chk_todo_title_not_blank).';
COMMENT ON COLUMN todos.due IS 'Due date. NULL = no deadline.';
COMMENT ON COLUMN todos.project_id IS 'Optional parent project. SET NULL on project deletion — the todo survives unclassified.';
COMMENT ON COLUMN todos.completed_at IS 'When the todo was completed. NULL unless state=done, enforced by chk_todo_completed_at_consistency.';
COMMENT ON COLUMN todos.energy IS 'Required energy level for GTD engage-by-energy. NULL = not set.';
COMMENT ON COLUMN todos.priority IS 'Todo priority for GTD engage-by-priority. NULL = not set.';
COMMENT ON COLUMN todos.recur_interval IS 'Recurrence frequency count. NULL = non-recurring. Paired with recur_unit by chk_todo_recurrence_pair.';
COMMENT ON COLUMN todos.recur_unit IS 'Recurrence unit. NULL = non-recurring todo.';
COMMENT ON COLUMN todos.description IS 'Free-text detail. Empty string = no detail.';
COMMENT ON COLUMN todos.created_by IS
    'Which agent created or imported this todo into the system. '
    'FK to agents. Default human. '
    'Examples: human (manual or synced from external tool), planner (morning briefing).';
COMMENT ON COLUMN todos.created_at IS 'Row insertion timestamp.';
COMMENT ON COLUMN todos.updated_at IS 'Set explicitly by application in UPDATE queries. No trigger — application-managed.';

CREATE INDEX idx_todos_active ON todos (state) WHERE state IN ('todo', 'in_progress');
CREATE INDEX idx_todos_inbox ON todos (created_at DESC) WHERE state = 'inbox';
CREATE INDEX idx_todos_project ON todos (project_id) WHERE project_id IS NOT NULL;
CREATE INDEX idx_todos_completed ON todos (completed_at) WHERE state = 'done';
CREATE INDEX idx_todos_created_by ON todos (created_by, created_at DESC);

CREATE TABLE daily_plan_items (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_date     DATE NOT NULL,
    todo_id       UUID NOT NULL REFERENCES todos(id) ON DELETE CASCADE,
    selected_by   TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    position      INT NOT NULL DEFAULT 0,
    reason        TEXT,
    status        TEXT NOT NULL DEFAULT 'planned'
                  CHECK (status IN ('planned', 'done', 'deferred', 'dropped')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (plan_date, todo_id)
);

CREATE INDEX idx_daily_plan_items_date
    ON daily_plan_items (plan_date DESC, position);

CREATE INDEX idx_daily_plan_items_active
    ON daily_plan_items (plan_date DESC)
    WHERE status = 'planned';

CREATE INDEX idx_daily_plan_items_todo
    ON daily_plan_items (todo_id);

-- Position uniqueness applies to the active plan only. A day's 'planned' rows
-- must each occupy a distinct slot; terminal rows (done/deferred/dropped) are
-- frozen history that keep their original position, so a re-plan may reuse a
-- terminal row's slot. Scoping the constraint to status='planned' permits that.
CREATE UNIQUE INDEX idx_daily_plan_items_position
    ON daily_plan_items (plan_date, position)
    WHERE status = 'planned';

COMMENT ON TABLE daily_plan_items IS
    'Daily commitment records. Each row represents a todo item selected for '
    'a specific day''s plan. Lifecycle: planned → done | deferred | dropped. '
    'Re-plan replaces only the day''s ''planned'' rows; terminal rows '
    '(done/deferred/dropped) are preserved as history and cannot be re-planned '
    '(re-sending one is rejected). Position is unique among ''planned'' rows only.';

COMMENT ON COLUMN daily_plan_items.plan_date IS
    'The date this todo was planned for. Combined with todo_id forms a unique constraint — '
    'one todo can appear at most once per day.';
COMMENT ON COLUMN daily_plan_items.todo_id IS
    'The todo committed to. CASCADE on delete — if the todo is removed, the plan item goes too.';
COMMENT ON COLUMN daily_plan_items.selected_by IS
    'Which agent added this item to the plan. Typically planner (morning briefing, cron auto-populate) '
    'or human (manual selection via MCP tool).';
COMMENT ON COLUMN daily_plan_items.position IS
    'Ordering within a day''s plan. 0-based. Semantic: first item = highest priority for today.';
COMMENT ON COLUMN daily_plan_items.reason IS
    'Optional rationale for selecting this todo today. NULL = no specific reason recorded.';
COMMENT ON COLUMN daily_plan_items.status IS
    'Lifecycle state. planned = committed for today. '
    'done = completed within this day (independent of todos.state for recurring todos). '
    'deferred = not done today, carry-over candidate for future planning. '
    'dropped = explicitly removed from plan, no intent to carry over.';
COMMENT ON COLUMN daily_plan_items.updated_at IS
    'Application-managed. Tracks when status last changed. '
    'Critical for Weekly Review analysis and cron debug.';

-- ============================================================
-- Todo skips
-- ============================================================

CREATE TABLE todo_skips (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    todo_id      UUID NOT NULL REFERENCES todos(id) ON DELETE CASCADE,
    original_due DATE NOT NULL,
    skipped_date DATE NOT NULL,
    reason       TEXT NOT NULL DEFAULT 'auto-expired'
        CHECK (reason IN ('auto-expired', 'manual')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(todo_id, skipped_date)
);

COMMENT ON TABLE todo_skips IS
    'Per-occurrence skip history for recurring todo items. RETENTION: 1 year. '
    'Scope discipline vs daily_plan_items.status=''dropped'': todo_skips records '
    'that a RECURRING todo''s scheduled occurrence did not happen; daily_plan_items '
    '(status=dropped) records that a planner explicitly removed the todo from a '
    'specific day''s plan. Both can apply to the same (todo_id, date) in theory — '
    'by convention, the cron-driven skip detection runs AFTER daily_plan reconciliation '
    'each night, so a todo the user dropped from today''s plan does NOT also get a '
    'todo_skips row. Writers MUST preserve this order: daily_plan_items(dropped) first, '
    'todo_skips after. Analytics that count "missed occurrences" should SELECT only '
    'todo_skips; plan adherence metrics use daily_plan_items.';
COMMENT ON COLUMN todo_skips.todo_id IS 'Which recurring todo was skipped. CASCADE — skips die with their todo.';
COMMENT ON COLUMN todo_skips.original_due IS 'Due date when skip was detected by cron.';
COMMENT ON COLUMN todo_skips.skipped_date IS 'The occurrence date that was missed.';
COMMENT ON COLUMN todo_skips.reason IS 'auto-expired (cron detected overdue) or manual (user skipped).';
COMMENT ON COLUMN todo_skips.created_at IS 'Row insertion timestamp.';

-- Structural invariant: a todo_skips row and a daily_plan_items(status='dropped')
-- row for the same (todo_id, date) MUST NOT coexist. Enforces the
-- "missed-occurrence vs dropped-plan" scope split — analytics count
-- todo_skips for missed occurrences, daily_plan_items.status='dropped' for
-- plan adherence. Bidirectional: rejects either (a) inserting a todo_skip
-- when drop already exists, or (b) updating a daily_plan_item to 'dropped'
-- when a skip already exists.
CREATE OR REPLACE FUNCTION enforce_todo_skip_not_already_dropped() RETURNS TRIGGER AS $$
BEGIN
    IF TG_TABLE_NAME = 'todo_skips' THEN
        IF EXISTS (
            SELECT 1 FROM daily_plan_items
            WHERE todo_id = NEW.todo_id
              AND plan_date = NEW.skipped_date
              AND status = 'dropped'
        ) THEN
            RAISE EXCEPTION 'todo_skips: (todo_id=%, skipped_date=%) already recorded as dropped in daily_plan_items; cannot also record as skipped',
                NEW.todo_id, NEW.skipped_date;
        END IF;
    ELSIF TG_TABLE_NAME = 'daily_plan_items' THEN
        IF NEW.status <> 'dropped' THEN
            RETURN NEW;
        END IF;
        IF EXISTS (
            SELECT 1 FROM todo_skips
            WHERE todo_id = NEW.todo_id
              AND skipped_date = NEW.plan_date
        ) THEN
            RAISE EXCEPTION 'daily_plan_items: (todo_id=%, plan_date=%) already recorded as a todo_skip; cannot also mark as dropped',
                NEW.todo_id, NEW.plan_date;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_todo_skips_not_already_dropped
    BEFORE INSERT ON todo_skips
    FOR EACH ROW EXECUTE FUNCTION enforce_todo_skip_not_already_dropped();
COMMENT ON TRIGGER trg_todo_skips_not_already_dropped ON todo_skips
    IS 'Rejects INSERT when daily_plan_items already recorded the same (todo_id, date) as status=''dropped''.';

CREATE TRIGGER trg_daily_plan_items_not_already_skipped
    BEFORE INSERT OR UPDATE OF status ON daily_plan_items
    FOR EACH ROW EXECUTE FUNCTION enforce_todo_skip_not_already_dropped();
COMMENT ON TRIGGER trg_daily_plan_items_not_already_skipped ON daily_plan_items
    IS 'Rejects setting status=''dropped'' when todo_skips already has a row for the same (todo_id, date). Paired with trg_todo_skips_not_already_dropped for bidirectional enforcement.';

-- ============================================================
-- Activity events
--
-- activity_events is the canonical audit log of internal entity state
-- changes, written by AFTER triggers on covered tables. Application code
-- MUST NOT bypass these triggers — the table is the single source of
-- truth for "what happened to which entity when".
-- ============================================================

CREATE TABLE activity_events (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type   TEXT NOT NULL CHECK (entity_type IN (
                      'todo', 'goal', 'milestone', 'project', 'content',
                      'note', 'learning_attempt', 'learning_hypothesis',
                      'learning_plan_entry', 'learning_session'
                  )),
    entity_id     UUID NOT NULL,
    entity_title  TEXT,
    entity_slug   TEXT,
    change_kind   TEXT NOT NULL CHECK (change_kind IN (
                      'created', 'updated', 'state_changed', 'published',
                      'completed', 'archived'
                  )),
    project_id    UUID REFERENCES projects(id) ON DELETE SET NULL,
    actor         TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload       JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE activity_events IS
    'Canonical audit log of internal entity state changes. Written by AFTER triggers '
    'on covered tables. Application code MUST NOT INSERT into this table directly — '
    'the trigger path is the only legitimate writer. RETENTION: indefinite.';
COMMENT ON COLUMN activity_events.entity_type IS
    'Which entity domain this event describes. Closed set via CHECK. Used in conjunction '
    'with entity_id to identify the specific row that changed.';
COMMENT ON COLUMN activity_events.entity_id IS
    'UUID of the changed row. Polymorphic — FK integrity is not enforced (would require '
    'separate FK per entity_type). entity_title and entity_slug carry the write-time '
    'snapshot so consumers (morning_context, weekly_summary, session_delta) do not '
    'need to JOIN live entity tables; a hard-deleted entity_id still has a usable '
    'historical record.';
COMMENT ON COLUMN activity_events.entity_title IS
    'Human-readable title of the entity AT THE TIME of the event. NULL when the '
    'entity has no natural title (learning_session) or the trigger cannot resolve '
    'one. Survives hard-delete of the referenced entity.';
COMMENT ON COLUMN activity_events.entity_slug IS
    'Slug of the entity AT THE TIME of the event, for slug-addressable types '
    '(content, bookmark, note, project). NULL otherwise.';
COMMENT ON COLUMN activity_events.change_kind IS
    'Closed set of mutation kinds. created = INSERT. state_changed = enum/status transition. '
    'completed/published/archived = specific terminal transitions worth distinguishing. '
    'updated = generic field change.';
COMMENT ON COLUMN activity_events.project_id IS
    'Optional project association for project-scoped activity feeds. SET NULL on project deletion.';
COMMENT ON COLUMN activity_events.actor IS
    'Agent that caused the change. RESTRICT on agent deletion — historical audit must not dangle.';
COMMENT ON COLUMN activity_events.occurred_at IS 'When the change happened. DEFAULT now() since triggers fire synchronously.';
COMMENT ON COLUMN activity_events.payload IS
    'Change-specific structured data: before/after values, transition reasons, related entity IDs. '
    'Schema varies by (entity_type, change_kind) pair.';

CREATE INDEX idx_activity_events_entity ON activity_events (entity_type, entity_id, occurred_at DESC);
CREATE INDEX idx_activity_events_occurred_at ON activity_events (occurred_at DESC);
CREATE INDEX idx_activity_events_project ON activity_events (project_id, occurred_at DESC) WHERE project_id IS NOT NULL;
CREATE INDEX idx_activity_events_kind ON activity_events (entity_type, change_kind, occurred_at DESC);
CREATE INDEX idx_activity_events_actor ON activity_events (actor, occurred_at DESC);

-- ============================================================
-- Project aliases
-- ============================================================

CREATE TABLE project_aliases (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alias      TEXT NOT NULL,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    source     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE project_aliases IS 'Maps variant project names to canonical project. Used by activity event and MCP search to resolve fuzzy project references.';
COMMENT ON COLUMN project_aliases.alias IS 'Variant name (e.g. repo name, external title variant). Case-insensitive unique — "Koopa0.dev" and "koopa0.dev" are the same alias.';
COMMENT ON COLUMN project_aliases.project_id IS 'References canonical project. CASCADE — aliases meaningless without project.';
COMMENT ON COLUMN project_aliases.source IS 'Where this alias was discovered (e.g. github, manual).';

-- Case-insensitive unique: prevents "Koopa0.dev" and "koopa0.dev" as separate aliases
CREATE UNIQUE INDEX idx_project_aliases_lower_alias ON project_aliases (LOWER(alias));

-- ============================================================
-- activity_events triggers — canonical audit log writers
--
-- Application code MUST set the actor identity for the current transaction via
--   SET LOCAL koopa.actor = '<agent_name>';
-- before any covered table mutation. The triggers read this via current_setting.
-- If unset, the actor defaults to 'system'.
--
-- The triggers are AFTER row triggers, so a successful mutation of a covered
-- table always produces exactly one activity_events row per covered transition.
-- The guarantee is scoped to covered-table mutations: the triggers fire on
-- INSERT/UPDATE/DELETE of the tables they are attached to. A direct
-- `INSERT INTO activity_events` fires no trigger and is accepted by the DB — it
-- is a convention violation (the application layer must never write audit rows
-- by hand), not something the schema blocks.
-- ============================================================

CREATE OR REPLACE FUNCTION current_actor() RETURNS TEXT AS $$
DECLARE
    actor TEXT;
BEGIN
    actor := current_setting('koopa.actor', true);
    IF actor IS NULL OR actor = '' THEN
        RETURN 'system';
    END IF;
    RETURN actor;
END;
$$ LANGUAGE plpgsql STABLE;

-- todos: INSERT + state changes
CREATE OR REPLACE FUNCTION audit_todos() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, project_id, actor, payload)
        VALUES ('todo', NEW.id, NEW.title, 'created', NEW.project_id, current_actor(),
                jsonb_build_object('state', NEW.state));
    ELSIF NEW.state IS DISTINCT FROM OLD.state THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, project_id, actor, payload)
        VALUES ('todo', NEW.id, NEW.title,
                CASE WHEN NEW.state = 'done' THEN 'completed' ELSE 'state_changed' END,
                NEW.project_id, current_actor(),
                jsonb_build_object('from', OLD.state, 'to', NEW.state));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_todos_audit
    AFTER INSERT OR UPDATE OF state ON todos
    FOR EACH ROW EXECUTE FUNCTION audit_todos();

-- goals: INSERT + status changes
CREATE OR REPLACE FUNCTION audit_goals() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
        VALUES ('goal', NEW.id, NEW.title, 'created', current_actor(),
                jsonb_build_object('status', NEW.status));
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
        VALUES ('goal', NEW.id, NEW.title, 'state_changed', current_actor(),
                jsonb_build_object('from', OLD.status, 'to', NEW.status));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_goals_audit
    AFTER INSERT OR UPDATE OF status ON goals
    FOR EACH ROW EXECUTE FUNCTION audit_goals();

-- milestones: INSERT + completion transitions
CREATE OR REPLACE FUNCTION audit_milestones() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
        VALUES ('milestone', NEW.id, NEW.title, 'created', current_actor(),
                jsonb_build_object('goal_id', NEW.goal_id));
    ELSIF OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
        VALUES ('milestone', NEW.id, NEW.title, 'completed', current_actor(),
                jsonb_build_object('goal_id', NEW.goal_id, 'completed_at', NEW.completed_at));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_milestones_audit
    AFTER INSERT OR UPDATE OF completed_at ON milestones
    FOR EACH ROW EXECUTE FUNCTION audit_milestones();

-- projects: INSERT + status changes
CREATE OR REPLACE FUNCTION audit_projects() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, project_id, actor, payload)
        VALUES ('project', NEW.id, NEW.title, NEW.slug, 'created', NEW.id, current_actor(),
                jsonb_build_object('status', NEW.status));
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, project_id, actor, payload)
        VALUES ('project', NEW.id, NEW.title, NEW.slug,
                CASE
                    WHEN NEW.status = 'completed' THEN 'completed'
                    WHEN NEW.status = 'archived'  THEN 'archived'
                    ELSE 'state_changed'
                END,
                NEW.id, current_actor(),
                jsonb_build_object('from', OLD.status, 'to', NEW.status));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_projects_audit
    AFTER INSERT OR UPDATE OF status ON projects
    FOR EACH ROW EXECUTE FUNCTION audit_projects();

-- contents: INSERT + status changes (especially → published)
CREATE OR REPLACE FUNCTION audit_contents() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, project_id, actor, payload)
        VALUES ('content', NEW.id, NEW.title, NEW.slug, 'created', NEW.project_id, current_actor(),
                jsonb_build_object('status', NEW.status, 'type', NEW.type));
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, project_id, actor, payload)
        VALUES ('content', NEW.id, NEW.title, NEW.slug,
                CASE
                    WHEN NEW.status = 'published' THEN 'published'
                    WHEN NEW.status = 'archived'  THEN 'archived'
                    ELSE 'state_changed'
                END,
                NEW.project_id, current_actor(),
                jsonb_build_object('from', OLD.status, 'to', NEW.status));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_contents_audit
    AFTER INSERT OR UPDATE OF status ON contents
    FOR EACH ROW EXECUTE FUNCTION audit_contents();

-- Note: the coupling between projects.status = 'archived' and its
-- project_profile demotion (is_public = false) is enforced in
-- internal/project.Store.UpdateStatus, not in a trigger — per the
-- trigger policy that keeps cross-aggregate side effects out of the DB.


-- ============================================================
-- Readings — literature shelf + reading diary
--
-- One book per readings row; one dated diary entry per reading_reflections
-- row. Deeply private: no agent surface (no MCP, not in the search_knowledge
-- corpus), admin HTTP only. No audit triggers (every write is the single
-- human admin behind adminMid — an actor trail would record a constant) and
-- no rating column, ever — reflections are the only evaluation (owner decision).
-- ============================================================

CREATE TABLE readings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       TEXT NOT NULL,
    author      TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'want_to_read'
        CHECK (status IN ('want_to_read', 'reading', 'finished', 'abandoned')),
    started_on  DATE,
    finished_on DATE,
    is_public   BOOLEAN NOT NULL DEFAULT false,
    goal_id     UUID REFERENCES goals(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_reading_title_not_blank
        CHECK (btrim(title) <> '')
);

COMMENT ON TABLE readings IS
    'Literature reading shelf — one row per book, Koopa-private. Evaluation '
    'happens only through reading_reflections (dated diary entries); there is '
    'intentionally no rating column. Agent surface is read-only: list_readings '
    'and get_reading expose the shelf over MCP, but no agent write path exists. '
    'Not in the search_knowledge corpus; mutations are admin HTTP only.';
COMMENT ON COLUMN readings.title IS
    'Book title as Koopa records it. Required, never blank (chk_reading_title_not_blank).';
COMMENT ON COLUMN readings.author IS
    'Author name(s), free text. Empty string when not recorded — "unknown author" '
    'carries no distinct meaning from "not entered", so NOT NULL DEFAULT '''' '
    'instead of nullable.';
COMMENT ON COLUMN readings.status IS
    'Shelf state: want_to_read → reading → finished | abandoned. The CHECK '
    'closes the value set; transitions are NOT schema-enforced — any change is '
    'allowed (abandoned books get picked back up, finished books get re-read). '
    'Set by the admin HTTP handler, never by trigger.';
COMMENT ON COLUMN readings.started_on IS
    'Date Koopa started reading. NULL while the book sits on the want-to-read '
    'shelf or when the start date was never recorded.';
COMMENT ON COLUMN readings.finished_on IS
    'Date Koopa finished (or gave up on) the book. NULL until the reading '
    'concludes. The handler auto-stamps today on a transition to finished when '
    'no explicit date is supplied.';
COMMENT ON COLUMN readings.is_public IS
    'Reserved for a future public shelf. Default false; nothing public-facing '
    'reads this yet — flipping it has no effect until a public surface exists.';
COMMENT ON COLUMN readings.goal_id IS
    'Optional link to the goal this book serves (e.g. reading toward a learning '
    'objective). NULL when the book stands on its own — most books do, so '
    'nullable rather than required. ON DELETE SET NULL: deleting a goal unlinks '
    'the book, never deletes it. Inert until goals exist; set via admin.';
COMMENT ON COLUMN readings.created_at IS
    'Row creation time. Set by the database, never updated.';
COMMENT ON COLUMN readings.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_readings_status ON readings(status);
-- Partial: goal_id is NULL for most books (they stand on their own), so the
-- index covers only the linked minority. Backs the ON DELETE SET NULL parent
-- lookup when a goal is deleted (mirrors idx_projects_goal_id).
CREATE INDEX idx_readings_goal_id ON readings(goal_id) WHERE goal_id IS NOT NULL;

CREATE TABLE reading_reflections (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reading_id UUID NOT NULL REFERENCES readings(id) ON DELETE CASCADE,
    entry_date DATE NOT NULL DEFAULT CURRENT_DATE,
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_reading_reflection_body_not_blank
        CHECK (btrim(body) <> '')
);

COMMENT ON TABLE reading_reflections IS
    'Reading diary — dated entries under one book, shown as a time-ordered '
    'thread (entry_date, then created_at) on the book page. Many per book. '
    'Private like readings: no agent surface, no search corpus, admin HTTP only.';
COMMENT ON COLUMN reading_reflections.reading_id IS
    'The book this entry belongs to. ON DELETE CASCADE — deleting a book '
    'deletes its entire diary; the entries have no meaning without the book.';
COMMENT ON COLUMN reading_reflections.entry_date IS
    'The diary date the entry belongs to — the day of reading, not necessarily '
    'the day it was typed in. Defaults to the current date; the handler applies '
    'the same default when the field is omitted.';
COMMENT ON COLUMN reading_reflections.body IS
    'The diary entry text. Required, never blank '
    '(chk_reading_reflection_body_not_blank). Free-form prose; newlines allowed.';
COMMENT ON COLUMN reading_reflections.created_at IS
    'Row creation time. Tiebreak for thread ordering when two entries share an '
    'entry_date.';
COMMENT ON COLUMN reading_reflections.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_reading_reflections_thread
    ON reading_reflections(reading_id, entry_date, created_at);


-- ============================================================
-- Songs — ヨルシカ song shelf + reflection diary
--
-- Mirrors the readings/reading_reflections pattern: one song per row, many
-- dated reflections threaded under it. Same privacy posture (no agent surface,
-- no search corpus, admin HTTP only) and no rating/progress column. The
-- distinct dimension is the Japanese-study reference layer (lyrics / owner
-- translation / vocabulary) — all owner-filled, never generated. album is a
-- free-text grouping label; there is no album entity and no narrative relation
-- (v1).
-- ============================================================

CREATE TABLE songs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title_ja    TEXT NOT NULL,
    album       TEXT NOT NULL DEFAULT '',
    lyrics_ja   TEXT NOT NULL DEFAULT '',
    translation TEXT NOT NULL DEFAULT '',
    vocabulary  TEXT NOT NULL DEFAULT '',
    is_public   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_song_title_ja_not_blank
        CHECK (btrim(title_ja) <> '')
);

COMMENT ON TABLE songs IS
    'ヨルシカ song shelf — one row per song, Koopa-private. Reflections live in '
    'song_reflections (dated thread). No rating column; no agent surface (no '
    'MCP, not in the search_knowledge corpus), admin HTTP only.';
COMMENT ON COLUMN songs.title_ja IS
    'Japanese song title (original). Required, never blank (chk_song_title_ja_not_blank).';
COMMENT ON COLUMN songs.album IS
    'Album name as a free-text grouping label. No album entity, no narrative '
    'relation (v1). Empty string when not recorded.';
COMMENT ON COLUMN songs.lyrics_ja IS
    'Japanese lyrics. Owner-filled for study; never generated. Empty until entered.';
COMMENT ON COLUMN songs.translation IS
    'Owner translation of the lyrics. Owner-filled; never generated. Empty until entered.';
COMMENT ON COLUMN songs.vocabulary IS
    'Vocabulary notes for Japanese study (free-form). Owner-filled; never '
    'generated. Empty until entered.';
COMMENT ON COLUMN songs.is_public IS
    'Reserved for a future public surface. Default false; nothing public-facing '
    'reads this yet.';
COMMENT ON COLUMN songs.created_at IS
    'Row creation time. Set by the database, never updated.';
COMMENT ON COLUMN songs.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

CREATE TABLE song_reflections (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    song_id    UUID NOT NULL REFERENCES songs(id) ON DELETE CASCADE,
    entry_date DATE NOT NULL DEFAULT CURRENT_DATE,
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_song_reflection_body_not_blank
        CHECK (btrim(body) <> '')
);

COMMENT ON TABLE song_reflections IS
    'Song reflection diary — dated entries under one song (理解/感受/意境), shown '
    'as a thread ordered by (entry_date, created_at). Many per song. Private '
    'like songs: no agent surface, no search corpus, admin HTTP only.';
COMMENT ON COLUMN song_reflections.song_id IS
    'The song this entry belongs to. ON DELETE CASCADE — deleting a song deletes '
    'its entire reflection thread; the entries have no meaning without the song.';
COMMENT ON COLUMN song_reflections.entry_date IS
    'The reflection date — the day of listening/understanding, not necessarily '
    'the typing date. Defaults to the current date; the handler applies the same '
    'default when omitted.';
COMMENT ON COLUMN song_reflections.body IS
    'The reflection text. Required, never blank (chk_song_reflection_body_not_blank). '
    'Free-form prose; newlines allowed.';
COMMENT ON COLUMN song_reflections.created_at IS
    'Row creation time. Tiebreak for thread ordering when two entries share an entry_date.';
COMMENT ON COLUMN song_reflections.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_song_reflections_thread
    ON song_reflections(song_id, entry_date, created_at);
