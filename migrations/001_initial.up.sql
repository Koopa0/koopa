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
    'not_started', 'in_progress', 'done', 'abandoned', 'on_hold'
);

CREATE TYPE project_status AS ENUM (
    'planned', 'in_progress', 'on_hold', 'completed', 'maintained', 'archived'
);

CREATE TYPE todo_state AS ENUM (
    'inbox', 'todo', 'in_progress', 'done', 'someday'
);

CREATE TYPE agent_status AS ENUM ('active', 'retired');

CREATE TYPE agent_note_kind AS ENUM ('plan', 'context', 'reflection');

CREATE TYPE task_state AS ENUM (
    'submitted', 'working', 'completed', 'canceled', 'revision_requested'
);

CREATE TYPE message_role AS ENUM ('request', 'response');

CREATE TYPE hypothesis_state AS ENUM (
    'unverified', 'verified', 'invalidated', 'archived'
);

CREATE TYPE note_kind AS ENUM (
    'solve-note', 'concept-note', 'debug-postmortem',
    'decision-log', 'reading-note', 'musing'
);

CREATE TYPE note_maturity AS ENUM (
    'seed', 'stub', 'evergreen', 'needs_revision', 'archived'
);

CREATE TYPE concept_kind AS ENUM (
    'pattern', 'skill', 'principle'
);

-- ============================================================
-- Identity model: agents (registry projection)
--
-- Source of truth lives in Go: internal/agent/registry.go::BuiltinAgents().
-- This table is a DB projection of that registry — rows are upserted at
-- application startup by internal/agent/sync.go::SyncToTable. Capability
-- flags are intentionally absent: authorization is enforced in Go via the
-- agent.Authorized compile-time wrapper type, not by DB columns.
--
-- The table exists so that coordination entities (tasks, agent_notes,
-- learning_hypotheses, bookmarks, etc.) can maintain referential integrity to a
-- known agent identity, and so that retiring an agent leaves an auditable trace
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
        CHECK (platform IN ('claude-cowork', 'claude-code', 'claude-web', 'human', 'system')),
    CONSTRAINT chk_agent_status_retired CHECK (
        (status = 'active'  AND retired_at IS NULL) OR
        (status = 'retired' AND retired_at IS NOT NULL)
    )
);

COMMENT ON TABLE agents IS 'DB projection of the Go BuiltinAgents() registry. Rows are upserted at startup by agent.SyncToTable. Capability flags are NOT stored here — authorization is enforced in Go via the agent.Authorized compile-time wrapper. FK targets for coordination references (tasks, agent_notes, learning_hypotheses) use ON DELETE RESTRICT so historical records cannot dangle. Removed registry entries transition to status=retired rather than being deleted.';
COMMENT ON COLUMN agents.name IS 'Unique agent identifier. Used as the caller identity (as: field) in MCP tool calls and as FK target for created_by / assignee / curated_by columns. Format: lowercase, must start with a letter, alphanumeric + hyphens.';
COMMENT ON COLUMN agents.display_name IS 'Human-readable label for admin UI and logs. Non-blank (chk_agent_display_name_not_blank).';
COMMENT ON COLUMN agents.platform IS 'Execution context. Closed set: claude-cowork, claude-code, claude-web, human, system (chk_agent_platform). The system value is reserved for the database-level fallback agent registered by BuiltinAgents — it attributes writes that bypass the Go actor middleware (pg_cron, manual psql ops, bug safety net). Routing decisions are driven by agent registry lookups, not this column.';
COMMENT ON COLUMN agents.description IS 'Short role description. Empty string = no description.';
COMMENT ON COLUMN agents.status IS 'active = currently present in BuiltinAgents(). retired = previously registered but no longer in the Go literal. chk_agent_status_retired ties retired_at to status=retired.';
COMMENT ON COLUMN agents.synced_at IS 'When this row was last reconciled with BuiltinAgents() by agent.SyncToTable. Updated on every startup sync.';
COMMENT ON COLUMN agents.retired_at IS 'When this agent was retired (removed from BuiltinAgents). NULL while status=active. Set by SyncToTable when the registry entry disappears.';
COMMENT ON COLUMN agents.created_at IS 'When the row was first upserted. Useful for onboarding audit.';

CREATE INDEX idx_agents_status ON agents (status);

-- ============================================================
-- Core domain: topics, tags, users
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
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_topic_name_not_blank
        CHECK (btrim(name) <> '')
);

COMMENT ON TABLE topics IS 'High-level knowledge domains (Go, AI, System Design). 10-20, manually managed. Used for content categorization and feed association.';
COMMENT ON COLUMN topics.slug IS 'URL-safe identifier (e.g. system-design). Used in feed_topics and content_topics junctions. Format: lowercase alphanumeric segments separated by single hyphens (chk_topic_slug_format) — no consecutive or trailing hyphens.';
COMMENT ON COLUMN topics.icon IS 'Optional emoji or icon identifier for UI display.';
COMMENT ON COLUMN topics.sort_order IS 'Priority tier for display ordering (lower = higher priority). Convention: sort_order is for tier-based UI placement that may have gaps; position is for sequence-based 0-based indexing within a parent. See top-of-file ordering convention block.';

CREATE TABLE tags (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    parent_id   UUID REFERENCES tags(id) ON DELETE SET NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_tag_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_tag_name_not_blank
        CHECK (btrim(name) <> '')
);

COMMENT ON TABLE tags IS 'Canonical tag registry. Fine-grained content-classification labels (two-pointers, error-handling). Resolved through tag_aliases pipeline. Mastery diagnosis and weakness tracking live in the concepts + learning_attempt_observations path — tags MUST NOT carry diagnostic semantics.';
COMMENT ON COLUMN tags.slug IS 'Canonical form (e.g. two-pointers, dp). Controlled vocabulary. Format: lowercase alphanumeric segments separated by single hyphens (chk_tag_slug_format). Namespaced slugs (weakness:xxx, improvement:xxx) were removed — weakness/mastery diagnosis runs through concepts + learning_attempt_observations.';
COMMENT ON COLUMN tags.parent_id IS 'Hierarchical parent tag. SET NULL on parent deletion — orphaned tags remain valid.';

CREATE INDEX idx_tags_parent ON tags(parent_id);

CREATE TABLE tag_aliases (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_tag      TEXT NOT NULL UNIQUE,
    tag_id       UUID REFERENCES tags(id) ON DELETE CASCADE,
    resolution_source TEXT NOT NULL DEFAULT 'admin'
                 CHECK (resolution_source IN ('auto-exact', 'auto-ci', 'auto-slug', 'admin', 'unmapped', 'rejected')),
    confirmed    BOOLEAN NOT NULL DEFAULT false,
    confirmed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_confirmed_pair
        CHECK ((confirmed = false AND confirmed_at IS NULL)
            OR (confirmed = true AND confirmed_at IS NOT NULL))
);

COMMENT ON TABLE tag_aliases IS 'Maps raw tag strings (from frontmatter/external) to canonical tags. Pipeline: raw_tag → lookup alias → resolve to tag_id.';
COMMENT ON COLUMN tag_aliases.raw_tag IS 'Original tag string as found in source (e.g. "golang", "JS", "dynamic-programming").';
COMMENT ON COLUMN tag_aliases.tag_id IS 'Resolved canonical tag. NULL for unmapped/rejected aliases.';
COMMENT ON COLUMN tag_aliases.resolution_source IS 'How the alias was resolved: auto-exact (exact match), auto-ci (case-insensitive), auto-slug (Slugify matched a canonical tag), admin (manually mapped by admin), unmapped (pending), rejected (admin declined).';
COMMENT ON COLUMN tag_aliases.confirmed IS 'Whether an admin has verified this mapping. Unconfirmed auto-matches may be wrong.';
COMMENT ON COLUMN tag_aliases.confirmed_at IS
    'When an admin confirmed this mapping. NULL iff confirmed = false '
    '(enforced by chk_confirmed_pair). Set together with confirmed = true.';

CREATE INDEX idx_tag_aliases_tag ON tag_aliases(tag_id);
CREATE INDEX idx_tag_aliases_confirmed ON tag_aliases(confirmed);
CREATE INDEX idx_tag_aliases_lower_raw_tag ON tag_aliases (LOWER(raw_tag));

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
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_area_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_area_name_not_blank
        CHECK (btrim(name) <> '')
);

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
    'Lifecycle: not_started → in_progress → done | abandoned | on_hold. '
    'on_hold = paused but not abandoned, can resume to in_progress. '
    'abandoned = terminal, will not pursue.';
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
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_project_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_project_title_not_blank
        CHECK (btrim(title) <> '')
);

COMMENT ON TABLE projects IS
    'PARA projects — planning aggregate, execution vehicles. Short-term efforts '
    'with clear outcomes. Projects and milestones are siblings under a goal: '
    'a project may advance a goal without mapping to a specific milestone. '
    'Public portfolio/case-study fields live in project_profiles (1:1).';
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
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_content_title_not_blank
        CHECK (btrim(title) <> ''),
    CONSTRAINT chk_content_publication
        CHECK ((status = 'published') = (published_at IS NOT NULL)),
    CONSTRAINT chk_content_public_requires_published
        CHECK (NOT is_public OR status = 'published')
);

COMMENT ON TABLE contents IS 'First-party publishable knowledge layer. Five content types (article, essay, build-log, til, digest) share one editorial lifecycle: draft → review → published → archived. The review state is a two-actor handoff signal — Claude marks a draft ready (submit_content_for_review), human admin publishes (publish_content). Notes (Zettelkasten) live in a separate notes table with maturity-based lifecycle — intentionally not mixed here. published status and published_at are tied by chk_content_publication; is_public requires published by chk_content_public_requires_published.';
COMMENT ON COLUMN contents.slug IS 'URL-safe identifier. Globally unique. Used in public URLs. Format: lowercase alphanumeric segments separated by single hyphens (chk_content_slug_format).';
COMMENT ON COLUMN contents.type IS 'Content format: article, essay, build-log, til, digest. All are public-facing first-party content going through the review lifecycle. Notes are NOT a content type — they live in the notes table.';
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
COMMENT ON COLUMN contents.published_at IS 'When content was published. NULL = not yet published.';
COMMENT ON COLUMN contents.search_vector IS
    'Generated tsvector for full-text search. Uses ''simple'' config (no stemming/language-specific '
    'tokenization) for multilingual safety. Weight A = title, C = body (first 10K chars). '
    'Semantic search via embedding compensates for tsvector recall limitations.';
COMMENT ON COLUMN contents.embedding IS 'pgvector embedding (1536d) from gemini-embedding-2-preview. See internal/embedder.Dimension — schema + Go must match exactly or pgvector rejects writes.';
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
-- Notes — Zettelkasten knowledge artifacts
--
-- Notes are Koopa-private knowledge artifacts with a maturity-based lifecycle
-- (seed → stub → evergreen → needs_revision → archived). Distinct from contents:
-- contents is publishable editorial writing (article/essay/til/build-log/digest)
-- going through draft → review → published. Notes never "publish" — they
-- mature in place. A learning_target may accumulate multiple notes of different
-- kinds over time (solve-note → concept-note → debug-postmortem); the M:N
-- attachment lives in learning_target_notes.
-- ============================================================

CREATE TABLE notes (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          TEXT NOT NULL UNIQUE,
    title         TEXT NOT NULL,
    body          TEXT NOT NULL DEFAULT '',
    kind          note_kind NOT NULL,
    maturity      note_maturity NOT NULL DEFAULT 'seed',
    created_by    TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    metadata      JSONB,
    ai_metadata   JSONB,
    embedding     vector(1536),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    search_vector TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(left(body, 10000), '')), 'C')
    ) STORED,

    CONSTRAINT chk_note_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_note_title_not_blank
        CHECK (btrim(title) <> '')
);

COMMENT ON TABLE notes IS
    'Zettelkasten knowledge artifacts — Koopa-private. Maturity-based lifecycle '
    '(seed → evergreen → archived), no publication state. Writeups for '
    'learning_targets attach via learning_target_notes. Public-facing content '
    '(articles, essays, etc.) lives in contents — a separate entity with its own '
    'draft → review → published editorial lifecycle. Publication state and '
    'maturity state are distinct state machines; notes and contents are kept '
    'as separate tables rather than single-table inheritance for this reason.';
COMMENT ON COLUMN notes.slug IS
    'URL-safe identifier. Globally unique within notes. Same format rules as contents.slug.';
COMMENT ON COLUMN notes.kind IS
    'Note sub-type. Six values: solve-note (LeetCode problem write-up), '
    'concept-note (cross-target pattern synthesis), debug-postmortem (production '
    'debug analysis), decision-log (technical decision record), reading-note '
    '(book chapter takeaway), musing (unstructured thought). Uses the note_kind '
    'ENUM, shared with learning_domains.canonical_writeup_kind.';
COMMENT ON COLUMN notes.maturity IS
    'Refinement stage: seed (just captured), stub (skeleton), evergreen (verified), '
    'needs_revision (known issue), archived (no longer maintained). Default seed '
    'on creation; transitioned by update_note_maturity MCP tool. archived is '
    'operationally terminal but not one-way — recovery via update_note_maturity '
    'is supported.';
COMMENT ON COLUMN notes.created_by IS
    'Which agent wrote this note. FK to agents. RESTRICT on agent deletion.';
COMMENT ON COLUMN notes.metadata IS
    'Free-form JSONB. If a field needs WHERE/JOIN/GROUP BY ≥ 3 times, promote to a column.';
COMMENT ON COLUMN notes.ai_metadata IS
    'AI pipeline metadata: {summary, keywords, extracted_concepts}. Set by background enrichment.';
COMMENT ON COLUMN notes.embedding IS
    'pgvector embedding (1536d) from gemini-embedding-2-preview. Used by search_knowledge.';
COMMENT ON COLUMN notes.search_vector IS
    'Generated tsvector for full-text search. Mirrors contents.search_vector shape.';
COMMENT ON COLUMN notes.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_notes_kind ON notes(kind);
CREATE INDEX idx_notes_maturity ON notes(maturity);
CREATE INDEX idx_notes_search ON notes USING GIN(search_vector);
CREATE INDEX idx_notes_created_at ON notes(created_at DESC);
CREATE INDEX idx_notes_embedding_hnsw ON notes USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- ============================================================
-- Junction: contents ↔ topics, contents ↔ tags
-- ============================================================

CREATE TABLE content_topics (
    content_id UUID NOT NULL REFERENCES contents(id) ON DELETE CASCADE,
    topic_id   UUID NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    PRIMARY KEY (content_id, topic_id)
);

COMMENT ON TABLE content_topics IS 'Junction: content ↔ topic. Many-to-many. Curated knowledge domain categories.';

CREATE INDEX idx_content_topics_topic_id ON content_topics(topic_id);

CREATE TABLE content_tags (
    content_id UUID NOT NULL REFERENCES contents(id) ON DELETE CASCADE,
    tag_id     UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (content_id, tag_id)
);

COMMENT ON COLUMN content_tags.tag_id IS 'References canonical tag. Distinct from content_topics: topics are curated categories, tags are raw labels resolved through the alias pipeline.';

CREATE INDEX idx_content_tags_tag_id ON content_tags(tag_id);

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
    relevance_score     DOUBLE PRECISION NOT NULL DEFAULT 0
                        CHECK (relevance_score >= 0 AND relevance_score <= 1),
    status              feed_entry_status NOT NULL DEFAULT 'unread',
    curated_content_id  UUID REFERENCES contents(id) ON DELETE SET NULL,
    collected_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    url_hash            TEXT NOT NULL,
    user_feedback       TEXT,
    feedback_at         TIMESTAMPTZ,
    feed_id             UUID REFERENCES feeds(id) ON DELETE SET NULL,
    published_at        TIMESTAMPTZ,

    CONSTRAINT chk_feedback_pair
        CHECK ((user_feedback IS NULL) = (feedback_at IS NULL)),
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
COMMENT ON COLUMN feed_entries.relevance_score IS 'Keyword-weighted relevance score in the closed interval [0.0, 1.0] — 0 = unscored/irrelevant, 1 = perfect match. Computed by the fetch pipeline. Display and filter thresholds (e.g. > 0.5) assume this scale.';
COMMENT ON COLUMN feed_entries.status IS 'Curation lifecycle: unread → read → curated | ignored.';
COMMENT ON COLUMN feed_entries.curated_content_id IS 'When curated into first-party content, references the contents row. SET NULL on content deletion. feed_entry → bookmark curation is not supported — use the bookmark UI directly.';
COMMENT ON COLUMN feed_entries.collected_at IS 'When the pipeline first fetched this entry.';
COMMENT ON COLUMN feed_entries.user_feedback IS 'Admin feedback on relevance scoring quality. Used to tune scoring.';
COMMENT ON COLUMN feed_entries.feedback_at IS 'When feedback was given. NULL = no feedback.';
COMMENT ON COLUMN feed_entries.published_at IS 'Original publication date from the feed. NULL if not provided.';

CREATE INDEX idx_feed_entries_status ON feed_entries(status);
CREATE INDEX idx_feed_entries_relevance ON feed_entries(relevance_score DESC);
CREATE UNIQUE INDEX idx_feed_entries_url_hash ON feed_entries (url_hash);
CREATE INDEX idx_feed_entries_feed_id ON feed_entries (feed_id) WHERE feed_id IS NOT NULL;
CREATE INDEX idx_feed_entries_collected_at ON feed_entries (collected_at DESC);
CREATE INDEX idx_feed_entries_unread_at ON feed_entries (collected_at DESC) WHERE status = 'unread';
CREATE INDEX idx_feed_entries_unread_relevance ON feed_entries (relevance_score DESC) WHERE status = 'unread';
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
    'someday = interested but not acting now — reviewed periodically.';
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
    'Examples: human (manual or synced from external tool), hq (morning briefing).';
COMMENT ON COLUMN todos.created_at IS 'Row insertion timestamp.';
COMMENT ON COLUMN todos.updated_at IS 'Set explicitly by application in UPDATE queries. No trigger — application-managed.';

CREATE INDEX idx_todos_active ON todos (state) WHERE state IN ('todo', 'in_progress');
CREATE INDEX idx_todos_inbox ON todos (created_at DESC) WHERE state = 'inbox';
CREATE INDEX idx_todos_project ON todos (project_id) WHERE project_id IS NOT NULL;
CREATE INDEX idx_todos_completed ON todos (completed_at) WHERE state = 'done';
CREATE INDEX idx_todos_created_by ON todos (created_by, created_at DESC);

-- ============================================================
-- Agent notes
-- An agent's internal narrative log (plan / context / reflection).
-- Self-directed, not inter-agent coordination.
-- ============================================================

CREATE TABLE agent_notes (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          agent_note_kind NOT NULL,
    created_by    TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    content       TEXT NOT NULL,
    metadata      JSONB,
    entry_date    DATE NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    search_vector TSVECTOR GENERATED ALWAYS AS (
        to_tsvector('simple', coalesce(content, ''))
    ) STORED
);

COMMENT ON TABLE agent_notes IS 'An agent''s internal narrative log — plans, context snapshots, reflections. Self-directed, not inter-agent coordination. Produced by a single agent across a session or day. RETENTION: indefinite.';
COMMENT ON COLUMN agent_notes.kind IS 'plan = daily plan. context = end-of-session state snapshot. reflection = retrospective review.';
COMMENT ON COLUMN agent_notes.created_by IS 'Which agent wrote this note. FK to agents.';
COMMENT ON COLUMN agent_notes.content IS 'Free-text body of the note. Markdown allowed.';
COMMENT ON COLUMN agent_notes.entry_date IS 'The logical date this note belongs to. May differ from created_at for backfilled notes.';
COMMENT ON COLUMN agent_notes.metadata IS
    'Structured metadata per kind. '
    'plan: {reasoning}. Daily todo selection is tracked in daily_plan_items, not here. '
    'context, reflection: no required metadata schema.';
COMMENT ON COLUMN agent_notes.created_at IS 'Row insertion timestamp.';
COMMENT ON COLUMN agent_notes.search_vector IS
    'Generated tsvector for full-text search over content. Uses ''simple'' '
    'config (no stemming, multilingual-safe — notes are written in both '
    'Chinese and English). GIN-indexed via idx_agent_notes_search. '
    'Mirrors contents.search_vector / notes.search_vector shape.';

CREATE INDEX idx_agent_notes_date ON agent_notes (entry_date DESC);
CREATE INDEX idx_agent_notes_kind ON agent_notes (entry_date, kind);
CREATE INDEX idx_agent_notes_search ON agent_notes USING GIN(search_vector);

CREATE TABLE daily_plan_items (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_date     DATE NOT NULL,
    todo_id       UUID NOT NULL REFERENCES todos(id) ON DELETE CASCADE,
    selected_by   TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    position      INT NOT NULL DEFAULT 0,
    reason        TEXT,
    agent_note_id UUID REFERENCES agent_notes(id) ON DELETE SET NULL,
    status        TEXT NOT NULL DEFAULT 'planned'
                  CHECK (status IN ('planned', 'done', 'deferred', 'dropped')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (plan_date, todo_id),
    UNIQUE (plan_date, position)
);

CREATE INDEX idx_daily_plan_items_date
    ON daily_plan_items (plan_date DESC, position);

CREATE INDEX idx_daily_plan_items_active
    ON daily_plan_items (plan_date DESC)
    WHERE status = 'planned';

CREATE INDEX idx_daily_plan_items_todo
    ON daily_plan_items (todo_id);
CREATE INDEX idx_daily_plan_items_agent_note
    ON daily_plan_items (agent_note_id) WHERE agent_note_id IS NOT NULL;

COMMENT ON TABLE daily_plan_items IS
    'Daily commitment records. Each row represents a todo item selected for '
    'a specific day''s plan. Lifecycle: planned → done | deferred | dropped. '
    'Re-plan uses INSERT ... ON CONFLICT (plan_date, todo_id) DO UPDATE SET status = ''planned''.';

COMMENT ON COLUMN daily_plan_items.plan_date IS
    'The date this todo was planned for. Combined with todo_id forms a unique constraint — '
    'one todo can appear at most once per day.';
COMMENT ON COLUMN daily_plan_items.todo_id IS
    'The todo committed to. CASCADE on delete — if the todo is removed, the plan item goes too.';
COMMENT ON COLUMN daily_plan_items.selected_by IS
    'Which agent added this item to the plan. Typically hq (morning briefing, cron auto-populate) '
    'or human (manual selection via MCP tool).';
COMMENT ON COLUMN daily_plan_items.position IS
    'Ordering within a day''s plan. 0-based. Semantic: first item = highest priority for today.';
COMMENT ON COLUMN daily_plan_items.agent_note_id IS
    'Optional link to the agent_notes(kind=''plan'') entry that drove this planning session. '
    'All items from the same planning session share the same agent_note_id. '
    'Enables "which reasoning led to these todo selections" queries. '
    'Symmetric with learning_sessions.agent_note_id — session produces the note, '
    'agent_note_id links back. SET NULL on note deletion. '
    'INVARIANT: the referenced agent_note MUST have kind=''plan''. Schema does not '
    'enforce this (no CHECK across rows) — writers are responsible. plan_day and '
    'morning_context MCP handlers must validate kind before insert; tests live in '
    'internal/mcp (agent_note kind binding integration).';
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

-- Structural invariant: daily_plan_items.agent_note_id, when set, must
-- reference an agent_notes row with kind='plan'. The FK alone does not
-- enforce kind binding; this trigger closes the gap so any path that writes
-- the column (existing MCP handler, future tools, manual repair) is checked
-- at the database boundary rather than at a single writer.
CREATE OR REPLACE FUNCTION enforce_daily_plan_agent_note_kind() RETURNS TRIGGER AS $$
DECLARE
    note_kind agent_note_kind;
BEGIN
    IF NEW.agent_note_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO note_kind FROM agent_notes WHERE id = NEW.agent_note_id;
    IF note_kind IS DISTINCT FROM 'plan' THEN
        RAISE EXCEPTION 'daily_plan_items.agent_note_id must reference an agent_notes row with kind=''plan'' (got kind=%)', note_kind;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_daily_plan_items_agent_note_kind
    BEFORE INSERT OR UPDATE OF agent_note_id ON daily_plan_items
    FOR EACH ROW EXECUTE FUNCTION enforce_daily_plan_agent_note_kind();
COMMENT ON TRIGGER trg_daily_plan_items_agent_note_kind ON daily_plan_items
    IS 'Rejects INSERT/UPDATE when agent_note_id points to an agent_notes row whose kind is not ''plan''.';

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
                      'todo', 'goal', 'milestone', 'project', 'content', 'bookmark',
                      'note', 'learning_attempt', 'task', 'learning_hypothesis',
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
-- Coordination layer: tasks + task_messages + artifacts
--
-- tasks         = inter-agent work unit with an explicit lifecycle
-- task_messages = ordered request/response conversation turns
-- artifacts     = structured deliverables produced by the assignee
-- ============================================================

CREATE TABLE tasks (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_by   TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    assignee     TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    title        TEXT NOT NULL,
    state        task_state NOT NULL DEFAULT 'submitted',
    deadline                TIMESTAMPTZ,
    priority                TEXT CHECK (priority IN ('high', 'medium', 'low')),
    submitted_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at             TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    canceled_at             TIMESTAMPTZ,
    revision_requested_at   TIMESTAMPTZ,
    metadata                JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT chk_task_title_not_blank
        CHECK (btrim(title) <> ''),
    CONSTRAINT chk_tasks_no_self_assignment
        CHECK (created_by <> assignee),
    CONSTRAINT chk_tasks_state_timestamps CHECK (
        (state = 'submitted'          AND accepted_at IS NULL     AND completed_at IS NULL     AND canceled_at IS NULL     AND revision_requested_at IS NULL) OR
        (state = 'working'            AND accepted_at IS NOT NULL AND completed_at IS NULL     AND canceled_at IS NULL     AND revision_requested_at IS NULL) OR
        (state = 'completed'          AND accepted_at IS NOT NULL AND completed_at IS NOT NULL AND canceled_at IS NULL     AND revision_requested_at IS NULL) OR
        (state = 'canceled'           AND canceled_at IS NOT NULL AND completed_at IS NULL                                AND revision_requested_at IS NULL) OR
        (state = 'revision_requested' AND accepted_at IS NOT NULL AND completed_at IS NOT NULL AND canceled_at IS NULL     AND revision_requested_at IS NOT NULL)
    )
);

COMMENT ON TABLE tasks IS
    'Inter-agent coordination work units. Distinct from personal GTD todos. '
    'One agent asks another to do work. Lifecycle: submitted → working → completed | canceled. '
    'Completed tasks can enter a revision cycle: completed → revision_requested → working → completed. '
    'chk_tasks_state_timestamps makes illegal (state, timestamp) combinations impossible. '
    'Conversation history lives in task_messages; structured deliverables live in artifacts. '
    'A completed task must have at least one response message and at least one artifact — '
    'enforced by trg_tasks_completion_requires_outputs.';
COMMENT ON COLUMN tasks.created_by IS 'Agent that submitted the task. FK to agents.';
COMMENT ON COLUMN tasks.assignee IS 'Agent expected to perform the work. FK to agents.';
COMMENT ON COLUMN tasks.title IS 'Short human-readable task label.';
COMMENT ON COLUMN tasks.state IS 'submitted = created, not yet accepted. working = assignee accepted, in flight. completed = response and artifact delivered. canceled = withdrawn before completion. revision_requested = human reviewer requested changes on a completed task.';
COMMENT ON COLUMN tasks.deadline IS 'When the task must be completed by. NULL = no deadline. Queryable routing signal for "tasks due soon" dashboards.';
COMMENT ON COLUMN tasks.priority IS 'Caller-declared priority (high | medium | low). NULL = unspecified. Queryable routing signal alongside deadline.';
COMMENT ON COLUMN tasks.submitted_at IS 'When the task was created. DEFAULT now().';
COMMENT ON COLUMN tasks.accepted_at IS 'When the assignee transitioned the task to working. NULL while state=submitted or for tasks canceled before acceptance.';
COMMENT ON COLUMN tasks.completed_at IS 'When the assignee delivered the final outputs. NULL unless state=completed or revision_requested. Cleared when re-entering working after revision.';
COMMENT ON COLUMN tasks.canceled_at IS 'When the task was canceled. NULL unless state=canceled. Mutually exclusive with completed_at.';
COMMENT ON COLUMN tasks.revision_requested_at IS 'When a human reviewer requested changes on a completed task. NULL unless state=revision_requested. Cleared when re-entering working after revision.';
COMMENT ON COLUMN tasks.metadata IS 'Non-routing task info: correlation keys, opaque payload hints. Promote a field to a column when WHERE/JOIN/GROUP BY usage exceeds 3 occurrences.';

CREATE INDEX idx_tasks_assignee_open
    ON tasks (assignee, submitted_at DESC)
    WHERE state IN ('submitted', 'working');

CREATE INDEX idx_tasks_created_by_open
    ON tasks (created_by, submitted_at DESC)
    WHERE state IN ('submitted', 'working');

CREATE INDEX idx_tasks_state ON tasks (state);

-- ============================================================
-- task_messages: request/response conversation turns
--
-- Parts are stored as a JSONB array of a2a.Part values in a2a-go's flattened
-- form: {"text": "..."} or {"data": {...}}. Hard size caps prevent unbounded
-- payloads — anything larger must be stored as an artifact.
-- ============================================================

CREATE TABLE task_messages (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id    UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    role       message_role NOT NULL,
    position   INTEGER NOT NULL,
    parts      JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (task_id, position),

    CONSTRAINT chk_task_messages_parts_count CHECK (
        jsonb_typeof(parts) = 'array' AND
        jsonb_array_length(parts) BETWEEN 1 AND 16
    ),
    CONSTRAINT chk_task_messages_parts_size CHECK (
        pg_column_size(parts) <= 32768
    )
);

COMMENT ON TABLE task_messages IS 'Ordered request/response conversation turns on a task. Parts column is a JSONB array of a2a.Part values (flattened form). Hard size caps (16 parts max, 32 KB total) are DB-enforced bloat prevention — anything larger belongs in artifacts, not messages.';
COMMENT ON COLUMN task_messages.task_id IS 'Parent task. CASCADE — messages die with their task.';
COMMENT ON COLUMN task_messages.role IS 'request = message from the task creator to the assignee. response = message from the assignee back to the task creator.';
COMMENT ON COLUMN task_messages.position IS 'Order within a task conversation, 0-based. UNIQUE(task_id, position) prevents duplicates and out-of-order inserts.';
COMMENT ON COLUMN task_messages.parts IS 'JSONB array of a2a.Part values in a2a-go''s flattened format. Each part is {"text": "..."} or {"data": {...}}. Serialized/deserialized by a2a-go — Go code never hand-rolls this shape.';
COMMENT ON COLUMN task_messages.created_at IS 'Row insertion timestamp.';

CREATE INDEX idx_task_messages_task ON task_messages (task_id, position);

-- ============================================================
-- artifacts: structured task deliverables
--
-- Looser size bounds than messages (32 parts max, 256 KB total). Anything
-- above 256 KB belongs in external object storage referenced by a part.
-- ============================================================

CREATE TABLE artifacts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id     UUID REFERENCES tasks(id) ON DELETE CASCADE,
    created_by  TEXT REFERENCES agents(name) ON DELETE RESTRICT,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    parts       JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_artifacts_parts_count CHECK (
        jsonb_typeof(parts) = 'array' AND
        jsonb_array_length(parts) BETWEEN 1 AND 32
    ),
    CONSTRAINT chk_artifacts_parts_size CHECK (
        pg_column_size(parts) <= 262144
    ),
    CONSTRAINT chk_artifacts_standalone_attribution CHECK (
        task_id IS NOT NULL OR created_by IS NOT NULL
    )
);

COMMENT ON TABLE artifacts IS 'Structured deliverables, optionally bound to a task. Task-bound artifacts are produced during task work; standalone artifacts are self-initiated by an agent. Size bounds (32 parts, 256 KB) are looser than task_messages bounds.';
COMMENT ON COLUMN artifacts.task_id IS 'Parent task. NULL for standalone (self-initiated) artifacts. CASCADE — task-bound artifacts die with their task.';
COMMENT ON COLUMN artifacts.created_by IS 'Agent that created this artifact. Required for standalone artifacts (task_id IS NULL). Optional for task-bound artifacts (attribution comes from the task).';
COMMENT ON COLUMN artifacts.name IS 'Short label identifying this artifact (e.g. "weekly-report", "architecture-diagram").';
COMMENT ON COLUMN artifacts.description IS 'Optional longer description. Empty string = no description.';
COMMENT ON COLUMN artifacts.parts IS 'JSONB array of a2a.Part values (same format as task_messages.parts). Stores the actual deliverable content.';
COMMENT ON COLUMN artifacts.created_at IS 'Row insertion timestamp.';

CREATE INDEX idx_artifacts_task ON artifacts (task_id, created_at);
CREATE INDEX idx_artifacts_created_by ON artifacts (created_by, created_at DESC)
    WHERE task_id IS NULL;

-- A completed task must have at least one response message and at least one artifact.
CREATE OR REPLACE FUNCTION enforce_task_completion_outputs() RETURNS TRIGGER AS $$
DECLARE
    response_count INT;
    artifact_count INT;
BEGIN
    IF NEW.state <> 'completed' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.state = 'completed' THEN
        RETURN NEW;
    END IF;
    SELECT COUNT(*) INTO response_count
        FROM task_messages WHERE task_id = NEW.id AND role = 'response';
    SELECT COUNT(*) INTO artifact_count
        FROM artifacts WHERE task_id = NEW.id;
    IF response_count = 0 OR artifact_count = 0 THEN
        RAISE EXCEPTION 'task % cannot transition to completed: requires at least one response message (have %) and one artifact (have %)',
            NEW.id, response_count, artifact_count;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tasks_completion_requires_outputs
    BEFORE INSERT OR UPDATE OF state ON tasks
    FOR EACH ROW EXECUTE FUNCTION enforce_task_completion_outputs();

-- ============================================================
-- Learning analytics: concepts, targets, sessions, attempts, observations.
-- review_cards is defined after learning_targets (FK target).
-- (learning_hypotheses is defined after this block because it FKs into
-- learning_attempts and learning_attempt_observations.)
-- ============================================================

-- ============================================================
-- Learning domains lookup
-- ============================================================

CREATE TABLE learning_domains (
    slug                   TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    active                 BOOLEAN NOT NULL DEFAULT true,
    canonical_writeup_kind note_kind,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_learning_domain_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_learning_domain_name_not_blank
        CHECK (btrim(name) <> '')
);

COMMENT ON TABLE learning_domains IS
    'Closed set of learning domains. FK target for concepts.domain, learning_targets.domain, '
    'learning_sessions.domain, and learning_plans.domain. Adding a domain requires INSERT here first.';
COMMENT ON COLUMN learning_domains.slug IS 'Unique domain identifier. Lowercase kebab-case.';
COMMENT ON COLUMN learning_domains.name IS 'Display name.';
COMMENT ON COLUMN learning_domains.active IS 'Whether new entities can reference this domain.';
COMMENT ON COLUMN learning_domains.canonical_writeup_kind IS
    'Which notes.kind serves as the canonical writeup for targets in this domain. '
    'E.g., leetcode domain canonical = solve-note; ddia-chapter canonical = reading-note. '
    'NULL = no canonical rule (caller must enumerate all attached notes). '
    'Used by read-side queries (learning_target_notes JOIN notes WHERE kind = '
    'learning_domains.canonical_writeup_kind ORDER BY updated_at DESC LIMIT 1) '
    'to pick the "primary" writeup for a target.';

-- Concepts: learning ontology, independent from tags. Tags handle content
-- classification; concepts handle mastery tracking and weakness diagnosis.

CREATE TABLE concepts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL,
    name        TEXT NOT NULL,
    domain      TEXT NOT NULL REFERENCES learning_domains(slug) ON DELETE RESTRICT,
    kind        concept_kind NOT NULL,
    parent_id   UUID REFERENCES concepts(id) ON DELETE SET NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_concept_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_concept_name_not_blank
        CHECK (btrim(name) <> '')
);

COMMENT ON TABLE concepts IS
    'Learning ontology — concepts, patterns, skills, and principles that can be '
    'learned, practiced, and diagnosed. Independent from tags (which handle content '
    'classification). Hierarchy via parent_id (typical: pattern contains skill, '
    'skill refines principle — but kind ordering is convention, not DDL-enforced). '
    'Mastery is a derived state computed from attempt_observations aggregation, '
    'not stored on this table.';
COMMENT ON COLUMN concepts.slug IS
    'URL-safe identifier. Case-insensitive uniqueness per domain enforced by idx_concepts_domain_slug. '
    'Convention: lowercase-kebab (e.g. binary-search, two-pointers, te-form).';
COMMENT ON COLUMN concepts.name IS
    'Human-readable display name (e.g. "Binary Search", "Te-form Conjugation").';
COMMENT ON COLUMN concepts.domain IS
    'Learning domain. FK to learning_domains. Same-domain invariant for parent_id is '
    'enforced by trg_concepts_parent_domain.';
COMMENT ON COLUMN concepts.kind IS
    'Concept classification. '
    'pattern: strategic framework (two-pointers, binary-search, sliding-window). '
    'skill: practicable ability (constraint-analysis, edge-case-handling). '
    'principle: theoretical foundation (amortized analysis, CAP theorem, N3 grammar).';
COMMENT ON COLUMN concepts.parent_id IS
    'Self-referencing hierarchy. SET NULL on parent deletion — children become roots. '
    'Acyclicity is enforced by trg_concepts_acyclicity. '
    'Same-domain invariant is enforced by trg_concepts_parent_domain. '
    'kind ordering (pattern > skill > principle) is CONVENTION, not DDL. A '
    'kind=''skill'' concept with a kind=''pattern'' parent is typical; the reverse '
    '(pattern with skill parent) is semantically odd but not rejected by the schema. '
    'Queries that assume a fixed kind root (e.g. "list top-level patterns for leetcode") '
    'MUST filter by kind AND parent_id IS NULL; do NOT rely on kind being monotonic up '
    'the hierarchy. Cross-kind edges are legitimate — e.g. the Japanese domain where a '
    'principle (N3 grammar) subsumes a skill (te-form conjugation).';
COMMENT ON COLUMN concepts.description IS
    'Optional elaboration. Empty string default — not nullable.';
COMMENT ON COLUMN concepts.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

CREATE UNIQUE INDEX idx_concepts_domain_slug ON concepts (domain, LOWER(slug));
CREATE INDEX idx_concepts_domain_kind ON concepts (domain, kind);
CREATE INDEX idx_concepts_parent ON concepts (parent_id) WHERE parent_id IS NOT NULL;

-- ============================================================
-- Content ↔ concept junction
--
-- Many-to-many: a contents row (article/essay/til/build-log/digest) maps to the
-- concepts it covers. Used by dashboards and search to find "all public writing
-- about X concept". Notes have their own note_concepts junction (separate table
-- since notes and contents are distinct entities).
-- ============================================================

CREATE TABLE content_concepts (
    content_id UUID NOT NULL REFERENCES contents(id) ON DELETE CASCADE,
    concept_id UUID NOT NULL REFERENCES concepts(id) ON DELETE CASCADE,
    relevance  TEXT NOT NULL DEFAULT 'primary'
               CHECK (relevance IN ('primary', 'secondary')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (content_id, concept_id)
);

COMMENT ON TABLE content_concepts IS
    'Many-to-many junction between contents and concepts. One public content '
    '(article / essay / til / build-log / digest) may cover multiple concepts. '
    'Notes use the separate note_concepts junction — intentionally not polymorphic. '
    'Cascade on either side keeps the junction free of dangling references.';
COMMENT ON COLUMN content_concepts.content_id IS
    'Content row. CASCADE on content deletion.';
COMMENT ON COLUMN content_concepts.concept_id IS
    'Concept row. CASCADE on concept deletion.';
COMMENT ON COLUMN content_concepts.relevance IS
    'primary = the core concept this content covers. secondary = a supporting concept also referenced. '
    'At most one primary per content, enforced by idx_content_concepts_one_primary.';
COMMENT ON COLUMN content_concepts.created_at IS
    'When the link was created. Matches the project junction convention '
    '(content_topics, content_tags, learning_target_concepts).';

CREATE INDEX idx_content_concepts_concept ON content_concepts(concept_id);
CREATE UNIQUE INDEX idx_content_concepts_one_primary
    ON content_concepts (content_id)
    WHERE relevance = 'primary';

-- Learning targets — what to learn, practice, and revisit
--
-- Things to be learned, practiced, and revisited. Independent of
-- notes (knowledge artifacts). A LeetCode problem exists before
-- you write a note about it. A book chapter exists before you do
-- a reading session.

CREATE TABLE learning_targets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain      TEXT NOT NULL REFERENCES learning_domains(slug) ON DELETE RESTRICT,
    title       TEXT NOT NULL,
    external_id TEXT,
    difficulty  TEXT CHECK (difficulty IN ('easy', 'medium', 'hard')),
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE learning_targets IS
    'Learning targets — what to learn, practice, and revisit. Lifecycle differs from '
    'notes: targets follow not-attempted → practicing → mastered (learning progress), '
    'while notes follow seed → evergreen → archived (knowledge maturity). Targets exist '
    'before notes are written. Writeups attach via the learning_target_notes and '
    'learning_target_contents junction tables (N:M — a single target may accumulate '
    'multiple writeups of different kinds over time: solve-note → concept-note → '
    'debug-postmortem). Canonical writeup per domain = notes row whose kind matches '
    'learning_domains.canonical_writeup_kind.';
COMMENT ON COLUMN learning_targets.domain IS 'Learning domain. FK to learning_domains.';
COMMENT ON COLUMN learning_targets.title IS
    'Display title. LeetCode: problem name. Reading: chapter title. '
    'Japanese: grammar point or drill name.';
COMMENT ON COLUMN learning_targets.external_id IS
    'Provider-specific identifier. LeetCode problem number, textbook section ID, '
    'JLPT grammar point ID. NULL for custom drills without external identity. '
    'Partial unique: one item per (domain, external_id) where external_id IS NOT NULL.';
COMMENT ON COLUMN learning_targets.difficulty IS
    'Generic 3-tier difficulty. Domain-specific info (JLPT N5-N1, etc.) goes in metadata. '
    'NULL = not categorized.';
COMMENT ON COLUMN learning_targets.metadata IS
    'Domain-specific data not needing WHERE/JOIN/GROUP BY. '
    'Not queryable — if a field needs WHERE/JOIN/GROUP BY, promote to a column. '
    'LeetCode: {problem_url, companies, frequency, constraints}. '
    'Japanese: {jlpt_level, textbook, chapter, grammar_point}. '
    'System Design: {source_book, chapter, scenario_type}. '
    'Reading: {book_title, chapter, page_range}.';
COMMENT ON COLUMN learning_targets.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

CREATE UNIQUE INDEX idx_learning_targets_domain_external
    ON learning_targets (domain, external_id)
    WHERE external_id IS NOT NULL;

-- Title-only rows canonicalise on (domain, title). Pairs with the
-- external-id partial above: together they cover both resolution paths
-- (FindOrCreateTarget supports external-id-bearing callers AND title-only
-- callers). Without this, record_attempt and manage_plan.add_entries with
-- only a title could produce two separate rows for the same problem and
-- silently split attempt history / mastery signals.
CREATE UNIQUE INDEX uq_learning_targets_domain_title_no_external
    ON learning_targets (domain, title)
    WHERE external_id IS NULL;
COMMENT ON INDEX uq_learning_targets_domain_title_no_external IS
    'Prevents duplicate title-only learning_targets per domain. Paired with idx_learning_targets_domain_external, covers both FindOrCreateTarget resolution paths without blocking intentionally-distinct titles on external-id-bearing rows.';

CREATE INDEX idx_learning_targets_domain ON learning_targets (domain);

-- ============================================================
-- Spaced repetition: review_cards + review_logs
-- ============================================================

CREATE TABLE review_cards (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    learning_target_id   UUID NOT NULL REFERENCES learning_targets(id) ON DELETE CASCADE,
    card_state           JSONB NOT NULL,
    due                  TIMESTAMPTZ NOT NULL,
    last_sync_drift_at   TIMESTAMPTZ,
    last_drift_reason    TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_review_card_state_not_empty
        CHECK (card_state <> '{}'::jsonb AND card_state <> 'null'::jsonb),
    CONSTRAINT chk_review_card_drift_pair
        CHECK ((last_sync_drift_at IS NULL AND last_drift_reason IS NULL)
            OR (last_sync_drift_at IS NOT NULL AND last_drift_reason IS NOT NULL))
);

COMMENT ON TABLE review_cards IS
    'Spaced repetition card state. Algorithm-agnostic; currently FSRS. One card per '
    'learning_target. Review is scoped to learning_targets only — content- or '
    'concept-scoped review is not modelled; add a new junction table when that '
    'feature ships.';
COMMENT ON COLUMN review_cards.learning_target_id IS
    'Learning target (problem, drill, chapter). CASCADE on target deletion. Unique '
    '(uq_review_cards_learning_target) — one card per target.';
COMMENT ON COLUMN review_cards.card_state IS
    'Serialized FSRS state (Due, Stability, Difficulty, Reps, Lapses). Opaque to SQL.';
COMMENT ON COLUMN review_cards.due IS
    'Denormalized from card_state for index-based due-date queries.';
COMMENT ON COLUMN review_cards.last_sync_drift_at IS
    'When the last attempt-driven FSRS review for this card failed to apply. '
    'NULL = never drifted. Paired with last_drift_reason by chk_review_card_drift_pair. '
    'Cleared on next successful review. Consumers (retrieval view) surface a '
    'drift_suspect flag when this is set and more recent than the last attempt.';
COMMENT ON COLUMN review_cards.last_drift_reason IS
    'Short machine-readable reason for the most recent drift event. '
    'NULL when last_sync_drift_at is NULL. Examples: unknown_outcome, persist_failed.';
COMMENT ON COLUMN review_cards.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

CREATE UNIQUE INDEX uq_review_cards_learning_target
    ON review_cards (learning_target_id);

CREATE INDEX idx_review_cards_due ON review_cards (due);

CREATE TABLE review_logs (
    id             BIGSERIAL PRIMARY KEY,
    card_id        UUID NOT NULL REFERENCES review_cards(id) ON DELETE CASCADE,
    rating         INT NOT NULL CHECK (rating BETWEEN 1 AND 4),
    scheduled_days INT NOT NULL CHECK (scheduled_days >= 0),
    elapsed_days   INT NOT NULL CHECK (elapsed_days >= 0),
    state          INT NOT NULL CHECK (state BETWEEN 0 AND 3),
    reviewed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE review_logs IS 'Append-only review history. One row per review event. RETENTION: indefinite (FSRS algorithm needs full history).';
COMMENT ON COLUMN review_logs.card_id IS
    'The review card this log belongs to. CASCADE — card deletion removes its history.';
COMMENT ON COLUMN review_logs.reviewed_at IS
    'When this review occurred. May differ from row insertion time if backfilled. '
    'DEFAULT now() for real-time reviews.';
COMMENT ON COLUMN review_logs.rating IS '1=Again (forgot), 2=Hard (partial), 3=Good (remembered), 4=Easy.';
COMMENT ON COLUMN review_logs.scheduled_days IS 'Days the FSRS algorithm scheduled between this and the previous review.';
COMMENT ON COLUMN review_logs.elapsed_days IS 'Actual days elapsed since the previous review.';
COMMENT ON COLUMN review_logs.state IS 'Card state BEFORE this review: 0=New, 1=Learning, 2=Review, 3=Relearning.';

CREATE INDEX idx_review_logs_card ON review_logs (card_id, reviewed_at DESC);

-- Learning item ↔ concept junction

CREATE TABLE learning_target_concepts (
    learning_target_id UUID NOT NULL REFERENCES learning_targets(id) ON DELETE CASCADE,
    concept_id       UUID NOT NULL REFERENCES concepts(id) ON DELETE CASCADE,
    relevance        TEXT NOT NULL DEFAULT 'primary'
                     CHECK (relevance IN ('primary', 'secondary')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (learning_target_id, concept_id)
);

COMMENT ON TABLE learning_target_concepts IS
    'Junction: which concepts a learning target exercises. CASCADE on both sides.';
COMMENT ON COLUMN learning_target_concepts.relevance IS
    'primary = the core concept this target drills. secondary = a supporting concept also exercised. '
    'At most one primary per target, enforced by idx_learning_target_concepts_one_primary.';

CREATE INDEX idx_learning_target_concepts_concept ON learning_target_concepts (concept_id);
CREATE UNIQUE INDEX idx_learning_target_concepts_one_primary
    ON learning_target_concepts (learning_target_id)
    WHERE relevance = 'primary';

-- ============================================================
-- Learning target writeup junctions
--
-- A learning target may accumulate multiple writeups of different kinds over
-- time. Two physical tables (not polymorphic FK) because notes and contents
-- are distinct entities with different lifecycles.
-- ============================================================

CREATE TABLE learning_target_notes (
    target_id  UUID NOT NULL REFERENCES learning_targets(id) ON DELETE CASCADE,
    note_id    UUID NOT NULL REFERENCES notes(id)            ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (target_id, note_id)
);

COMMENT ON TABLE learning_target_notes IS
    'Many-to-many: which notes are writeups of a learning target. One target may '
    'have multiple notes of different kinds (solve-note, concept-note, '
    'debug-postmortem, etc.) accumulated over time. Canonical writeup per domain '
    'resolves via learning_domains.canonical_writeup_kind.';

CREATE INDEX idx_learning_target_notes_note ON learning_target_notes (note_id);

CREATE TABLE learning_target_contents (
    target_id  UUID NOT NULL REFERENCES learning_targets(id) ON DELETE CASCADE,
    content_id UUID NOT NULL REFERENCES contents(id)          ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (target_id, content_id)
);

COMMENT ON TABLE learning_target_contents IS
    'Many-to-many: which public-facing contents (article/essay/til/build-log/digest) '
    'reference a learning target. E.g., an article "Understanding Go Memory Model" '
    'may be attached to the learning_target for DDIA Chapter 6 Memory Ordering.';

CREATE INDEX idx_learning_target_contents_content ON learning_target_contents (content_id);

-- ============================================================
-- Notes ↔ concepts junction
--
-- Parallel to content_concepts but for notes. Notes and contents both map to
-- concepts via their own junctions — intentionally not polymorphic.
-- ============================================================

CREATE TABLE note_concepts (
    note_id    UUID NOT NULL REFERENCES notes(id)    ON DELETE CASCADE,
    concept_id UUID NOT NULL REFERENCES concepts(id) ON DELETE CASCADE,
    relevance  TEXT NOT NULL DEFAULT 'primary'
               CHECK (relevance IN ('primary', 'secondary')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (note_id, concept_id)
);

COMMENT ON TABLE note_concepts IS
    'Many-to-many junction: which concepts a note synthesizes. One concept-note '
    'may cover multiple concepts; one concept may be covered by many notes (solve, '
    'concept, postmortem). Separate from content_concepts because notes and contents '
    'are distinct entities.';
COMMENT ON COLUMN note_concepts.relevance IS
    'primary = the core concept this note synthesizes. secondary = a supporting concept also referenced. '
    'At most one primary per note, enforced by idx_note_concepts_one_primary.';

CREATE INDEX idx_note_concepts_concept ON note_concepts(concept_id);
CREATE UNIQUE INDEX idx_note_concepts_one_primary
    ON note_concepts (note_id)
    WHERE relevance = 'primary';

-- Learning sessions: orchestration boundary with explicit start/end, mode,
-- and a container of attempts. Distinct from agent_notes (narrative log);
-- a session may produce an agent_note(kind=reflection) at the end, linked
-- via agent_note_id.

CREATE TABLE learning_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain              TEXT NOT NULL REFERENCES learning_domains(slug) ON DELETE RESTRICT,
    session_mode        TEXT NOT NULL
                        CHECK (session_mode IN ('retrieval', 'practice', 'mixed', 'review', 'reading')),
    agent_note_id       UUID REFERENCES agent_notes(id) ON DELETE SET NULL,
    daily_plan_item_id  UUID REFERENCES daily_plan_items(id) ON DELETE SET NULL,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at            TIMESTAMPTZ,
    metadata            JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_session_time_order
        CHECK (ended_at IS NULL OR ended_at >= started_at)
);

COMMENT ON TABLE learning_sessions IS
    'Session orchestration boundary — explicit start/end, mode, and attempt container. '
    'Distinct from agent_notes: agent_notes are post-hoc narrative (plan, context, '
    'reflection), sessions are in-progress orchestration. A session ending may produce '
    'an agent_notes(kind=reflection) entry, linked via agent_note_id. '
    'updated_at tracks mutation: ended_at and agent_note_id are written by EndSession, '
    'and metadata may be updated mid-session by orchestration code.';
COMMENT ON COLUMN learning_sessions.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries (notably EndSession).';
COMMENT ON COLUMN learning_sessions.domain IS 'Learning domain for this session. FK to learning_domains.';
COMMENT ON COLUMN learning_sessions.session_mode IS
    'retrieval: recall-based testing (no hints). '
    'practice: active problem-solving with coaching. '
    'mixed: combination of retrieval and practice. '
    'review: revisiting previously solved items. '
    'reading: comprehension-focused (DDIA, O''Reilly, literary texts).';
COMMENT ON COLUMN learning_sessions.agent_note_id IS
    'Optional link to the reflection agent_notes entry written after the session. '
    'The session produces the note, not the other way around. '
    'SET NULL on note deletion. Kind binding (must reference an agent_notes row '
    'with kind=''reflection'') is enforced by trg_learning_sessions_agent_note_kind.';
COMMENT ON COLUMN learning_sessions.daily_plan_item_id IS
    'If this session was planned in the daily plan, link here. '
    'Enables plan adherence analysis. SET NULL on plan item deletion.';
COMMENT ON COLUMN learning_sessions.started_at IS
    'Session start time. DEFAULT now() for immediate starts.';
COMMENT ON COLUMN learning_sessions.ended_at IS
    'NULL until session ends. NULL + old started_at = abandoned/crashed session.';
COMMENT ON COLUMN learning_sessions.metadata IS
    'Session orchestration details: coaching prompt used, session summary, '
    'configuration. Not queryable — stays in JSONB.';

CREATE INDEX idx_learning_sessions_started ON learning_sessions (started_at DESC);
CREATE INDEX idx_learning_sessions_domain ON learning_sessions (domain);
CREATE INDEX idx_learning_sessions_agent_note ON learning_sessions (agent_note_id)
    WHERE agent_note_id IS NOT NULL;

-- Structural invariant: learning_sessions.agent_note_id, when set, must
-- reference an agent_notes row with kind='reflection'. The FK alone does not
-- enforce kind binding; this trigger is the database-boundary guard so any
-- writer path (end_session, future tools, manual repair) is validated.
CREATE OR REPLACE FUNCTION enforce_learning_session_agent_note_kind() RETURNS TRIGGER AS $$
DECLARE
    note_kind agent_note_kind;
BEGIN
    IF NEW.agent_note_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT kind INTO note_kind FROM agent_notes WHERE id = NEW.agent_note_id;
    IF note_kind IS DISTINCT FROM 'reflection' THEN
        RAISE EXCEPTION 'learning_sessions.agent_note_id must reference an agent_notes row with kind=''reflection'' (got kind=%)', note_kind;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_learning_sessions_agent_note_kind
    BEFORE INSERT OR UPDATE OF agent_note_id ON learning_sessions
    FOR EACH ROW EXECUTE FUNCTION enforce_learning_session_agent_note_kind();
COMMENT ON TRIGGER trg_learning_sessions_agent_note_kind ON learning_sessions
    IS 'Rejects INSERT/UPDATE when agent_note_id points to an agent_notes row whose kind is not ''reflection''.';

-- At-most-one-active-session invariant enforcement. Constant key on
-- partial rows WHERE ended_at IS NULL — any two active sessions collide
-- by definition. start_session relies on this instead of a check-then-act
-- SQL pattern, which would race under READ COMMITTED isolation.
-- Concurrent INSERT race surfaces as 23505, mapped to ErrActiveExists by
-- the Go store layer.
CREATE UNIQUE INDEX uq_learning_sessions_one_active
    ON learning_sessions ((TRUE))
    WHERE ended_at IS NULL;
COMMENT ON INDEX uq_learning_sessions_one_active IS
    'At-most-one-active-session invariant. See internal/learning/store.go::StartSession — 23505 is mapped to ErrActiveExists.';

-- Attempts: individual learning attempt records
--
-- One learning target can have multiple attempts (first try,
-- revisit, re-practice). Each attempt records paradigm + outcome,
-- duration, approach, and where you got stuck. paradigm is its own column
-- so future paradigms (e.g. rubric_based for system-design mock interviews)
-- extend by adding an enum value + a joint CHECK arm, not by re-auditing
-- every outcome-filtered query.

CREATE TABLE learning_attempts (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    learning_target_id UUID NOT NULL REFERENCES learning_targets(id) ON DELETE CASCADE,
    session_id        UUID NOT NULL REFERENCES learning_sessions(id) ON DELETE RESTRICT,
    attempt_number    INT NOT NULL DEFAULT 1,
    paradigm          TEXT NOT NULL
                      CHECK (paradigm IN ('problem_solving', 'immersive')),
    outcome           TEXT NOT NULL,
    duration_minutes  INT,
    stuck_at          TEXT,
    approach_used     TEXT,
    metadata          JSONB NOT NULL DEFAULT '{}',
    attempted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_attempt_number_positive CHECK (attempt_number >= 1),
    CONSTRAINT chk_duration_positive CHECK (duration_minutes IS NULL OR duration_minutes > 0),
    CONSTRAINT chk_learning_attempts_paradigm_outcome CHECK (
        (paradigm = 'problem_solving' AND outcome IN (
            'solved_independent', 'solved_with_hint', 'solved_after_solution',
            'incomplete', 'gave_up'))
        OR (paradigm = 'immersive' AND outcome IN (
            'completed', 'completed_with_support',
            'incomplete', 'gave_up'))
    )
);

COMMENT ON TABLE learning_attempts IS
    'Individual learning attempt records. One learning target can have multiple attempts '
    '(first try, revisit, re-practice). CASCADE from learning_targets. Append-only — no '
    'updated_at. RETENTION: indefinite (learning history is a permanent personal asset).';
COMMENT ON COLUMN learning_attempts.learning_target_id IS
    'The learning target attempted. CASCADE — attempts are meaningless without their item.';
COMMENT ON COLUMN learning_attempts.session_id IS
    'The session this attempt occurred in. NOT NULL — every attempt must live in a '
    'session. ON DELETE RESTRICT — sessions with attempts cannot be deleted; end them instead.';
COMMENT ON COLUMN learning_attempts.attempt_number IS
    'Nth attempt at this item. 1 = first try, 2+ = revisit. Application must compute '
    'MAX(attempt_number) + 1 before inserting — DEFAULT 1 only applies to first attempts. '
    'UNIQUE with learning_target_id enforces no duplicate numbering.';
COMMENT ON COLUMN learning_attempts.paradigm IS
    'Paradigm of the attempt. Own column so a new paradigm extends by '
    '(enum value + joint CHECK arm) instead of by re-auditing every '
    'outcome-filtered query. '
    'problem_solving: LeetCode, grammar drills, Japanese output practice — '
    'outcome expresses how much help the learner needed. '
    'immersive: DDIA reading, literary analysis, listening practice — outcome '
    'expresses whether comprehension was self-sustained. '
    'Extending: add enum value + add joint CHECK arm with that paradigm''s '
    'outcome vocabulary.';
COMMENT ON COLUMN learning_attempts.outcome IS
    'Paradigm-scoped outcome value. Joint CHECK (chk_learning_attempts_paradigm_outcome) '
    'enforces that outcome belongs to paradigm''s vocabulary. '
    'problem_solving ⇒ {solved_independent, solved_with_hint, solved_after_solution, '
    'incomplete, gave_up}. '
    'immersive ⇒ {completed, completed_with_support, incomplete, gave_up}. '
    'Shared values (incomplete, gave_up) are legal under both paradigms. '
    'Cross-paradigm analytics use learning_targets.domain / learning_sessions.domain '
    'as the filter — do NOT use session_mode to infer paradigm (mixed and review '
    'cross paradigms; shared outcomes break the inference).';
COMMENT ON COLUMN learning_attempts.duration_minutes IS
    'Time spent on this attempt in minutes. NULL = not tracked. Must be positive.';
COMMENT ON COLUMN learning_attempts.stuck_at IS
    'Free-text: where you got stuck. High cardinality, not a queryable category.';
COMMENT ON COLUMN learning_attempts.approach_used IS
    'Free-text: what method you used. Coaching context, not a queryable enum.';
COMMENT ON COLUMN learning_attempts.metadata IS
    'Narrative data: coaching hints given, alternative approaches considered, code quality '
    'observations, LLM transcript excerpts. Not queryable — stays in JSONB. '
    'If a field needs WHERE/JOIN/GROUP BY, promote to a column.';
COMMENT ON COLUMN learning_attempts.attempted_at IS
    'When this attempt occurred. May differ from created_at if backfilled.';

CREATE UNIQUE INDEX idx_learning_attempts_item_number ON learning_attempts (learning_target_id, attempt_number);
CREATE INDEX idx_learning_attempts_item_date ON learning_attempts (learning_target_id, attempted_at DESC);
CREATE INDEX idx_learning_attempts_session ON learning_attempts (session_id);
CREATE INDEX idx_learning_attempts_date ON learning_attempts (attempted_at DESC);

-- Attempt observations: weakness / improvement / mastery signals
--
-- The heart of learning analytics. Each observation connects
-- an attempt to a concept with a typed signal. Powers the
-- drill-down weakness UI and progression tracking.

-- Canonical category registry for observations. Every value written to
-- learning_attempt_observations.category must exist here; the FK makes the
-- dashboard's GROUP BY category a typo-free aggregation key. domain is
-- metadata for curation (which domain owns this category); it is not part
-- of the FK join key — a category slug is globally unique so callers do
-- not have to plumb domain through to the observation writer.
CREATE TABLE observation_categories (
    slug        TEXT PRIMARY KEY,
    domain      TEXT NOT NULL REFERENCES learning_domains(slug) ON DELETE RESTRICT,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_observation_category_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$')
);

COMMENT ON TABLE observation_categories IS
    'Canonical observation.category registry. FK from '
    'learning_attempt_observations.category makes the dashboard''s GROUP BY '
    'category a typo-free aggregation key. Domain is metadata; slugs are global.';

CREATE INDEX idx_observation_categories_domain ON observation_categories(domain);

CREATE TABLE learning_attempt_observations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attempt_id  UUID NOT NULL REFERENCES learning_attempts(id) ON DELETE CASCADE,
    concept_id  UUID NOT NULL REFERENCES concepts(id) ON DELETE RESTRICT,
    signal_type TEXT NOT NULL CHECK (signal_type IN ('weakness', 'improvement', 'mastery')),
    category    TEXT NOT NULL REFERENCES observation_categories(slug) ON DELETE RESTRICT,
    severity    TEXT CHECK (severity IN ('minor', 'moderate', 'critical')),
    detail      TEXT,
    confidence  TEXT NOT NULL DEFAULT 'high' CHECK (confidence IN ('high', 'low')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_severity_weakness_only
        CHECK (signal_type = 'weakness' OR severity IS NULL)
);

COMMENT ON TABLE learning_attempt_observations IS
    'Micro-cognitive signals observed during a specific attempt on a specific concept. '
    'Powers weakness overview, progression tracking, and drill-down UI. Append-only. '
    'CASCADE from attempts, RESTRICT from concepts. RETENTION: indefinite (learning '
    'history is a permanent personal asset).';
COMMENT ON COLUMN learning_attempt_observations.attempt_id IS
    'The attempt during which this signal was observed. CASCADE — observations die with their attempt.';
COMMENT ON COLUMN learning_attempt_observations.concept_id IS
    'The concept this signal pertains to. RESTRICT — cannot delete a concept that has '
    'observations. To merge concepts: UPDATE observations to surviving concept_id first, '
    'then DELETE the old concept. Observations are irreplaceable historical analytics.';
COMMENT ON COLUMN learning_attempt_observations.signal_type IS
    'weakness: something went wrong with this concept during this attempt. '
    'improvement: noticeable progress compared to previous attempts. '
    'mastery: demonstrated independent, fluent application.';
COMMENT ON COLUMN learning_attempt_observations.category IS
    'Observation dimension. Enforced by FK to observation_categories(slug) — '
    'unknown or typo values are rejected at write time, not silently split in '
    'dashboard aggregation. Curate the closed set via the observation_categories '
    'table; seeded sets live in migrations/002_seed.up.sql.';
COMMENT ON COLUMN learning_attempt_observations.severity IS
    'Granularity within a signal. minor: forgot one edge case. moderate: correct approach, '
    'failed execution. critical: did not recognize the pattern at all. '
    'NULL for improvement/mastery signals where severity does not apply.';
COMMENT ON COLUMN learning_attempt_observations.detail IS
    'Free-text evidence or explanation. NULL when the signal is self-explanatory '
    'from category alone.';
COMMENT ON COLUMN learning_attempt_observations.confidence IS
    'high (default): signal directly evidenced by the attempt outcome — '
    'user said "I forgot how X works" or repeatedly failed at X. '
    'low: coach inferred the signal from indirect evidence — '
    'user struggled with the problem and coach suspects X is the missing skill. '
    'Both persist. Dashboard mastery and weakness views default to high only; '
    'pass confidence_filter=all to include low-confidence observations.';

CREATE INDEX idx_learning_attempt_observations_concept_signal ON learning_attempt_observations (concept_id, signal_type);
CREATE INDEX idx_learning_attempt_observations_attempt ON learning_attempt_observations (attempt_id);
CREATE INDEX idx_learning_attempt_observations_high_confidence
    ON learning_attempt_observations (concept_id, created_at DESC)
    WHERE confidence = 'high';

-- Learning target relations: variation / prerequisite graph
--
-- Direction convention:
--   anchor_id  = the reference point (the target the row is "about")
--   related_id = the other learning target related to the anchor
--   relation_type = how related_id relates to anchor_id
--
-- (anchor=42, related=167, easier_variant) means
-- "167 is an easier variant of 42."
--
-- Why anchor/related instead of the more conventional source/target:
-- the table name already says "learning_target", so the graph-theory
-- column names "source/target" would create the awkward triple
-- "learning_target_relations.target_id" where "target" means three
-- different things at once (the table's entity, the FK target, and
-- the directed-edge endpoint). anchor/related sidesteps the collision.

CREATE TABLE learning_target_relations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    anchor_id     UUID NOT NULL REFERENCES learning_targets(id) ON DELETE CASCADE,
    related_id    UUID NOT NULL REFERENCES learning_targets(id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL
                  CHECK (relation_type IN (
                      'easier_variant', 'harder_variant', 'prerequisite',
                      'follow_up', 'same_pattern', 'similar_structure')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_no_self_relation CHECK (anchor_id <> related_id)
);

COMMENT ON TABLE learning_target_relations IS
    'Directed graph of learning target relationships. anchor is the reference target; '
    'related is the other target; relation_type describes how related relates to anchor. '
    'Example: (anchor=42, related=167, easier_variant) means "167 is an easier variant of 42". '
    'CASCADE on both sides. Append-only. Same-domain invariant enforced by '
    'trg_learning_target_relations_domain. Symmetric relations (same_pattern, '
    'similar_structure) auto-insert the reverse edge via '
    'trg_learning_target_relations_symmetry — writers insert one direction, '
    'the schema stores both. ON CONFLICT DO NOTHING keeps the second insert idempotent.';
COMMENT ON COLUMN learning_target_relations.anchor_id IS 'The reference target. CASCADE on deletion.';
COMMENT ON COLUMN learning_target_relations.related_id IS 'The target related to anchor. CASCADE on deletion.';
COMMENT ON COLUMN learning_target_relations.relation_type IS
    'Directed types (anchor → related reads one-way): '
    'easier_variant (related is simpler), harder_variant (related is more complex), '
    'prerequisite (related should be done before anchor), follow_up (related is a '
    'natural next step after anchor). '
    'Symmetric types (A-related-to-B ⇔ B-related-to-A): same_pattern (same core '
    'pattern), similar_structure (structural similarity, different pattern). '
    'The reverse edge of a symmetric insert is auto-created by '
    'trg_learning_target_relations_symmetry — callers insert one direction only.';

CREATE UNIQUE INDEX idx_learning_target_relations_triple
    ON learning_target_relations (anchor_id, related_id, relation_type);
CREATE INDEX idx_learning_target_relations_anchor ON learning_target_relations (anchor_id);
CREATE INDEX idx_learning_target_relations_related ON learning_target_relations (related_id);

-- ============================================================
-- Learning subsystem invariants enforced via triggers
-- ============================================================

-- concepts.parent_id and child must share the same domain.
CREATE OR REPLACE FUNCTION enforce_concept_parent_domain() RETURNS TRIGGER AS $$
DECLARE
    parent_domain TEXT;
BEGIN
    IF NEW.parent_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT domain INTO parent_domain FROM concepts WHERE id = NEW.parent_id;
    IF parent_domain IS DISTINCT FROM NEW.domain THEN
        RAISE EXCEPTION 'concept % has domain %, parent % has domain %; parent and child must share a domain',
            NEW.id, NEW.domain, NEW.parent_id, parent_domain;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_concepts_parent_domain
    BEFORE INSERT OR UPDATE OF parent_id, domain ON concepts
    FOR EACH ROW EXECUTE FUNCTION enforce_concept_parent_domain();

-- concepts.parent_id graph must remain acyclic.
CREATE OR REPLACE FUNCTION enforce_concept_acyclicity() RETURNS TRIGGER AS $$
DECLARE
    cycle_found BOOLEAN;
BEGIN
    IF NEW.parent_id IS NULL THEN
        RETURN NEW;
    END IF;
    WITH RECURSIVE ancestors(id) AS (
        SELECT NEW.parent_id
        UNION ALL
        SELECT c.parent_id FROM concepts c JOIN ancestors a ON c.id = a.id WHERE c.parent_id IS NOT NULL
    )
    SELECT EXISTS (SELECT 1 FROM ancestors WHERE id = NEW.id) INTO cycle_found;
    IF cycle_found THEN
        RAISE EXCEPTION 'concept % parent_id assignment would create a cycle', NEW.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_concepts_acyclicity
    BEFORE INSERT OR UPDATE OF parent_id ON concepts
    FOR EACH ROW EXECUTE FUNCTION enforce_concept_acyclicity();

-- learning_target_relations: anchor and related must share the same domain.
CREATE OR REPLACE FUNCTION enforce_learning_target_relation_domain() RETURNS TRIGGER AS $$
DECLARE
    anchor_domain  TEXT;
    related_domain TEXT;
BEGIN
    SELECT domain INTO anchor_domain  FROM learning_targets WHERE id = NEW.anchor_id;
    SELECT domain INTO related_domain FROM learning_targets WHERE id = NEW.related_id;
    IF anchor_domain IS DISTINCT FROM related_domain THEN
        RAISE EXCEPTION 'learning_target_relations: anchor % (domain %) and related % (domain %) must share a domain',
            NEW.anchor_id, anchor_domain, NEW.related_id, related_domain;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_learning_target_relations_domain
    BEFORE INSERT OR UPDATE OF anchor_id, related_id ON learning_target_relations
    FOR EACH ROW EXECUTE FUNCTION enforce_learning_target_relation_domain();

-- learning_target_relations: same_pattern and similar_structure are symmetric
-- relations — if A is same_pattern with B, B is same_pattern with A. Structure
-- is directed (anchor/related) but semantics isn't. Rather than forcing every
-- writer to remember both directions, insert the reverse automatically.
-- ON CONFLICT DO NOTHING guards against recursion: the second insert collides
-- with the unique (anchor_id, related_id, relation_type) index and terminates
-- silently. Directed relations (easier_variant, harder_variant, prerequisite,
-- follow_up) fall through as-is.
CREATE OR REPLACE FUNCTION enforce_learning_target_relation_symmetry() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.relation_type IN ('same_pattern', 'similar_structure') THEN
        INSERT INTO learning_target_relations (anchor_id, related_id, relation_type)
        VALUES (NEW.related_id, NEW.anchor_id, NEW.relation_type)
        ON CONFLICT (anchor_id, related_id, relation_type) DO NOTHING;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_learning_target_relations_symmetry
    AFTER INSERT ON learning_target_relations
    FOR EACH ROW EXECUTE FUNCTION enforce_learning_target_relation_symmetry();

-- ============================================================
-- Learning hypotheses
--
-- Falsifiable hypothesis tracker scoped to the learning domain. Defined here
-- so resolved_by_* FKs into learning_attempts and learning_attempt_observations
-- are valid. Name reflects actual scope — every evidence FK points into
-- learning structures; cross-domain hypothesis tracking (pipeline / system-
-- design / UX) would use a domain-scoped sibling table, not this one.
-- ============================================================

CREATE TABLE learning_hypotheses (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_by                  TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    content                     TEXT NOT NULL,
    state                       hypothesis_state NOT NULL DEFAULT 'unverified',
    claim                       TEXT NOT NULL,
    invalidation_condition      TEXT NOT NULL,
    metadata                    JSONB,
    observed_date               DATE NOT NULL,
    resolved_at                 TIMESTAMPTZ,
    resolved_by_attempt_id      UUID REFERENCES learning_attempts(id) ON DELETE SET NULL,
    resolved_by_observation_id  UUID REFERENCES learning_attempt_observations(id) ON DELETE SET NULL,
    resolution_summary          TEXT,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_learning_hypothesis_resolved_at
        CHECK ((state IN ('verified', 'invalidated')) = (resolved_at IS NOT NULL)),
    CONSTRAINT chk_learning_hypothesis_resolution
        CHECK (
            state IN ('unverified', 'archived')
            OR resolved_by_attempt_id IS NOT NULL
            OR resolved_by_observation_id IS NOT NULL
            OR (resolution_summary IS NOT NULL AND btrim(resolution_summary) <> '')
        )
);

COMMENT ON TABLE learning_hypotheses IS
    'Falsifiable hypothesis tracker for the LEARNING domain — LeetCode pattern '
    'failures, Japanese grammar misconceptions, system-design principle gaps. '
    'Each row carries a one-line claim plus the invalidation condition that '
    'would disprove it. Evidence FKs (resolved_by_attempt_id, '
    'resolved_by_observation_id) point only into learning structures. '
    'CROSS-DOMAIN HYPOTHESES DO NOT BELONG HERE — if you need hypothesis '
    'tracking for another domain (Resonance pipeline, system-design decisions '
    'outside learning, UX experiments), open an RFC for a domain-scoped sibling '
    'table (pipeline_hypotheses, design_hypotheses, ...). Adding non-learning '
    'rows to this table and satisfying chk_learning_hypothesis_resolution via '
    'free-text resolution_summary is a semantic bug: learning analytics will '
    'then include non-learning signals and vice versa.';
COMMENT ON COLUMN learning_hypotheses.created_by IS 'Which agent recorded the hypothesis. FK to agents.';
COMMENT ON COLUMN learning_hypotheses.content IS 'Full narrative context. claim is the one-line prediction; content is the supporting analysis.';
COMMENT ON COLUMN learning_hypotheses.state IS 'Lifecycle: unverified → verified | invalidated → archived.';
COMMENT ON COLUMN learning_hypotheses.claim IS 'One-line falsifiable prediction.';
COMMENT ON COLUMN learning_hypotheses.invalidation_condition IS 'What evidence would disprove the claim. Required — a hypothesis without one is not falsifiable.';
COMMENT ON COLUMN learning_hypotheses.metadata IS 'supporting_evidence, counter_evidence, conclusion, category, project, tags. Promote fields to columns when WHERE/JOIN/GROUP BY usage exceeds 3 occurrences.';
COMMENT ON COLUMN learning_hypotheses.observed_date IS 'Date the hypothesis was first observed or recorded.';
COMMENT ON COLUMN learning_hypotheses.resolved_at IS 'When the state transitioned to verified or invalidated. NULL otherwise. Tied to state by chk_learning_hypothesis_resolved_at.';
COMMENT ON COLUMN learning_hypotheses.resolved_by_attempt_id IS 'Optional FK to the learning attempt whose outcome resolved this hypothesis. SET NULL on attempt deletion.';
COMMENT ON COLUMN learning_hypotheses.resolved_by_observation_id IS 'Optional FK to the observation whose evidence resolved this hypothesis. SET NULL on observation deletion.';
COMMENT ON COLUMN learning_hypotheses.resolution_summary IS 'Free-text resolution rationale. Required when state is verified/invalidated and neither resolved_by_* FK is set.';

CREATE INDEX idx_learning_hypotheses_state ON learning_hypotheses (state);
CREATE INDEX idx_learning_hypotheses_date ON learning_hypotheses (observed_date DESC);
CREATE INDEX idx_learning_hypotheses_resolved_attempt
    ON learning_hypotheses (resolved_by_attempt_id) WHERE resolved_by_attempt_id IS NOT NULL;
CREATE INDEX idx_learning_hypotheses_resolved_observation
    ON learning_hypotheses (resolved_by_observation_id) WHERE resolved_by_observation_id IS NOT NULL;

-- ============================================================
-- Learning plans: ordered, mutable curricula linking plans to items
-- ============================================================

CREATE TABLE learning_plans (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    domain       TEXT NOT NULL REFERENCES learning_domains(slug) ON DELETE RESTRICT,
    goal_id      UUID REFERENCES goals(id) ON DELETE SET NULL,
    status       TEXT NOT NULL DEFAULT 'draft'
                 CHECK (status IN ('draft', 'active', 'completed', 'paused', 'abandoned')),
    target_count INT CHECK (target_count IS NULL OR target_count > 0),
    plan_config  JSONB NOT NULL DEFAULT '{}',
    created_by   TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_learning_plans_domain ON learning_plans (domain);
CREATE INDEX idx_learning_plans_goal ON learning_plans (goal_id) WHERE goal_id IS NOT NULL;
CREATE INDEX idx_learning_plans_status ON learning_plans (status) WHERE status IN ('draft', 'active');
CREATE INDEX idx_learning_plans_created_by ON learning_plans (created_by);

COMMENT ON TABLE learning_plans IS
    'Ordered, mutable learning curricula — a named commitment to practice a specific '
    'set of learning targets. Plans serve aspirations (goals), not execution vehicles '
    '(projects). Status lifecycle: draft → active → completed/paused/abandoned. '
    'Draft = workspace/uncommitted. Active = committed curriculum being tracked '
    'against execution.';
COMMENT ON COLUMN learning_plans.id IS
    'Primary key. Auto-generated UUID.';
COMMENT ON COLUMN learning_plans.title IS
    'Display title (e.g., "LeetCode 200 題計畫"). Not unique — allows v1/v2 scenarios.';
COMMENT ON COLUMN learning_plans.description IS
    'Plan description, strategy notes. Empty string = no description.';
COMMENT ON COLUMN learning_plans.domain IS 'Learning domain. FK to learning_domains.';
COMMENT ON COLUMN learning_plans.goal_id IS
    'Optional aspirational target. NULL = area-level maintenance plan (no specific goal). '
    'SET NULL on goal deletion.';
COMMENT ON COLUMN learning_plans.status IS
    'Lifecycle state. draft → active → completed. Can pause from active, abandon from '
    'draft/active/paused. Draft plans are not tracked in execution. See '
    'mcp-decision-policy.md for mutation rules per status.';
COMMENT ON COLUMN learning_plans.target_count IS
    'Advisory target item count (e.g., 200). NULL = open-ended plan. Not enforced by DB.';
COMMENT ON COLUMN learning_plans.plan_config IS
    'Plan-creation parameters that do NOT need WHERE/JOIN/GROUP BY. If any field needs '
    'filtering, promote to a column. Examples: difficulty_distribution, focus_areas, '
    'pacing_notes.';
COMMENT ON COLUMN learning_plans.created_by IS
    'Which agent created this plan. FK to agents. RESTRICT on delete — cannot remove an agent '
    'who owns plans.';
COMMENT ON COLUMN learning_plans.created_at IS
    'Row creation timestamp.';
COMMENT ON COLUMN learning_plans.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

CREATE TABLE learning_plan_entries (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_id                 UUID NOT NULL REFERENCES learning_plans(id) ON DELETE CASCADE,
    learning_target_id      UUID NOT NULL REFERENCES learning_targets(id) ON DELETE RESTRICT,
    position                INT NOT NULL DEFAULT 0,
    status                  TEXT NOT NULL DEFAULT 'planned'
                            CHECK (status IN ('planned', 'completed', 'skipped', 'substituted')),
    phase                   TEXT,
    substituted_by          UUID REFERENCES learning_plan_entries(id) ON DELETE SET NULL,
    completed_by_attempt_id UUID REFERENCES learning_attempts(id) ON DELETE SET NULL,
    reason                  TEXT,
    added_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at            TIMESTAMPTZ,

    UNIQUE (plan_id, learning_target_id),
    UNIQUE (plan_id, position),
    CONSTRAINT chk_substituted_by_requires_status
        CHECK (substituted_by IS NULL OR status = 'substituted'),
    CONSTRAINT chk_substituted_by_not_self
        CHECK (substituted_by IS NULL OR substituted_by <> id),
    CONSTRAINT chk_completed_at_requires_status
        CHECK (completed_at IS NULL OR status = 'completed'),
    CONSTRAINT chk_completed_by_attempt_requires_status
        CHECK (status <> 'completed' OR completed_by_attempt_id IS NOT NULL)
);

CREATE INDEX idx_learning_plan_entries_plan ON learning_plan_entries (plan_id, position);
CREATE INDEX idx_learning_plan_entries_target ON learning_plan_entries (learning_target_id);
CREATE INDEX idx_learning_plan_entries_phase ON learning_plan_entries (plan_id, phase) WHERE phase IS NOT NULL;
CREATE INDEX idx_learning_plan_entries_status ON learning_plan_entries (plan_id, status);
CREATE INDEX idx_learning_plan_entries_attempt ON learning_plan_entries (completed_by_attempt_id)
    WHERE completed_by_attempt_id IS NOT NULL;

-- Structural invariant: substituted_by forms a DAG within a plan. An entry
-- cannot substitute through a chain that leads back to itself. Same pattern
-- as concepts.parent_id acyclicity.
CREATE OR REPLACE FUNCTION enforce_learning_plan_entry_substitution_acyclic() RETURNS TRIGGER AS $$
DECLARE
    cycle_found BOOLEAN;
BEGIN
    IF NEW.substituted_by IS NULL THEN
        RETURN NEW;
    END IF;
    WITH RECURSIVE chain(id) AS (
        SELECT NEW.substituted_by
        UNION ALL
        SELECT e.substituted_by FROM learning_plan_entries e JOIN chain c ON e.id = c.id WHERE e.substituted_by IS NOT NULL
    )
    SELECT EXISTS (SELECT 1 FROM chain WHERE id = NEW.id) INTO cycle_found;
    IF cycle_found THEN
        RAISE EXCEPTION 'learning_plan_entries % substituted_by assignment would create a substitution cycle', NEW.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_learning_plan_entries_substitution_acyclic
    BEFORE INSERT OR UPDATE OF substituted_by ON learning_plan_entries
    FOR EACH ROW EXECUTE FUNCTION enforce_learning_plan_entry_substitution_acyclic();
COMMENT ON TRIGGER trg_learning_plan_entries_substitution_acyclic ON learning_plan_entries
    IS 'Rejects substituted_by assignment that would create a cycle in the substitution chain within a plan.';

COMMENT ON TABLE learning_plan_entries IS
    'Junction between plans and items — plan membership with ordering '
    'and per-item lifecycle. Same item can appear in multiple plans (cross-plan '
    'reuse). CASCADE from plan deletion. RESTRICT from item deletion — cannot '
    'silently remove items from a plan. Append-style with status tracking — no updated_at '
    '(status transitions are the audit trail).';
COMMENT ON COLUMN learning_plan_entries.id IS
    'Primary key. Auto-generated UUID.';
COMMENT ON COLUMN learning_plan_entries.plan_id IS
    'Parent learning plan. CASCADE — deleting a plan removes all its items.';
COMMENT ON COLUMN learning_plan_entries.learning_target_id IS
    'The learning target included in this plan. RESTRICT on delete — cannot silently '
    'remove a plan item by deleting its catalog entry. Resolve plan references first.';
COMMENT ON COLUMN learning_plan_entries.position IS
    '0-based ordering within the plan. Enforced by UNIQUE (plan_id, position) — '
    'application must choose non-colliding positions, typically via max(position)+1 '
    'append or explicit reorder transaction.';
COMMENT ON COLUMN learning_plan_entries.status IS
    'Plan-item lifecycle: planned → completed (via explicit tool call after successful '
    'attempt) | skipped (plan decision to not do it) | substituted (replaced by another '
    'item). Distinct from attempt.outcome — plan_status is a plan-domain decision, not '
    'an execution result.';
COMMENT ON COLUMN learning_plan_entries.phase IS
    'Optional grouping label within the plan (e.g., "1-arrays", "phase-2-trees"). '
    'Free-text with kebab-case validation enforced in Go, not DB. NULL = no phase grouping.';
COMMENT ON COLUMN learning_plan_entries.substituted_by IS
    'If status=''substituted'', points to the learning_plan_entries.id of the replacement '
    'entry WITHIN THE SAME PLAN. NULL for non-substituted entries. SET NULL if replacement '
    'entry is deleted.';
COMMENT ON COLUMN learning_plan_entries.completed_by_attempt_id IS
    'The attempt that triggered plan-item completion. FK to attempts(id). '
    'NULL for planned/skipped/substituted items, and for manually completed items '
    '(e.g., completed outside a session or on another platform with no attempt record). '
    'Policy: when Claude marks an item completed via manage_plan, this field is MANDATORY '
    '(enforced by policy, not schema). Schema stays nullable to allow future manual/UI '
    'completion paths. SET NULL on attempt deletion — completion decision survives.';
COMMENT ON COLUMN learning_plan_entries.reason IS
    'Context for status transitions. For completed: what attempt outcome and reasoning '
    'informed the completion decision (policy-mandatory when Claude completes). '
    'For skipped/substituted: why the item was removed from active tracking. '
    'NULL for planned items only.';
COMMENT ON COLUMN learning_plan_entries.added_at IS
    'When this item was added to the plan.';
COMMENT ON COLUMN learning_plan_entries.completed_at IS
    'When this item was marked completed in the plan context. NULL until status → '
    'completed. Set by manage_plan tool call, not derived from attempts.';

-- ============================================================
-- Bookmarks — external resources curated with commentary
-- ============================================================
-- Split out from contents.type='bookmark' polymorphism. Bookmarks
-- differ from first-party content: external canonical URL,
-- curate = publish (no editorial review),
-- different RSS output. See internal/bookmark package.

CREATE TABLE bookmarks (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url                  TEXT NOT NULL,
    url_hash             TEXT NOT NULL,
    slug                 TEXT NOT NULL,
    title                TEXT NOT NULL,
    excerpt              TEXT NOT NULL DEFAULT '',
    note                 TEXT NOT NULL DEFAULT '',
    capture_channel      TEXT NOT NULL
        CHECK (capture_channel IN ('rss', 'manual', 'shared')),
    source_feed_entry_id UUID REFERENCES feed_entries(id) ON DELETE SET NULL,
    curated_by           TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    curated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_public            BOOLEAN NOT NULL DEFAULT true,
    published_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    embedding            vector(1536),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uniq_bookmarks_url_hash UNIQUE (url_hash),
    CONSTRAINT uniq_bookmarks_slug UNIQUE (slug),
    CONSTRAINT chk_bookmark_url_scheme
        CHECK (url ~ '^https?://'),
    CONSTRAINT chk_bookmark_url_hash_format
        CHECK (url_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT chk_bookmark_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_bookmark_title_not_blank
        CHECK (btrim(title) <> '')
);

COMMENT ON TABLE bookmarks IS 'External resources curated with personal commentary. Curate = publish: creating a bookmark sets published_at = now() and is_public = true by default. No editorial review.';
COMMENT ON COLUMN bookmarks.url IS 'Canonical external URL. Must use http(s) scheme. SEO canonical tag points to this value.';
COMMENT ON COLUMN bookmarks.url_hash IS 'SHA-256 hex digest (64 chars) of the canonical URL. Dedup identity. Computed in application code before INSERT.';
COMMENT ON COLUMN bookmarks.slug IS 'URL-safe internal identifier for the bookmark''s permalink on the koopa0.dev site. Distinct from the external URL.';
COMMENT ON COLUMN bookmarks.title IS 'Display title. May override the source title if edited at capture time.';
COMMENT ON COLUMN bookmarks.excerpt IS 'Short excerpt from the source. Empty string when none.';
COMMENT ON COLUMN bookmarks.note IS 'Curator''s personal commentary. Empty string when none.';
COMMENT ON COLUMN bookmarks.capture_channel IS 'How the bookmark entered the system. rss = curated from a feed entry. manual = pasted by the curator. shared = received via an external channel.';
COMMENT ON COLUMN bookmarks.source_feed_entry_id IS 'When capture_channel=rss, references the originating feed_entries row. NULL otherwise. SET NULL on feed_entry deletion.';
COMMENT ON COLUMN bookmarks.curated_by IS 'Agent that curated the bookmark. FK to agents.';
COMMENT ON COLUMN bookmarks.curated_at IS 'When the bookmark was curated into the system.';
COMMENT ON COLUMN bookmarks.is_public IS 'Whether this bookmark is visible on the public website. Defaults to true — curate = publish.';
COMMENT ON COLUMN bookmarks.published_at IS 'When the bookmark was published. Defaults to now() at row creation since creating a bookmark is the act of publishing.';
COMMENT ON COLUMN bookmarks.embedding IS 'pgvector embedding (1536d) from gemini-embedding-2-preview. Must match internal/embedder.Dimension or pgvector rejects writes.';

CREATE INDEX idx_bookmarks_published_at ON bookmarks(published_at DESC NULLS LAST)
    WHERE is_public = true;
CREATE INDEX idx_bookmarks_curated_at ON bookmarks(curated_at DESC);
CREATE INDEX idx_bookmarks_source_feed_entry ON bookmarks(source_feed_entry_id)
    WHERE source_feed_entry_id IS NOT NULL;
CREATE INDEX idx_bookmarks_embedding_hnsw ON bookmarks USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE TABLE bookmark_topics (
    bookmark_id UUID NOT NULL REFERENCES bookmarks(id) ON DELETE CASCADE,
    topic_id    UUID NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    PRIMARY KEY (bookmark_id, topic_id)
);

COMMENT ON TABLE bookmark_topics IS 'Junction: bookmark ↔ topic. Many-to-many. Topics are curated knowledge domain categories (same taxonomy as content_topics).';

CREATE INDEX idx_bookmark_topics_topic_id ON bookmark_topics(topic_id);

CREATE TABLE bookmark_tags (
    bookmark_id UUID NOT NULL REFERENCES bookmarks(id) ON DELETE CASCADE,
    tag_id      UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (bookmark_id, tag_id)
);

COMMENT ON TABLE bookmark_tags IS 'Junction: bookmark ↔ tag. References canonical tags resolved through the tag_aliases pipeline.';

CREATE INDEX idx_bookmark_tags_tag_id ON bookmark_tags(tag_id);

-- ============================================================
-- Cross-table invariants — require both endpoint tables to exist
-- ============================================================

-- feed_entry ↔ bookmark curation exclusion. A single feed_entry may be
-- curated into first-party content (feed_entries.curated_content_id) OR into
-- an external bookmark (bookmarks.source_feed_entry_id), never both.
-- Enforced bidirectionally. SELECT ... FOR UPDATE on the feed_entries row
-- serialises the cross-table check — without the lock, two concurrent
-- transactions (one setting curated_content_id, one inserting a bookmark
-- that references the same feed_entry) could both pass the IF EXISTS guard
-- under READ COMMITTED and commit conflicting state.
CREATE OR REPLACE FUNCTION enforce_feed_entry_curation_exclusion() RETURNS TRIGGER AS $$
DECLARE
    locked_feed_id UUID;
BEGIN
    IF TG_TABLE_NAME = 'feed_entries' THEN
        IF NEW.curated_content_id IS NULL THEN
            RETURN NEW;
        END IF;
        -- Take a row lock on this feed_entry so a concurrent bookmark INSERT
        -- referencing the same feed_entry must wait for our commit.
        PERFORM 1 FROM feed_entries WHERE id = NEW.id FOR UPDATE;
        IF EXISTS (SELECT 1 FROM bookmarks WHERE source_feed_entry_id = NEW.id) THEN
            RAISE EXCEPTION 'feed_entries % already curated as a bookmark; cannot also set curated_content_id', NEW.id;
        END IF;
    ELSIF TG_TABLE_NAME = 'bookmarks' THEN
        IF NEW.source_feed_entry_id IS NULL THEN
            RETURN NEW;
        END IF;
        -- Lock the referenced feed_entry so concurrent feed_entries UPDATE
        -- setting curated_content_id must wait.
        SELECT id INTO locked_feed_id
            FROM feed_entries
            WHERE id = NEW.source_feed_entry_id
            FOR UPDATE;
        IF EXISTS (
            SELECT 1 FROM feed_entries
            WHERE id = NEW.source_feed_entry_id AND curated_content_id IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'feed_entries % already curated as first-party content; cannot also capture as bookmark', NEW.source_feed_entry_id;
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_feed_entries_curation_exclusion
    BEFORE INSERT OR UPDATE OF curated_content_id ON feed_entries
    FOR EACH ROW EXECUTE FUNCTION enforce_feed_entry_curation_exclusion();
COMMENT ON TRIGGER trg_feed_entries_curation_exclusion ON feed_entries
    IS 'Rejects setting curated_content_id when the feed_entry is already referenced by a bookmark.source_feed_entry_id — a feed entry is curated as EITHER first-party content OR an external bookmark, never both.';

CREATE TRIGGER trg_bookmarks_curation_exclusion
    BEFORE INSERT OR UPDATE OF source_feed_entry_id ON bookmarks
    FOR EACH ROW EXECUTE FUNCTION enforce_feed_entry_curation_exclusion();
COMMENT ON TRIGGER trg_bookmarks_curation_exclusion ON bookmarks
    IS 'Rejects setting source_feed_entry_id when the referenced feed_entry already has a curated_content_id — paired with trg_feed_entries_curation_exclusion for bidirectional enforcement.';

-- ============================================================
-- activity_events triggers — canonical audit log writers
--
-- Application code MUST set the actor identity for the current transaction via
--   SET LOCAL koopa.actor = '<agent_name>';
-- before any covered table mutation. The triggers read this via current_setting.
-- If unset, the actor defaults to 'system'.
--
-- The triggers are AFTER row triggers, so a successful mutation always produces
-- exactly one activity_events row per covered transition. Bypassing the trigger
-- requires DROP TRIGGER — there is no application path that can skip it.
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

-- bookmarks: INSERT + publication transitions
CREATE OR REPLACE FUNCTION audit_bookmarks() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, actor, payload)
        VALUES ('bookmark', NEW.id, NEW.title, NEW.slug, 'created', current_actor(),
                jsonb_build_object('is_public', NEW.is_public));
    ELSIF OLD.published_at IS DISTINCT FROM NEW.published_at AND NEW.published_at IS NOT NULL THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, actor, payload)
        VALUES ('bookmark', NEW.id, NEW.title, NEW.slug, 'published', current_actor(),
                jsonb_build_object('published_at', NEW.published_at));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_bookmarks_audit
    AFTER INSERT OR UPDATE OF published_at ON bookmarks
    FOR EACH ROW EXECUTE FUNCTION audit_bookmarks();

-- notes: INSERT audit (entity_type='note' was previously registered in the
-- entity_type CHECK but had no trigger — closing that coverage gap).
CREATE OR REPLACE FUNCTION audit_notes() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO activity_events (entity_type, entity_id, entity_title, entity_slug, change_kind, actor, payload)
    VALUES ('note', NEW.id, NEW.title, NEW.slug, 'created', current_actor(),
            jsonb_build_object('kind', NEW.kind, 'maturity', NEW.maturity));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_notes_audit
    AFTER INSERT ON notes
    FOR EACH ROW EXECUTE FUNCTION audit_notes();
COMMENT ON TRIGGER trg_notes_audit ON notes
    IS 'Writes activity_events entity_type=''note'' on INSERT. Snapshot columns carry title/slug so consumers read without JOIN.';

-- learning_attempts: INSERT audit. entity_title is resolved from learning_targets
-- at write time so the activity feed shows "solved problem X" without a live JOIN.
CREATE OR REPLACE FUNCTION audit_learning_attempts() RETURNS TRIGGER AS $$
DECLARE
    target_title TEXT;
BEGIN
    SELECT title INTO target_title FROM learning_targets WHERE id = NEW.learning_target_id;
    INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
    VALUES ('learning_attempt', NEW.id, target_title, 'created', current_actor(),
            jsonb_build_object(
                'learning_target_id', NEW.learning_target_id,
                'outcome', NEW.outcome,
                'attempt_number', NEW.attempt_number
            ));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_learning_attempts_audit
    AFTER INSERT ON learning_attempts
    FOR EACH ROW EXECUTE FUNCTION audit_learning_attempts();

-- tasks: INSERT + state transitions. INSERT must always be 'submitted' per
-- chk_tasks_state_timestamps; the 'created' event documents the submission.
CREATE OR REPLACE FUNCTION audit_tasks() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
        VALUES ('task', NEW.id, NEW.title, 'created', current_actor(),
                jsonb_build_object('state', NEW.state,
                                   'assignee', NEW.assignee, 'created_by', NEW.created_by));
    ELSIF NEW.state IS DISTINCT FROM OLD.state THEN
        INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
        VALUES ('task', NEW.id, NEW.title,
                CASE WHEN NEW.state = 'completed' THEN 'completed' ELSE 'state_changed' END,
                current_actor(),
                jsonb_build_object('from', OLD.state, 'to', NEW.state,
                                   'assignee', NEW.assignee, 'created_by', NEW.created_by));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tasks_audit
    AFTER INSERT OR UPDATE OF state ON tasks
    FOR EACH ROW EXECUTE FUNCTION audit_tasks();

-- learning_hypotheses: state transitions. entity_title is the claim (full
-- text; consumers may truncate for display).
CREATE OR REPLACE FUNCTION audit_learning_hypotheses() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
    VALUES ('learning_hypothesis', NEW.id, NEW.claim, 'state_changed', current_actor(),
            jsonb_build_object('from', OLD.state, 'to', NEW.state));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_learning_hypotheses_audit
    AFTER UPDATE OF state ON learning_hypotheses
    FOR EACH ROW
    WHEN (OLD.state IS DISTINCT FROM NEW.state)
    EXECUTE FUNCTION audit_learning_hypotheses();

-- learning_plan_entries: status transitions. entity_title is the owning
-- learning_target title for briefing legibility.
CREATE OR REPLACE FUNCTION audit_learning_plan_entries() RETURNS TRIGGER AS $$
DECLARE
    target_title TEXT;
BEGIN
    SELECT title INTO target_title FROM learning_targets WHERE id = NEW.learning_target_id;
    INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
    VALUES ('learning_plan_entry', NEW.id, target_title,
            CASE WHEN NEW.status = 'completed' THEN 'completed' ELSE 'state_changed' END,
            current_actor(),
            jsonb_build_object('from', OLD.status, 'to', NEW.status,
                               'plan_id', NEW.plan_id,
                               'learning_target_id', NEW.learning_target_id,
                               'completed_by_attempt_id', NEW.completed_by_attempt_id));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_learning_plan_entries_audit
    AFTER UPDATE OF status ON learning_plan_entries
    FOR EACH ROW
    WHEN (OLD.status IS DISTINCT FROM NEW.status)
    EXECUTE FUNCTION audit_learning_plan_entries();

-- learning_sessions: end-of-session transition. entity_title is "<domain> session"
-- since sessions have no natural title column.
CREATE OR REPLACE FUNCTION audit_learning_sessions() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO activity_events (entity_type, entity_id, entity_title, change_kind, actor, payload)
    VALUES ('learning_session', NEW.id, NEW.domain || ' session', 'completed', current_actor(),
            jsonb_build_object('domain', NEW.domain, 'session_mode', NEW.session_mode,
                               'started_at', NEW.started_at, 'ended_at', NEW.ended_at));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_learning_sessions_audit
    AFTER UPDATE OF ended_at ON learning_sessions
    FOR EACH ROW
    WHEN (OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL)
    EXECUTE FUNCTION audit_learning_sessions();

-- Note: the coupling between projects.status = 'archived' and its
-- project_profile demotion (is_public = false) is enforced in
-- internal/project.Store.UpdateStatus, not in a trigger — per the
-- trigger policy that keeps cross-aggregate side effects out of the DB.
