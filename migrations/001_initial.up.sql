CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================
-- Schema conventions
-- ============================================================
--
-- ============================================================
-- Enums
-- ============================================================

CREATE TYPE content_type AS ENUM (
    'article', 'essay', 'build-log', 'til', 'digest'
);
-- Dropped in the coordination rebuild:
--   - 'bookmark' → split out into bookmarks table (internal/bookmark)
--   - 'note'     → collided with Obsidian notes (internal/obsidian/note)
--                  and agent notes (internal/agent/note); contents was
--                  never the right home for either

CREATE TYPE content_status AS ENUM (
    'draft', 'review', 'published', 'archived'
);

CREATE TYPE source_type AS ENUM (
    'obsidian', 'notion', 'ai-generated', 'external', 'manual'
);

CREATE TYPE review_level AS ENUM (
    'auto', 'light', 'standard', 'strict'
);

CREATE TYPE review_status AS ENUM (
    'pending', 'approved', 'rejected', 'edited'
);

CREATE TYPE feed_entry_status AS ENUM (
    'unread', 'read', 'curated', 'ignored'
);

CREATE TYPE flow_status AS ENUM (
    'pending', 'running', 'completed', 'failed'
);

CREATE TYPE goal_status AS ENUM (
    'not-started', 'in-progress', 'done', 'abandoned', 'on-hold'
);

CREATE TYPE project_status AS ENUM (
    'planned', 'in-progress', 'on-hold', 'completed', 'maintained', 'archived'
);

CREATE TYPE todo_state AS ENUM (
    'inbox', 'todo', 'in_progress', 'done', 'someday'
);

CREATE TYPE agent_status AS ENUM ('active', 'retired');

CREATE TYPE agent_note_kind AS ENUM ('plan', 'context', 'reflection');

CREATE TYPE task_state AS ENUM (
    'submitted', 'working', 'completed', 'canceled'
);

CREATE TYPE message_role AS ENUM ('request', 'response');

CREATE TYPE hypothesis_state AS ENUM (
    'unverified', 'verified', 'invalidated', 'archived'
);

CREATE TYPE event_type AS ENUM (
    'note_created', 'note_updated',
    'push', 'pull_request',
    'project_update', 'todo_state_change', 'book_progress', 'goal_update',
    'todo_completed', 'content_published'
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
-- The table exists so that coordination entities (tasks.requester, tasks.assignee)
-- can maintain referential integrity to a known agent identity, and so that
-- retiring an agent leaves an auditable trace (status='retired', retired_at).
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
        CHECK (name ~ '^[a-z][a-z0-9-]*$'),
    CONSTRAINT chk_agent_display_name_not_blank
        CHECK (btrim(display_name) <> ''),
    CONSTRAINT chk_agent_platform
        CHECK (platform IN ('claude-cowork', 'claude-code', 'claude-web', 'human')),
    CONSTRAINT chk_agent_status_retired CHECK (
        (status = 'active'  AND retired_at IS NULL) OR
        (status = 'retired' AND retired_at IS NOT NULL)
    )
);

COMMENT ON TABLE agents IS 'DB projection of the Go BuiltinAgents() registry. Rows are upserted at startup by agent.SyncToTable. Capability flags are NOT stored here — authorization is enforced in Go via the agent.Authorized compile-time wrapper. FK targets for tasks.requester / tasks.assignee use ON DELETE RESTRICT so historical coordination records cannot dangle. Removed registry entries transition to status=retired rather than being deleted.';
COMMENT ON COLUMN agents.name IS 'Unique agent identifier. Used as requester/assignee in tasks and as the caller identity (as: field) in MCP tool calls. Matches the Go Agent.Name literal in BuiltinAgents(). Format: lowercase, must start with a letter, alphanumeric + hyphens (chk_agent_name_format).';
COMMENT ON COLUMN agents.display_name IS 'Human-readable label for admin UI and logs. Non-blank (chk_agent_display_name_not_blank).';
COMMENT ON COLUMN agents.platform IS 'Execution context. Closed set: claude-cowork, claude-code, claude-web, human (chk_agent_platform). Informational label — routing decisions are driven by agent registry lookups, not this column.';
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
    role       TEXT NOT NULL DEFAULT 'admin'
               CHECK (role IN ('admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_users_email_format
        CHECK (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$' AND length(email) <= 254)
);

COMMENT ON TABLE users IS 'System users. Currently single-admin only.';
COMMENT ON COLUMN users.email IS 'Login identity. Unique. Basic structural validation via chk_users_email_format (full RFC 5322 compliance is enforced at the application layer).';
COMMENT ON COLUMN users.role IS 'Single-value placeholder. Currently only admin exists. If no second role materializes by public API launch, delete this column. CHECK uses IN() syntax for easy extension.';
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
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'
               OR slug ~ '^(weakness|improvement):[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT chk_tag_name_not_blank
        CHECK (btrim(name) <> '')
);

COMMENT ON TABLE tags IS 'Canonical tag registry. Fine-grained labels (two-pointers, error-handling). Auto-extracted from obsidian notes, resolved through tag_aliases pipeline.';
COMMENT ON COLUMN tags.slug IS 'Canonical form (e.g. two-pointers, dp). Controlled vocabulary for LeetCode patterns. Format: standard slug, OR namespaced slug like weakness:state-transition / improvement:edge-cases (chk_tag_slug_format).';
COMMENT ON COLUMN tags.parent_id IS 'Hierarchical parent tag. SET NULL on parent deletion — orphaned tags remain valid.';

CREATE INDEX idx_tags_parent ON tags(parent_id);

CREATE TABLE tag_aliases (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_tag      TEXT NOT NULL UNIQUE,
    tag_id       UUID REFERENCES tags(id) ON DELETE CASCADE,
    match_method TEXT NOT NULL DEFAULT 'manual'
                 CHECK (match_method IN ('manual', 'exact', 'case-insensitive', 'unmapped', 'rejected')),
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
COMMENT ON COLUMN tag_aliases.match_method IS 'How the alias was resolved: exact, case-insensitive, manual (admin), unmapped (pending), rejected (admin declined).';
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
    status            goal_status NOT NULL DEFAULT 'not-started',
    area_id           UUID REFERENCES areas(id) ON DELETE SET NULL,
    quarter           TEXT,
    deadline          TIMESTAMPTZ,
    external_provider TEXT,
    external_ref      TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_goal_title_not_blank
        CHECK (btrim(title) <> ''),
    CONSTRAINT chk_goal_external_pair
        CHECK ((external_provider IS NULL AND external_ref IS NULL)
            OR (external_provider IS NOT NULL AND external_ref IS NOT NULL)),
    CONSTRAINT uniq_goal_external UNIQUE (external_provider, external_ref)
);

COMMENT ON TABLE goals IS
    'Planning objectives — aspirational outcomes with optional deadlines. '
    'Each goal may have milestones (progress checkpoints) and projects (execution vehicles). '
    'Milestone progress is advisory — goal status is managed manually, not auto-derived.';
COMMENT ON COLUMN goals.status IS
    'Lifecycle: not-started → in-progress → done | abandoned | on-hold. '
    'on-hold = paused but not abandoned, can resume to in-progress. '
    'abandoned = terminal, will not pursue.';
COMMENT ON COLUMN goals.area_id IS
    'PARA Area of Responsibility this goal belongs to. FK to areas. '
    'SET NULL on area deletion — goal survives unclassified. NULL = no area assigned.';
COMMENT ON COLUMN goals.quarter IS 'Target quarter (e.g. "Q1 2026"). Free-form text. NULL = no quarter assigned.';
COMMENT ON COLUMN goals.deadline IS 'Hard deadline if any. NULL = no deadline.';
COMMENT ON COLUMN goals.external_provider IS
    'External system this goal is synced from (e.g. "notion", "linear"). NULL = local-only. '
    'Replaces the previous notion_page_id field — generalised because koopa0.dev is moving away '
    'from Notion. Paired with external_ref via chk_goal_external_pair.';
COMMENT ON COLUMN goals.external_ref IS
    'Provider-specific identifier within external_provider (e.g. Notion page ID). '
    'NULL = not synced. UNIQUE per provider via uniq_goal_external.';
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
    external_provider TEXT,
    external_ref      TEXT,
    position          INT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (goal_id, title),

    CONSTRAINT chk_milestone_title_not_blank
        CHECK (btrim(title) <> ''),
    CONSTRAINT chk_milestone_external_pair
        CHECK ((external_provider IS NULL AND external_ref IS NULL)
            OR (external_provider IS NOT NULL AND external_ref IS NOT NULL)),
    CONSTRAINT uniq_milestone_external UNIQUE (external_provider, external_ref)
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
COMMENT ON COLUMN milestones.external_provider IS
    'External system this milestone is synced from (e.g. "notion"). NULL = local-only. '
    'Paired with external_ref via chk_milestone_external_pair.';
COMMENT ON COLUMN milestones.external_ref IS
    'Provider-specific identifier within external_provider. NULL = not synced. '
    'UNIQUE per provider via uniq_milestone_external.';
COMMENT ON COLUMN milestones.position IS
    'Sequence position within a goal (0-based). Convention: position is the gap-free '
    'sequence index a row holds inside its parent; sort_order is the priority tier '
    'used for top-level UI ordering. See top-of-file ordering convention block.';
COMMENT ON COLUMN milestones.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

-- ============================================================
-- Projects (after goals, before contents)
-- ============================================================

CREATE TABLE projects (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug              TEXT NOT NULL UNIQUE,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
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
    featured          BOOLEAN NOT NULL DEFAULT false,
    is_public         BOOLEAN NOT NULL DEFAULT false,
    sort_order        INT NOT NULL DEFAULT 0,
    status            project_status NOT NULL DEFAULT 'in-progress',
    external_provider TEXT,
    external_ref      TEXT,
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
        CHECK (btrim(title) <> ''),
    CONSTRAINT chk_project_github_url
        CHECK (github_url IS NULL OR github_url ~ '^https://github\.com/'),
    CONSTRAINT chk_project_live_url
        CHECK (live_url IS NULL OR live_url ~ '^https?://'),
    CONSTRAINT chk_project_external_pair
        CHECK ((external_provider IS NULL AND external_ref IS NULL)
            OR (external_provider IS NOT NULL AND external_ref IS NOT NULL)),
    CONSTRAINT uniq_project_external UNIQUE (external_provider, external_ref)
);

COMMENT ON TABLE projects IS
    'PARA projects — short-term efforts with a clear outcome. '
    'Projects and milestones are siblings under a goal: '
    'a project may advance a goal without mapping to a specific milestone. '
    'Includes portfolio/case study fields for public display.';
COMMENT ON COLUMN projects.role IS 'User role in this project (e.g. Lead Engineer, Sole Developer). NULL = not specified.';
COMMENT ON COLUMN projects.area_id IS
    'PARA Area of Responsibility. FK to areas. SET NULL on area deletion. NULL = unclassified.';
COMMENT ON COLUMN projects.repo IS 'GitHub repository full name (e.g. Koopa0/koopa0.dev). Used by activity event resolution and webhook routing.';
COMMENT ON COLUMN projects.github_url IS 'Full GitHub repository URL. NULL = no public repo.';
COMMENT ON COLUMN projects.live_url IS 'Production deployment URL. NULL = not deployed.';
COMMENT ON COLUMN projects.expected_cadence IS 'Expected development activity frequency. NULL = not set.';
COMMENT ON COLUMN projects.long_description IS 'Extended description for project detail page. NULL = use description.';
COMMENT ON COLUMN projects.problem IS 'Case study: what problem this project solves. NULL = not a case study.';
COMMENT ON COLUMN projects.solution IS 'Case study: how the problem was solved.';
COMMENT ON COLUMN projects.architecture IS 'Case study: system architecture description.';
COMMENT ON COLUMN projects.results IS 'Case study: measurable outcomes.';
COMMENT ON COLUMN projects.featured IS 'Whether to show on the public portfolio homepage.';
COMMENT ON COLUMN projects.is_public IS 'Whether this project is visible on the public website.';
COMMENT ON COLUMN projects.external_provider IS
    'External system this project is synced from (e.g. "notion"). NULL = local-only. '
    'Paired with external_ref via chk_project_external_pair.';
COMMENT ON COLUMN projects.external_ref IS
    'Provider-specific identifier within external_provider. NULL = not synced. '
    'UNIQUE per provider via uniq_project_external.';
COMMENT ON COLUMN projects.goal_id IS
    'Which goal this project serves. Nullable — a project can exist without a goal '
    '(PARA: some projects are pure Area maintenance, not goal-driven). SET NULL on goal deletion.';
COMMENT ON COLUMN projects.last_activity_at IS 'Timestamp of most recent activity event for this project. Updated by cron.';
COMMENT ON COLUMN projects.updated_at IS 'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_projects_featured ON projects(featured DESC, sort_order);
CREATE INDEX idx_projects_lower_title ON projects (LOWER(title));
CREATE INDEX idx_projects_repo ON projects (repo) WHERE repo IS NOT NULL;
CREATE INDEX idx_projects_status ON projects (status) WHERE status NOT IN ('completed', 'archived');
CREATE INDEX idx_projects_is_public ON projects (featured DESC, sort_order) WHERE is_public = true;
CREATE INDEX idx_projects_goal_id ON projects(goal_id) WHERE goal_id IS NOT NULL;
CREATE INDEX idx_projects_area ON projects (area_id) WHERE area_id IS NOT NULL;

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
    origin_ref    TEXT,
    source_type   source_type,
    series_id     TEXT,
    series_order  INT,
    review_level  review_level NOT NULL DEFAULT 'standard',
    ai_metadata   JSONB,
    reading_time_min INT NOT NULL DEFAULT 0 CHECK (reading_time_min >= 0),
    cover_image   TEXT,
    is_public     BOOLEAN NOT NULL DEFAULT true,
    project_id    UUID REFERENCES projects(id) ON DELETE SET NULL,
    published_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    embedding     vector(768),
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
        CHECK (btrim(title) <> '')
);

COMMENT ON TABLE contents IS 'Published content — the finished product. Five types share one table and one lifecycle: draft → review → published → archived.';
COMMENT ON COLUMN contents.slug IS 'URL-safe identifier. Globally unique. Used in public URLs. Format: lowercase alphanumeric segments separated by single hyphens (chk_content_slug_format).';
COMMENT ON COLUMN contents.type IS 'Content format: article, essay, build-log, til, digest. (note and bookmark removed in the coordination rebuild — they have their own dedicated tables.)';
COMMENT ON COLUMN contents.status IS 'Lifecycle: draft → review → published. archived = soft delete.';
COMMENT ON COLUMN contents.origin_ref IS 'Reference to the origin artifact — an Obsidian file path, an external URL, or NULL for manually created content. Renamed from contents.source to disambiguate from events.source (origin system) and tasks.requester (origin agent).';
COMMENT ON COLUMN contents.source_type IS 'Origin system classification (obsidian, notion, ai-generated, external, manual). Distinct from origin_ref which carries the actual identifier.';
COMMENT ON COLUMN contents.series_id IS 'Groups content into a series. Paired with series_order (chk_contents_series).';
COMMENT ON COLUMN contents.series_order IS 'Position within the series. Paired with series_id (chk_contents_series).';
COMMENT ON COLUMN contents.review_level IS 'AI review strictness: auto (publish immediately), light, standard, strict (human approval required).';
COMMENT ON COLUMN contents.reading_time_min IS 'Estimated reading time in minutes. Computed from body word count. Always >= 0.';
COMMENT ON COLUMN contents.ai_metadata IS 'AI pipeline metadata (JSONB). Structure: {summary, keywords, quality_score, review_notes}. Set by Genkit flows.';
COMMENT ON COLUMN contents.cover_image IS 'Cover image URL or path for content cards and social sharing. NULL = no cover image.';
COMMENT ON COLUMN contents.is_public IS 'Whether this content is visible on the public website. Private content is admin/MCP only.';
COMMENT ON COLUMN contents.project_id IS 'Associated project. SET NULL on project deletion — content survives independently.';
COMMENT ON COLUMN contents.published_at IS 'When content was published. NULL = not yet published.';
COMMENT ON COLUMN contents.search_vector IS
    'Generated tsvector for full-text search. Uses ''simple'' config (no stemming/language-specific '
    'tokenization) for multilingual safety. Weight A = title, C = body (first 10K chars). '
    'Semantic search via embedding compensates for tsvector recall limitations.';
COMMENT ON COLUMN contents.embedding IS 'pgvector embedding (768d) for semantic search via HNSW index.';
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
CREATE INDEX idx_contents_obsidian_slug ON contents (slug) WHERE source_type = 'obsidian';

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
-- Review queue
-- ============================================================

CREATE TABLE editorial_queue (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content_id     UUID NOT NULL REFERENCES contents(id) ON DELETE CASCADE,
    review_level   review_level NOT NULL,
    status         review_status NOT NULL DEFAULT 'pending',
    reviewer_notes TEXT,
    submitted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at    TIMESTAMPTZ,

    CONSTRAINT chk_reviewed_at_consistency
        CHECK ((status = 'pending' AND reviewed_at IS NULL)
            OR (status <> 'pending' AND reviewed_at IS NOT NULL))
);

COMMENT ON TABLE editorial_queue IS 'Content review workflow. One pending review per content (idx_editorial_queue_pending_content).';
COMMENT ON COLUMN editorial_queue.content_id IS 'References content under review. ON DELETE CASCADE — content deletion removes review record.';
COMMENT ON COLUMN editorial_queue.review_level IS
    'Snapshot of content.review_level at submission time. Does not live-update if content review_level changes.';
COMMENT ON COLUMN editorial_queue.status IS
    'Lifecycle: pending → approved | rejected | edited. chk_reviewed_at_consistency ties reviewed_at to non-pending status.';
COMMENT ON COLUMN editorial_queue.reviewer_notes IS 'Admin notes from the review. NULL = no notes.';
COMMENT ON COLUMN editorial_queue.submitted_at IS 'When this content was submitted for review.';
COMMENT ON COLUMN editorial_queue.reviewed_at IS 'When review was completed. NULL while status = pending, NOT NULL otherwise (enforced by chk_reviewed_at_consistency).';

CREATE INDEX idx_editorial_queue_status ON editorial_queue(status);
CREATE INDEX idx_editorial_queue_content_id ON editorial_queue(content_id);
CREATE UNIQUE INDEX idx_editorial_queue_pending_content ON editorial_queue (content_id) WHERE status = 'pending';

-- ============================================================
-- Feeds + feed entries (was: feeds + collected_data)
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
COMMENT ON COLUMN feeds.schedule IS 'Fetch cadence label (hourly | daily | weekly | biweekly | monthly), enforced by chk_feed_schedule. The Go scheduler maps each label to a concrete time interval. NOT a cron expression — for cron-format schedules see topic_monitors.schedule.';
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

-- Junction: feeds ↔ topics (was: feeds.topics TEXT[])
CREATE TABLE feed_topics (
    feed_id  UUID NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    topic_id UUID NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    PRIMARY KEY (feed_id, topic_id)
);

COMMENT ON TABLE feed_topics IS 'Which topics a feed covers. Replaces the old feeds.topics TEXT[] — proper FK instead of stringly-typed array.';

CREATE INDEX idx_feed_topics_topic ON feed_topics(topic_id);

CREATE TABLE feed_entries (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_url         TEXT NOT NULL,
    title              TEXT NOT NULL,
    original_content   TEXT NOT NULL DEFAULT '',
    relevance_score    DOUBLE PRECISION NOT NULL DEFAULT 0,
    status             feed_entry_status NOT NULL DEFAULT 'unread',
    curated_content_id UUID REFERENCES contents(id) ON DELETE SET NULL,
    collected_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    url_hash           TEXT NOT NULL,
    user_feedback      TEXT,
    feedback_at        TIMESTAMPTZ,
    feed_id            UUID REFERENCES feeds(id) ON DELETE SET NULL,
    published_at       TIMESTAMPTZ,

    CONSTRAINT chk_feedback_pair
        CHECK ((user_feedback IS NULL) = (feedback_at IS NULL)),
    CONSTRAINT chk_feed_entry_url_hash_format
        CHECK (url_hash ~ '^[a-f0-9]{64}$')
);

COMMENT ON TABLE feed_entries IS 'RSS feed items collected by the fetch pipeline. IMPORTANT SEMANTICS: topics are inherited from feed via feed_topics junction at QUERY TIME, not snapshot at ingestion. This means changing a feed''s topics retroactively changes all its entries'' topic associations. This is a deliberate product choice — topics represent current feed configuration, not historical classification. If historical topic tracking is needed, add feed_entry_topics snapshot table.';
COMMENT ON COLUMN feed_entries.url_hash IS 'Dedup identity — SHA256 of canonical source_url. NOT NULL — every entry must have dedup identity. Pipeline computes before INSERT.';
COMMENT ON COLUMN feed_entries.feed_id IS 'Source feed. NULL after feed deletion (SET NULL) — entries retained for curation.';
COMMENT ON COLUMN feed_entries.title IS 'Article title from the RSS feed. Raw — not cleaned or truncated.';
COMMENT ON COLUMN feed_entries.original_content IS
    'RSS entry content/summary. Stores the raw feed content (HTML or text). '
    'DEFAULT '''' — empty when feed provides no content element.';
COMMENT ON COLUMN feed_entries.source_url IS 'Original article URL.';
COMMENT ON COLUMN feed_entries.relevance_score IS 'Keyword-weighted relevance score computed by fetch pipeline. Higher = more relevant to tracked topics.';
COMMENT ON COLUMN feed_entries.status IS 'Curation lifecycle: unread → read → curated/ignored.';
COMMENT ON COLUMN feed_entries.curated_content_id IS 'If curated into a bookmark/article, references the content record. SET NULL on content deletion.';
COMMENT ON COLUMN feed_entries.collected_at IS 'When the pipeline first fetched this entry.';
COMMENT ON COLUMN feed_entries.user_feedback IS 'Admin feedback on relevance scoring quality. Used to tune scoring parameters.';
COMMENT ON COLUMN feed_entries.feedback_at IS 'When feedback was given. NULL = no feedback.';
COMMENT ON COLUMN feed_entries.published_at IS 'Original publication date from the feed. NULL if feed did not provide it.';

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
-- Topic monitors (was: tracking_topics)
-- ============================================================

CREATE TABLE topic_monitors (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    topic_id   UUID NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    keywords   TEXT[] NOT NULL DEFAULT '{}',
    sources    TEXT[] NOT NULL DEFAULT '{}',
    schedule   TEXT NOT NULL DEFAULT '0 */6 * * *',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(topic_id),

    CONSTRAINT chk_topic_monitor_schedule_not_blank
        CHECK (btrim(schedule) <> '')
);

COMMENT ON TABLE topic_monitors IS 'Active monitoring rules per topic. Keywords drive web search, schedule controls frequency. One monitor per topic max. Name comes from topics.name — not duplicated here.';
COMMENT ON COLUMN topic_monitors.keywords IS 'Search keywords for this topic. Used by monitoring pipeline to discover new content.';
COMMENT ON COLUMN topic_monitors.sources IS 'Specific source URLs or domains to monitor for this topic.';
COMMENT ON COLUMN topic_monitors.schedule IS 'Cron expression string (e.g. "0 */6 * * *"). Format validated by the Go scheduler — DB only enforces non-blank via chk_topic_monitor_schedule_not_blank. NOT a label like feeds.schedule.';

-- ============================================================
-- Flow runs (AI pipeline execution log)
-- ============================================================

CREATE TABLE flow_runs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    flow_name    TEXT NOT NULL,
    content_id   UUID REFERENCES contents(id) ON DELETE SET NULL,
    input        JSONB NOT NULL,
    output       JSONB,
    status       flow_status NOT NULL DEFAULT 'pending',
    error        TEXT,
    attempt      INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 3,
    started_at   TIMESTAMPTZ,
    ended_at     TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_max_attempts_positive
        CHECK (max_attempts > 0),
    CONSTRAINT chk_error_on_failure
        CHECK ((status = 'failed') = (error IS NOT NULL))
);

COMMENT ON TABLE flow_runs IS
    'Genkit AI flow execution records. Each row = one run of a flow. Retryable via attempt/max_attempts. '
    'RETENTION: completed/failed runs older than 90 days should be archived or deleted by retention cron.';
COMMENT ON COLUMN flow_runs.flow_name IS
    'Genkit flow identifier (e.g. classify, summarize, review). Matches Go flow registration name.';
COMMENT ON COLUMN flow_runs.content_id IS
    'Content being processed. SET NULL on content deletion — run history retained for diagnostics.';
COMMENT ON COLUMN flow_runs.input IS
    'Flow input payload (JSONB). Structure varies by flow_name.';
COMMENT ON COLUMN flow_runs.output IS
    'Flow output payload (JSONB). NULL until flow completes. Structure varies by flow_name.';
COMMENT ON COLUMN flow_runs.status IS
    'Lifecycle: pending → running → completed | failed. chk_error_on_failure ties error to failed status.';
COMMENT ON COLUMN flow_runs.error IS
    'Error message on failure. NULL on non-failed status, enforced by chk_error_on_failure.';
COMMENT ON COLUMN flow_runs.attempt IS
    'Current retry attempt (0-based). Incremented on each retry.';
COMMENT ON COLUMN flow_runs.max_attempts IS
    'Maximum retry attempts allowed. Must be > 0 (chk_max_attempts_positive).';
COMMENT ON COLUMN flow_runs.started_at IS
    'When the flow execution began. NULL if still pending.';
COMMENT ON COLUMN flow_runs.ended_at IS
    'When the flow execution completed or failed. NULL if still running or pending.';

CREATE INDEX idx_flow_runs_status ON flow_runs (status);
CREATE INDEX idx_flow_runs_retry ON flow_runs (created_at) WHERE status = 'failed';
CREATE INDEX idx_flow_runs_created_at ON flow_runs (created_at DESC);
CREATE INDEX idx_flow_runs_content_id ON flow_runs (content_id) WHERE content_id IS NOT NULL;
CREATE INDEX idx_flow_runs_dedup ON flow_runs (content_id, flow_name, status) WHERE status IN ('pending', 'running');
CREATE INDEX idx_flow_runs_completed ON flow_runs (content_id, flow_name, ended_at DESC) WHERE status = 'completed';

-- ============================================================
-- Todos (personal GTD work list — NOT inter-agent tasks)
--
-- Named todos (not tasks) to free the bare word "task" for the inter-agent
-- coordination entity (see §6.3 of docs/architecture/coordination-layer-target.md).
-- Vocabulary discipline: "task" = agent-to-agent work unit, "todo" = personal GTD item.
-- ============================================================

CREATE TABLE todos (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title             TEXT NOT NULL,
    state             todo_state NOT NULL DEFAULT 'todo',
    due               DATE,
    project_id        UUID REFERENCES projects(id) ON DELETE SET NULL,
    external_provider TEXT,
    external_ref      TEXT,
    completed_at      TIMESTAMPTZ,
    energy            TEXT CHECK (energy IN ('high', 'medium', 'low')),
    priority          TEXT CHECK (priority IN ('high', 'medium', 'low')),
    recur_interval    INT,
    recur_unit        TEXT CHECK (recur_unit IN ('days', 'weeks', 'months', 'years')),
    description       TEXT NOT NULL DEFAULT '',
    assignee          TEXT NOT NULL DEFAULT 'human' REFERENCES agents(name) ON DELETE RESTRICT,
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
            OR (recur_interval IS NOT NULL AND recur_unit IS NOT NULL AND recur_interval > 0)),
    CONSTRAINT chk_todo_external_pair
        CHECK ((external_provider IS NULL AND external_ref IS NULL)
            OR (external_provider IS NOT NULL AND external_ref IS NOT NULL)),
    CONSTRAINT uniq_todo_external UNIQUE (external_provider, external_ref)
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
COMMENT ON COLUMN todos.assignee IS 'Agent responsible for executing this todo. FK to agents. Default human. Capability enforcement is Go-side (agent.Authorize), not DB-side.';
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
CREATE INDEX idx_todos_assignee_active ON todos (assignee, state) WHERE state <> 'done';
CREATE INDEX idx_todos_created_by ON todos (created_by, created_at DESC);

-- ============================================================
-- Agent notes (was: journal)
-- Renamed for vocabulary precision: these are an agent's internal narrative log
-- (plan / context / reflection), not cross-entity "IPC". Not a coordination entity.
-- Moved before daily_plan_items so the FK can be inlined.
-- ============================================================

CREATE TABLE agent_notes (
    id         BIGSERIAL PRIMARY KEY,
    kind       agent_note_kind NOT NULL,
    author     TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    content    TEXT NOT NULL,
    metadata   JSONB,
    entry_date DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE agent_notes IS 'Agent''s internal narrative log — plans, context snapshots, reflections. Self-directed, not inter-agent coordination. Produced by a single agent across a session or day. metrics kind was removed in the coordination rebuild (no current writer).';
COMMENT ON COLUMN agent_notes.kind IS 'plan = daily plan. context = end-of-session state. reflection = retrospective review.';
COMMENT ON COLUMN agent_notes.author IS 'Which agent wrote this note. FK to agents. Renamed from "source" to disambiguate agent identity from system origin (events.source) and origin reference (contents.origin_ref).';
COMMENT ON COLUMN agent_notes.content IS 'Free-text body of the note. Markdown allowed.';
COMMENT ON COLUMN agent_notes.entry_date IS 'The logical date this note belongs to. May differ from created_at for backfilled notes.';
COMMENT ON COLUMN agent_notes.metadata IS
    'Structured metadata per kind. '
    'plan: {reasoning}. Daily todo selection is tracked in daily_plan_items, not here. '
    'context, reflection: no required metadata schema.';
COMMENT ON COLUMN agent_notes.created_at IS 'Row insertion timestamp.';

CREATE INDEX idx_agent_notes_date ON agent_notes (entry_date DESC);
CREATE INDEX idx_agent_notes_kind ON agent_notes (entry_date, kind);

CREATE TABLE daily_plan_items (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_date     DATE NOT NULL,
    todo_id       UUID NOT NULL REFERENCES todos(id) ON DELETE CASCADE,
    selected_by   TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    position      INT NOT NULL DEFAULT 0,
    reason        TEXT,
    agent_note_id BIGINT REFERENCES agent_notes(id) ON DELETE SET NULL,
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
    'Optional link to the agent_notes(kind=plan) entry that drove this planning session. '
    'All items from the same planning session share the same agent_note_id. '
    'Enables "which reasoning led to these todo selections" queries. '
    'Symmetric with sessions.agent_note_id — session produces the note, '
    'agent_note_id links back. SET NULL on note deletion.';
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
-- Todo skips (was: task_skips — renamed for vocabulary discipline)
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

COMMENT ON TABLE todo_skips IS 'Per-occurrence skip history for recurring todo items.';
COMMENT ON COLUMN todo_skips.todo_id IS 'Which recurring todo was skipped. CASCADE — skips die with their todo.';
COMMENT ON COLUMN todo_skips.original_due IS 'Due date when skip was detected by cron.';
COMMENT ON COLUMN todo_skips.skipped_date IS 'The occurrence date that was missed.';
COMMENT ON COLUMN todo_skips.reason IS 'auto-expired (cron detected overdue) or manual (user skipped).';
COMMENT ON COLUMN todo_skips.created_at IS 'Row insertion timestamp.';

-- ============================================================
-- Sources (was: notion_sources — platform-agnostic)
-- ============================================================

CREATE TABLE sync_sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id     TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    provider        TEXT NOT NULL DEFAULT 'notion'
                    CHECK (provider IN ('notion', 'linear', 'github')),
    role            TEXT CHECK (role IN ('projects', 'tasks', 'books', 'goals')),
    sync_mode       TEXT NOT NULL DEFAULT 'full'
                    CHECK (sync_mode IN ('full', 'incremental')),
    property_map    JSONB NOT NULL DEFAULT '{}',
    poll_interval   INTERVAL NOT NULL DEFAULT '15 minutes',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_synced_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE sync_sources IS
    'External data source sync configuration. Provider column distinguishes Notion, Linear, etc. '
    'UPGRADE PATH: when a second provider is added for the same role (e.g. Google Calendar for tasks), '
    'change UNIQUE(role) to UNIQUE(provider, role) to allow multiple sources per role.';
COMMENT ON COLUMN sync_sources.external_id IS 'Identifier in the external system (e.g. Notion database ID). UNIQUE — one source config per external resource.';
COMMENT ON COLUMN sync_sources.provider IS 'Which external platform this source connects to.';
COMMENT ON COLUMN sync_sources.role IS 'What kind of data this source provides. NULL = not categorized. UNIQUE partial index — one source per role.';
COMMENT ON COLUMN sync_sources.sync_mode IS 'Sync strategy: full (re-sync all), incremental (changes only).';
COMMENT ON COLUMN sync_sources.property_map IS 'Maps external properties to local fields (JSONB). Structure varies by provider and role.';
COMMENT ON COLUMN sync_sources.poll_interval IS 'How often to poll for changes. PostgreSQL INTERVAL type — DB validates format.';
COMMENT ON COLUMN sync_sources.last_synced_at IS 'Last successful sync timestamp. NULL = never synced.';
COMMENT ON COLUMN sync_sources.updated_at IS 'Application-managed. Set explicitly in UPDATE queries.';

CREATE INDEX idx_sync_sources_role_enabled ON sync_sources (role) WHERE enabled = true AND role IS NOT NULL;
CREATE INDEX idx_sync_sources_ext_enabled ON sync_sources (external_id) WHERE enabled = true;
CREATE UNIQUE INDEX idx_sync_sources_role ON sync_sources (role) WHERE role IS NOT NULL;

-- ============================================================
-- Obsidian notes — knowledge artifacts synced from an Obsidian vault
--
-- Renamed from `notes` to `obsidian_notes` so it stands in clear
-- contrast to `agent_notes` (agent narrative log). The Go package is
-- `internal/obsidian/note`. Distinct from `agent_notes` in three ways:
--   1. Source: vault file vs agent runtime
--   2. Authorship: external (Koopa typing in Obsidian) vs internal (an agent)
--   3. Lifecycle: synced from filesystem vs append-only narrative
-- ============================================================

CREATE TABLE obsidian_notes (
    id                BIGSERIAL PRIMARY KEY,
    file_path         TEXT UNIQUE NOT NULL,
    title             TEXT,
    type              TEXT,
    provenance        TEXT,
    context           TEXT,
    maturity          TEXT NOT NULL DEFAULT 'seed'
                      CHECK (maturity IN ('seed', 'evergreen', 'stub', 'archived')),
    raw_tags          JSONB,
    difficulty        TEXT CHECK (difficulty IN ('easy', 'medium', 'hard')),
    leetcode_id       INT,
    book              TEXT,
    chapter           TEXT,
    external_provider TEXT,
    external_ref      TEXT,
    content_text      TEXT,
    content_hash      TEXT,
    embedding         vector(768),
    search_vector     TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(left(content_text, 10000), '')), 'C')
    ) STORED,
    git_created_at    TIMESTAMPTZ,
    git_updated_at    TIMESTAMPTZ,
    synced_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_chapter_needs_book
        CHECK (chapter IS NULL OR book IS NOT NULL),
    CONSTRAINT chk_obsidian_note_content_hash_format
        CHECK (content_hash IS NULL OR content_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT chk_obsidian_note_external_pair
        CHECK ((external_provider IS NULL AND external_ref IS NULL)
            OR (external_provider IS NOT NULL AND external_ref IS NOT NULL))
);

COMMENT ON TABLE obsidian_notes IS
    'Knowledge artifacts synced from an Obsidian vault. Renamed from `notes` '
    'in the schema normalization pass to stand in clear contrast to agent_notes '
    '(agent narrative log). Nullable columns (title, type, provenance, context, '
    'content_text, content_hash, raw_tags) represent optional frontmatter fields '
    '— NULL means the field was absent in the source file.';
COMMENT ON COLUMN obsidian_notes.maturity IS 'Zettelkasten maturity: seed (new), stub (incomplete), evergreen (mature), archived.';
COMMENT ON COLUMN obsidian_notes.raw_tags IS 'Raw frontmatter tags (JSONB array). Ingestion snapshot — canonical mapping via obsidian_note_tags junction + tag_aliases pipeline.';
COMMENT ON COLUMN obsidian_notes.type IS 'Note type from frontmatter (e.g. leetcode, book-note, dev-log, til). Open-ended — values defined by vault conventions.';
COMMENT ON COLUMN obsidian_notes.provenance IS 'Knowledge provenance label (e.g. leetcode, claude, oreilly, ardanlabs). Renamed from `source` to disambiguate from events.source (origin system) and tasks.requester (origin agent). The sync origin (vault system) is implicit in file_path.';
COMMENT ON COLUMN obsidian_notes.context IS 'Project or domain context (e.g. project slug). QUASI-CANONICAL — comes from frontmatter (raw), but actively used by MCP search filtering and morning_context. Not FK because vault may reference projects not yet in DB. Treat as soft reference, not pure raw field.';
COMMENT ON COLUMN obsidian_notes.difficulty IS 'Problem difficulty. Primarily for LeetCode notes.';
COMMENT ON COLUMN obsidian_notes.leetcode_id IS 'LeetCode problem number. NULL for non-LeetCode notes.';
COMMENT ON COLUMN obsidian_notes.book IS 'Book title if this note is from a book reading session.';
COMMENT ON COLUMN obsidian_notes.chapter IS 'Chapter identifier within the book.';
COMMENT ON COLUMN obsidian_notes.external_provider IS
    'External system this note is associated with (e.g. "notion" for a linked Notion task). '
    'NULL = standalone vault note. Paired with external_ref via chk_obsidian_note_external_pair. '
    'Replaces the previous notion_task_id field — generalised because koopa0.dev is moving away from Notion.';
COMMENT ON COLUMN obsidian_notes.external_ref IS
    'Provider-specific identifier within external_provider. NULL = no external link.';
COMMENT ON COLUMN obsidian_notes.content_text IS 'Full text content extracted from the note file. Used for full-text search.';
COMMENT ON COLUMN obsidian_notes.content_hash IS 'SHA-256 hex of content_text (chk_obsidian_note_content_hash_format). Used for change detection during sync — skip re-processing if unchanged.';
COMMENT ON COLUMN obsidian_notes.search_vector IS
    'Generated tsvector for full-text search. Uses ''simple'' config — same rationale as contents.search_vector.';
COMMENT ON COLUMN obsidian_notes.embedding IS 'pgvector embedding (768d) for semantic search via HNSW index.';
COMMENT ON COLUMN obsidian_notes.git_created_at IS 'File creation time from git log. NULL if not tracked by git.';
COMMENT ON COLUMN obsidian_notes.git_updated_at IS 'File last modification time from git log. NULL if not tracked by git.';
COMMENT ON COLUMN obsidian_notes.synced_at IS 'When this note was last synced from the vault.';

CREATE INDEX idx_obsidian_notes_type ON obsidian_notes (type);
CREATE INDEX idx_obsidian_notes_context ON obsidian_notes (context);
CREATE INDEX idx_obsidian_notes_search ON obsidian_notes USING GIN(search_vector);
CREATE INDEX idx_obsidian_notes_embedding ON obsidian_notes USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);
CREATE INDEX idx_obsidian_notes_synced_at ON obsidian_notes(synced_at DESC);

-- Junction: obsidian_notes ↔ tags
CREATE TABLE obsidian_note_tags (
    obsidian_note_id  BIGINT NOT NULL REFERENCES obsidian_notes(id) ON DELETE CASCADE,
    tag_id            UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (obsidian_note_id, tag_id)
);

COMMENT ON TABLE obsidian_note_tags IS 'Junction: obsidian note ↔ canonical tag. Many-to-many. Tags resolved from raw_tags via tag_aliases pipeline.';

CREATE INDEX idx_obsidian_note_tags_tag ON obsidian_note_tags(tag_id);

-- Obsidian wikilink edges (knowledge graph)
CREATE TABLE obsidian_note_links (
    id              BIGSERIAL PRIMARY KEY,
    source_note_id  BIGINT NOT NULL REFERENCES obsidian_notes(id) ON DELETE CASCADE,
    target_path     TEXT NOT NULL,
    link_text       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE obsidian_note_links IS 'Wikilink edges between obsidian notes. Drives the knowledge graph API.';
COMMENT ON COLUMN obsidian_note_links.target_path IS 'Wikilink target file path. May reference notes not yet synced — forward/broken links expected.';

CREATE INDEX idx_obsidian_note_links_source ON obsidian_note_links (source_note_id);
CREATE INDEX idx_obsidian_note_links_target ON obsidian_note_links (target_path);
CREATE UNIQUE INDEX idx_obsidian_note_links_dedup ON obsidian_note_links (source_note_id, target_path);

-- ============================================================
-- Events (was: activity_events)
-- ============================================================

CREATE TABLE events (
    id          BIGSERIAL PRIMARY KEY,
    source_id   TEXT,
    timestamp   TIMESTAMPTZ NOT NULL,
    event_type  event_type NOT NULL,
    source      TEXT NOT NULL,
    project     TEXT,
    repo        TEXT,
    ref         TEXT,
    title       TEXT,
    body        TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE events IS 'Unified event log from all sources (GitHub, Notion, Obsidian sync, MCP, cron).';
COMMENT ON COLUMN events.source_id IS 'Event ID in the origin system (e.g. GitHub delivery ID). Used for dedup.';
COMMENT ON COLUMN events.event_type IS
    'Event classification. PostgreSQL ENUM — closed contract, all values defined in Go code. '
    'Adding a new event type requires ALTER TYPE ADD VALUE + Go code change. '
    'UPGRADE PATH: if event types grow significantly after Gmail/Calendar integration, '
    'consider migrating from ENUM to TEXT + CHECK for easier extensibility.';
COMMENT ON COLUMN events.source IS 'Origin system name (github, notion, obsidian, mcp, cron). NOT a participant — this is system-level.';
COMMENT ON COLUMN events.project IS 'Related project slug. Not FK — may reference projects not yet created or since renamed.';
COMMENT ON COLUMN events.repo IS 'GitHub repository full name (e.g. Koopa0/koopa0.dev).';
COMMENT ON COLUMN events.ref IS 'Git ref (branch name or tag).';
COMMENT ON COLUMN events.title IS 'Event summary (e.g. commit message, PR title, task name).';
COMMENT ON COLUMN events.body IS 'Event detail body. May contain markdown.';
COMMENT ON COLUMN events.timestamp IS
    'When the event occurred in the source system. Distinct from created_at '
    '(when the row was inserted into this DB). For webhook events, timestamp may '
    'predate created_at due to delivery delay.';
COMMENT ON COLUMN events.metadata IS 'Event-specific structured data (JSONB). GitHub: diff stats. Notion: changed fields.';

CREATE INDEX idx_events_timestamp ON events (timestamp DESC);
CREATE INDEX idx_events_project ON events (project, timestamp DESC) WHERE project IS NOT NULL;
CREATE INDEX idx_events_type ON events (event_type);
CREATE UNIQUE INDEX idx_events_dedup ON events (source, event_type, source_id) WHERE source_id IS NOT NULL;
CREATE INDEX idx_events_source_id ON events (source_id text_pattern_ops) WHERE source_id IS NOT NULL;

-- Junction: events ↔ tags (was: activity_event_tags)
CREATE TABLE event_tags (
    event_id  BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    tag_id    UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (event_id, tag_id)
);

COMMENT ON TABLE event_tags IS 'Junction: event ↔ tag. Many-to-many. Tags extracted from event metadata during ingestion.';

CREATE INDEX idx_event_tags_tag ON event_tags(tag_id);

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
COMMENT ON COLUMN project_aliases.alias IS 'Variant name (e.g. repo name, Notion title variant). Case-insensitive unique — "Koopa0.dev" and "koopa0.dev" are the same alias.';
COMMENT ON COLUMN project_aliases.project_id IS 'References canonical project. CASCADE — aliases meaningless without project.';
COMMENT ON COLUMN project_aliases.source IS 'Where this alias was discovered (e.g. github, notion, manual).';

-- Case-insensitive unique: prevents "Koopa0.dev" and "koopa0.dev" as separate aliases
CREATE UNIQUE INDEX idx_project_aliases_lower_alias ON project_aliases (LOWER(alias));

-- ============================================================
-- Coordination layer: tasks + task_messages + artifacts
--
-- Replaces the previous directives / reports pair with a unified work unit
-- modeled on A2A's Task/Message/Artifact triad. See
-- docs/architecture/coordination-layer-target.md §4-§6 for the full design.
--
-- tasks            = inter-agent work unit with an explicit lifecycle ENUM
-- task_messages    = ordered request/response conversation turns, multi-part body
-- artifacts        = structured deliverables, separate from conversation messages
--
-- Read-side bloat prevention uses three independent gates:
--   1. Go type system — TaskSummary has no content fields (compile-time)
--   2. Database       — chk_parts_count + chk_parts_total_size on task_messages
--   3. API contract   — distinct Summarize() and Load() methods, no options
-- ============================================================

CREATE TABLE tasks (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester    TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    assignee     TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    title        TEXT NOT NULL,
    state        task_state NOT NULL DEFAULT 'submitted',
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    accepted_at  TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    canceled_at  TIMESTAMPTZ,
    metadata     JSONB NOT NULL DEFAULT '{}',

    CONSTRAINT chk_task_title_not_blank
        CHECK (btrim(title) <> ''),
    CONSTRAINT chk_tasks_no_self_assignment
        CHECK (requester <> assignee),
    CONSTRAINT chk_tasks_state_timestamps CHECK (
        (state = 'submitted' AND accepted_at IS NULL     AND completed_at IS NULL     AND canceled_at IS NULL) OR
        (state = 'working'   AND accepted_at IS NOT NULL AND completed_at IS NULL     AND canceled_at IS NULL) OR
        (state = 'completed' AND accepted_at IS NOT NULL AND completed_at IS NOT NULL AND canceled_at IS NULL) OR
        (state = 'canceled'  AND canceled_at IS NOT NULL AND completed_at IS NULL)
    )
);

COMMENT ON TABLE tasks IS
    'Inter-agent coordination work units (NOT personal GTD todos — those live in todos). '
    'One requester agent asks one assignee agent to do work. Lifecycle: submitted → working → completed | canceled. '
    'chk_tasks_state_timestamps makes illegal state/timestamp combinations physically impossible at the DB layer, '
    'independent of any Go-side validation. Conversation history is stored in task_messages; '
    'structured deliverables in artifacts. A completed task must have at least one response message AND '
    'at least one artifact — enforced by Go transition logic (Store.Complete), not by DB CHECK, '
    'because the multi-table invariant cannot be expressed as a single-row constraint.';
COMMENT ON COLUMN tasks.requester IS 'Agent that submitted the task. FK to agents — historical references never dangle. Renamed from "source" to align with A2A vocabulary and disambiguate from events.source (origin system).';
COMMENT ON COLUMN tasks.assignee IS 'Agent expected to perform the work. FK to agents. Renamed from "target" to align with A2A vocabulary.';
COMMENT ON COLUMN tasks.title IS 'Short human-readable task label. Non-blank (chk_task_title_not_blank).';
COMMENT ON COLUMN tasks.state IS 'Lifecycle state. Four values: submitted (created, not yet accepted), working (assignee accepted, in flight), completed (response + artifact delivered), canceled (requester canceled). Failed/rejected/input_required are deferred — no current handler produces them.';
COMMENT ON COLUMN tasks.submitted_at IS 'When the requester created this task. DEFAULT now() — always set at insertion time.';
COMMENT ON COLUMN tasks.accepted_at IS 'When the assignee transitioned the task to working. NULL iff state=submitted or canceled-from-submitted (enforced by chk_tasks_state_timestamps).';
COMMENT ON COLUMN tasks.completed_at IS 'When the assignee delivered the final response+artifact. NULL unless state=completed.';
COMMENT ON COLUMN tasks.canceled_at IS 'When the requester canceled the task. NULL unless state=canceled. Mutually exclusive with completed_at.';
COMMENT ON COLUMN tasks.metadata IS 'Non-routing task info: deadline, priority hint, correlation keys. JSONB for flexibility; promote fields to columns when query patterns demand it. TODO(coordination): when query patterns stabilise, promote deadline and correlation_id to first-class columns.';

CREATE INDEX idx_tasks_assignee_open
    ON tasks (assignee, submitted_at DESC)
    WHERE state IN ('submitted', 'working');

CREATE INDEX idx_tasks_requester_open
    ON tasks (requester, submitted_at DESC)
    WHERE state IN ('submitted', 'working');

CREATE INDEX idx_tasks_state ON tasks (state);

-- ============================================================
-- task_messages: request/response conversation turns
--
-- Parts are stored as a JSONB array. Each element is an a2a.Part value
-- (github.com/a2aproject/a2a-go/v2/a2a) serialized via its MarshalJSON —
-- the flattened form: {"text": "..."} or {"data": {...}}. The Go layer never
-- hand-rolls this format. See docs/architecture/coordination-layer-target.md §16.
--
-- chk_parts_count + chk_parts_total_size are DB-side bloat prevention.
-- Anything that would exceed these must be stored as an artifact instead.
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
COMMENT ON COLUMN task_messages.role IS 'request = message from requester to assignee. response = message from assignee back to requester. Two values only; system messages are deferred until a real use case appears.';
COMMENT ON COLUMN task_messages.position IS 'Order within a task conversation, 0-based. UNIQUE(task_id, position) prevents duplicates and out-of-order inserts.';
COMMENT ON COLUMN task_messages.parts IS 'JSONB array of a2a.Part values in a2a-go''s flattened format. Each part is {"text": "..."} or {"data": {...}}. Serialized/deserialized by a2a-go — Go code never hand-rolls this shape.';
COMMENT ON COLUMN task_messages.created_at IS 'Row insertion timestamp.';

CREATE INDEX idx_task_messages_task ON task_messages (task_id, position);

-- ============================================================
-- artifacts: structured task deliverables
--
-- Looser size bounds than messages (32 parts max, 256 KB total): artifacts
-- are expected to be bigger than conversation messages, but still bounded.
-- Anything above 256 KB belongs in external object storage with a reference
-- part — that path is deferred until a real case shows up.
-- ============================================================

CREATE TABLE artifacts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id     UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
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
    )
);

COMMENT ON TABLE artifacts IS 'Structured deliverables produced by the target agent during or after task work. Separate from conversation messages because deliverables (research reports, document outputs) have an independent lifetime. Size bounds (32 parts, 256 KB) are looser than task_messages bounds.';
COMMENT ON COLUMN artifacts.task_id IS 'Parent task. CASCADE — artifacts die with their task.';
COMMENT ON COLUMN artifacts.name IS 'Short label identifying this artifact (e.g. "weekly-report", "architecture-diagram").';
COMMENT ON COLUMN artifacts.description IS 'Optional longer description. Empty string = no description.';
COMMENT ON COLUMN artifacts.parts IS 'JSONB array of a2a.Part values (same format as task_messages.parts). Stores the actual deliverable content.';
COMMENT ON COLUMN artifacts.created_at IS 'Row insertion timestamp.';

CREATE INDEX idx_artifacts_task ON artifacts (task_id, created_at);

-- ============================================================
-- Hypotheses (was: insights)
--
-- Falsifiable hypothesis tracker — records a one-line prediction plus the
-- condition that would invalidate it, then accumulates evidence over time.
-- Not a coordination entity, but kept next to tasks because the hypothesis
-- lifecycle was historically tangled with "insight" IPC messaging.
-- ============================================================

CREATE TABLE hypotheses (
    id                     BIGSERIAL PRIMARY KEY,
    author                 TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    content                TEXT NOT NULL,
    state                  hypothesis_state NOT NULL DEFAULT 'unverified',
    claim                  TEXT NOT NULL,
    invalidation_condition TEXT NOT NULL,
    metadata               JSONB,
    observed_date          DATE NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE hypotheses IS 'Falsifiable hypothesis tracker (was: insights). Each row carries a one-line falsifiable claim plus the invalidation condition that would disprove it. Evidence accumulates in metadata over time until the state transitions to verified or invalidated.';
COMMENT ON COLUMN hypotheses.author IS 'Which agent recorded the hypothesis. FK to agents. Renamed from "source" to align with agent_notes.author and disambiguate agent identity from system origin.';
COMMENT ON COLUMN hypotheses.content IS 'Full narrative context. The claim column is the one-line prediction; content is the supporting analysis and evidence.';
COMMENT ON COLUMN hypotheses.state IS 'Lifecycle: unverified → verified | invalidated → archived.';
COMMENT ON COLUMN hypotheses.claim IS 'One-line falsifiable prediction. Renamed from "hypothesis" to avoid the hypotheses.hypothesis stutter.';
COMMENT ON COLUMN hypotheses.invalidation_condition IS 'What would disprove the claim. Required — a hypothesis without an invalidation condition is not falsifiable and should not be recorded.';
COMMENT ON COLUMN hypotheses.metadata IS 'supporting_evidence, counter_evidence, conclusion, category, project, tags. Promote fields to columns when query patterns demand it.';
COMMENT ON COLUMN hypotheses.observed_date IS 'Date the hypothesis was first observed or recorded.';
COMMENT ON COLUMN hypotheses.created_at IS 'Row insertion timestamp.';

CREATE INDEX idx_hypotheses_state ON hypotheses (state);
CREATE INDEX idx_hypotheses_date ON hypotheses (observed_date DESC);

-- ============================================================
-- Learning analytics: concepts, items, sessions, attempts
--
-- Adds attempt tracking, concept ontology, weakness diagnosis,
-- variation-aware recommendation, and session orchestration.
--
-- The previous schema handles "what I learned" (notes, contents)
-- and "when to review" (FSRS). This extension answers "why am I
-- weak at binary search", "which attempts support that judgment",
-- and "what should I practice next".
--
-- review_cards is defined AFTER items so it can
-- directly reference both contents(id) and items(id).
-- ============================================================

-- Concepts: learning ontology (independent from tags)
--
-- Tags handle canonical labeling and content classification.
-- Concepts handle learning ontology, mastery tracking, and
-- weakness diagnosis. Not all tags are concepts. Not all
-- concepts have corresponding tags. When both exist,
-- concepts.tag_id bridges them.

CREATE TABLE concepts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL,
    name        TEXT NOT NULL,
    domain      TEXT NOT NULL
               CHECK (domain = lower(btrim(domain)) AND domain <> ''),
    kind        TEXT NOT NULL CHECK (kind IN ('pattern', 'skill', 'principle')),
    parent_id   UUID REFERENCES concepts(id) ON DELETE SET NULL,
    tag_id      UUID REFERENCES tags(id) ON DELETE SET NULL,
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
    'Learning domain: leetcode, japanese, system-design, go, english, reading, etc. '
    'Go-validated convention, not DB-enforced — domains expand as new learning areas '
    'are added. Deviation from schema-design.md CHECK rule is deliberate: domain set '
    'is open-ended and cross-cutting.';
COMMENT ON COLUMN concepts.kind IS
    'Concept classification. '
    'pattern: strategic framework (two-pointers, binary-search, sliding-window). '
    'skill: practicable ability (constraint-analysis, edge-case-handling). '
    'principle: theoretical foundation (amortized analysis, CAP theorem, N3 grammar). '
    '"knowledge" was rejected to avoid semantic overlap with notes.';
COMMENT ON COLUMN concepts.parent_id IS
    'Self-referencing hierarchy. Pattern "binary-search" → skill "recognize binary '
    'search on rotated array". SET NULL on parent deletion — children become roots. '
    'Acyclicity enforced by application, not database. '
    'Same-domain invariant: parent and child must share the same domain — '
    'cross-domain parenting is a data quality error, enforced by Go validation.';
COMMENT ON COLUMN concepts.tag_id IS
    'Optional cross-reference to the canonical tag system. When both a concept and '
    'a tag exist for the same thing, this FK bridges content classification (tag-based) '
    'and learning analytics (concept-based). SET NULL on tag deletion. '
    'Cardinality: many-to-one is intentional — multiple concepts across different domains '
    'may bridge to the same canonical tag (e.g. leetcode/binary-search and '
    'system-design/binary-search both link to tag binary-search).';
COMMENT ON COLUMN concepts.description IS
    'Optional elaboration. Empty string default — not nullable.';
COMMENT ON COLUMN concepts.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries.';

CREATE UNIQUE INDEX idx_concepts_domain_slug ON concepts (domain, LOWER(slug));
CREATE INDEX idx_concepts_domain_kind ON concepts (domain, kind);
CREATE INDEX idx_concepts_parent ON concepts (parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX idx_concepts_tag ON concepts (tag_id) WHERE tag_id IS NOT NULL;

-- Learning items: learning targets
--
-- Things to be learned, practiced, and revisited. Independent of
-- notes (knowledge artifacts). A LeetCode problem exists before
-- you write a note about it. A book chapter exists before you do
-- a reading session.

CREATE TABLE learning_targets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain      TEXT NOT NULL
               CHECK (domain = lower(btrim(domain)) AND domain <> ''),
    title       TEXT NOT NULL,
    external_id TEXT,
    difficulty  TEXT CHECK (difficulty IN ('easy', 'medium', 'hard')),
    obsidian_note_id BIGINT REFERENCES obsidian_notes(id) ON DELETE SET NULL,
    content_id  UUID REFERENCES contents(id) ON DELETE SET NULL,
    project_id  UUID REFERENCES projects(id) ON DELETE SET NULL,
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE learning_targets IS
    'Learning targets — what to learn, practice, and revisit. Lifecycle differs from '
    'notes: items follow not-attempted → practicing → mastered (learning progress), '
    'while notes follow seed → evergreen → archived (knowledge maturity). Items exist '
    'before notes are written.';
COMMENT ON COLUMN learning_targets.domain IS
    'Learning domain (same convention as concepts.domain). Go-validated, not DB-enforced.';
COMMENT ON COLUMN learning_targets.title IS
    'Display title. LeetCode: problem name. Reading: chapter title. '
    'Japanese: grammar point or drill name.';
COMMENT ON COLUMN learning_targets.external_id IS
    'Provider-specific identifier. LeetCode problem number, textbook section ID, '
    'JLPT grammar point ID. NULL for custom drills without external identity. '
    'Partial unique: one item per (domain, external_id) where external_id IS NOT NULL.';
COMMENT ON COLUMN learning_targets.difficulty IS
    'Generic 3-tier difficulty. Domain-specific info (JLPT N5-N1, etc.) goes in metadata. '
    'NULL = not categorized. Consistent with notes.difficulty CHECK.';
COMMENT ON COLUMN learning_targets.obsidian_note_id IS
    'Optional link to the item-level summary note (e.g. a LeetCode solve note). '
    'Distinct from learning_attempts.obsidian_note_id which links to an attempt-level working note. '
    'SET NULL on note deletion — the item persists without its note.';
COMMENT ON COLUMN learning_targets.content_id IS
    'Rare — for when a published article/essay is itself a learning target. '
    'Most items will not have this. SET NULL on content deletion.';
COMMENT ON COLUMN learning_targets.project_id IS
    'Optional PARA project association for catalog-level grouping. '
    'Plan membership and ordering is tracked via plan_items, not this FK. '
    'SET NULL on project deletion — the item persists without its project.';
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
CREATE INDEX idx_learning_targets_domain ON learning_targets (domain);
CREATE INDEX idx_learning_targets_obsidian_note ON learning_targets (obsidian_note_id) WHERE obsidian_note_id IS NOT NULL;
CREATE INDEX idx_learning_targets_project ON learning_targets (project_id) WHERE project_id IS NOT NULL;
CREATE INDEX idx_learning_targets_content ON learning_targets (content_id) WHERE content_id IS NOT NULL;

-- ============================================================
-- Spaced repetition: review_cards + review_logs
--
-- Placed after items so both FK targets (contents, items)
-- exist at definition time. No ALTER TABLE needed.
-- ============================================================

CREATE TABLE review_cards (
    id                 BIGSERIAL PRIMARY KEY,
    content_id         UUID REFERENCES contents(id) ON DELETE CASCADE,
    learning_target_id UUID REFERENCES learning_targets(id) ON DELETE CASCADE,
    tag_id             UUID REFERENCES tags(id) ON DELETE CASCADE,
    card_state         JSONB NOT NULL,
    due                TIMESTAMPTZ NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_review_target_exactly_one
        CHECK (num_nonnulls(content_id, learning_target_id) = 1),
    CONSTRAINT chk_tag_requires_content
        CHECK (tag_id IS NULL OR content_id IS NOT NULL),
    CONSTRAINT chk_review_card_state_not_empty
        CHECK (card_state <> '{}'::jsonb AND card_state <> 'null'::jsonb)
);

COMMENT ON TABLE review_cards IS
    'Spaced repetition card state. Algorithm-agnostic — currently FSRS. '
    'Two target types: content-based (article/note recall) and learning-item-based '
    '(problem/drill retention). Exactly one of content_id or learning_target_id must be '
    'NOT NULL, enforced by chk_review_target_exactly_one. FSRS engine is target-agnostic — '
    'it operates on (card_state, rating) → new_card_state regardless of target type.';
COMMENT ON COLUMN review_cards.content_id IS
    'Content-based review target. NULL when this card targets a learning item. '
    'Mutually exclusive with learning_target_id (checked by chk_review_target_exactly_one). '
    'CASCADE — deleting the content deletes its review cards.';
COMMENT ON COLUMN review_cards.learning_target_id IS
    'Learning-item-based review target (problem, drill, chapter). NULL when this card '
    'targets content. Mutually exclusive with content_id. '
    'CASCADE — deleting the item deletes its review cards.';
COMMENT ON COLUMN review_cards.tag_id IS
    'Canonical tag for per-concept review within content-based cards. NULL = whole-content '
    'review. Only meaningful when content_id IS NOT NULL, enforced by chk_tag_requires_content. '
    'CASCADE on tag deletion — SET NULL would risk violating idx_review_cards_content_whole '
    'unique constraint if a whole-content card already exists for the same content. '
    'Application layer should warn before tag deletion (FSRS state is lost).';
COMMENT ON COLUMN review_cards.card_state IS
    'Serialized algorithm state (Due, Stability, Difficulty, Reps, Lapses). Opaque to SQL.';
COMMENT ON COLUMN review_cards.due IS
    'Denormalized from card_state for index-based due-date queries.';
COMMENT ON COLUMN review_cards.updated_at IS
    'Application-managed. Set explicitly in UPDATE queries (after FSRS review).';

-- Content-based cards: two partial indexes.
-- One whole-content card per content (tag_id IS NULL).
-- One card per (content, tag) pair (tag_id IS NOT NULL).
CREATE UNIQUE INDEX idx_review_cards_content_whole
    ON review_cards (content_id) WHERE content_id IS NOT NULL AND tag_id IS NULL;
CREATE UNIQUE INDEX idx_review_cards_content_tagged
    ON review_cards (content_id, tag_id) WHERE content_id IS NOT NULL AND tag_id IS NOT NULL;

-- Learning-item-based cards: one card per item.
CREATE UNIQUE INDEX idx_review_cards_item
    ON review_cards (learning_target_id) WHERE learning_target_id IS NOT NULL;

CREATE INDEX idx_review_cards_due ON review_cards (due);

CREATE TABLE review_logs (
    id             BIGSERIAL PRIMARY KEY,
    card_id        BIGINT NOT NULL REFERENCES review_cards(id) ON DELETE CASCADE,
    rating         INT NOT NULL CHECK (rating BETWEEN 1 AND 4),
    scheduled_days INT NOT NULL CHECK (scheduled_days >= 0),
    elapsed_days   INT NOT NULL CHECK (elapsed_days >= 0),
    state          INT NOT NULL CHECK (state BETWEEN 0 AND 3),
    reviewed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE review_logs IS 'Append-only review history. One row per review event.';
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
    'Junction: which concepts a learning item exercises. A LeetCode problem''s primary '
    'concept is two-pointers; secondary might include hash-map. CASCADE on both sides — '
    'deleting an item or concept removes the association.';
COMMENT ON COLUMN learning_target_concepts.relevance IS
    'primary: the core concept this item drills. '
    'secondary: a supporting concept also exercised. '
    'Convention: one primary per item. Multiple primaries should be rare; '
    'if frequent, revisit the relevance model.';

CREATE INDEX idx_learning_target_concepts_concept ON learning_target_concepts (concept_id);

-- Learning sessions: orchestration boundary
--
-- A session has explicit start/end, a mode, and contains
-- multiple attempts. Distinct from agent_notes (post-hoc narrative log).
-- The session produces an agent_note entry, not the other way around.
--
-- No agent column: personal scale = always Koopa. Agent identity is
-- traceable via agent_note_id → agent_notes.author if needed.

CREATE TABLE learning_sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain              TEXT NOT NULL
                        CHECK (domain = lower(btrim(domain)) AND domain <> ''),
    session_mode        TEXT NOT NULL
                        CHECK (session_mode IN ('retrieval', 'practice', 'mixed', 'review', 'reading')),
    agent_note_id       BIGINT REFERENCES agent_notes(id) ON DELETE SET NULL,
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
COMMENT ON COLUMN learning_sessions.domain IS
    'Learning domain for this session (same convention as concepts.domain).';
COMMENT ON COLUMN learning_sessions.session_mode IS
    'retrieval: recall-based testing (no hints). '
    'practice: active problem-solving with coaching. '
    'mixed: combination of retrieval and practice. '
    'review: revisiting previously solved items. '
    'reading: comprehension-focused (DDIA, O''Reilly, literary texts).';
COMMENT ON COLUMN learning_sessions.agent_note_id IS
    'Optional link to the reflection agent_notes entry written after the session. '
    'The session produces the note, not the other way around. '
    'SET NULL on note deletion.';
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

-- Attempts: individual learning attempt records
--
-- One learning item can have multiple attempts (first try,
-- revisit, re-practice). Each attempt records outcome,
-- duration, approach, and where you got stuck.
--
-- outcome has two paradigms:
--   problem-solving: solved_independent, solved_with_hint,
--     solved_after_solution (LeetCode, grammar drills)
--   immersive: completed, completed_with_support
--     (reading, listening, literary analysis)
--   shared: incomplete, gave_up (work across both)

CREATE TABLE learning_attempts (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    learning_target_id UUID NOT NULL REFERENCES learning_targets(id) ON DELETE CASCADE,
    session_id        UUID REFERENCES learning_sessions(id) ON DELETE SET NULL,
    attempt_number    INT NOT NULL DEFAULT 1,
    outcome           TEXT NOT NULL
                      CHECK (outcome IN (
                          'solved_independent', 'solved_with_hint',
                          'solved_after_solution',
                          'completed', 'completed_with_support',
                          'incomplete', 'gave_up')),
    duration_minutes  INT,
    stuck_at          TEXT,
    approach_used     TEXT,
    obsidian_note_id  BIGINT REFERENCES obsidian_notes(id) ON DELETE SET NULL,
    metadata          JSONB NOT NULL DEFAULT '{}',
    attempted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_attempt_number_positive CHECK (attempt_number >= 1),
    CONSTRAINT chk_duration_positive CHECK (duration_minutes IS NULL OR duration_minutes > 0)
);

COMMENT ON TABLE learning_attempts IS
    'Individual learning attempt records. One learning item can have multiple attempts '
    '(first try, revisit, re-practice). CASCADE from items — deleting an item '
    'deletes its attempt history. No is_revisit column — derivable as attempt_number > 1. '
    'Append-only — no updated_at.';
COMMENT ON COLUMN learning_attempts.learning_target_id IS
    'The learning target attempted. CASCADE — attempts are meaningless without their item.';
COMMENT ON COLUMN learning_attempts.session_id IS
    'Optional link to the session this attempt occurred in. NULL for ad-hoc attempts '
    'outside a formal session. SET NULL on session deletion.';
COMMENT ON COLUMN learning_attempts.attempt_number IS
    'Nth attempt at this item. 1 = first try, 2+ = revisit. Application must compute '
    'MAX(attempt_number) + 1 before inserting — DEFAULT 1 only applies to first attempts. '
    'UNIQUE with learning_target_id enforces no duplicate numbering.';
COMMENT ON COLUMN learning_attempts.outcome IS
    'Two outcome paradigms coexist in this column. '
    'Problem-solving (LeetCode, drills): solved_independent (no help), '
    'solved_with_hint (nudge needed), solved_after_solution (saw answer first). '
    'Immersive (reading, listening, literary analysis): completed (finished independently), '
    'completed_with_support (needed dictionary, subtitles, translation, Claude annotation). '
    'Shared across both: incomplete (partially done), gave_up (could not proceed). '
    'MCP tool layer maps domain context to the appropriate paradigm.';
COMMENT ON COLUMN learning_attempts.duration_minutes IS
    'Time spent on this attempt in minutes. NULL = not tracked. Must be positive.';
COMMENT ON COLUMN learning_attempts.stuck_at IS
    'Free-text: where you got stuck. High cardinality, not a queryable category.';
COMMENT ON COLUMN learning_attempts.approach_used IS
    'Free-text: what method you used. Coaching context, not a queryable enum.';
COMMENT ON COLUMN learning_attempts.obsidian_note_id IS
    'Optional link to an attempt-level working note. Distinct from learning_targets.obsidian_note_id '
    '(item-level summary). SET NULL on note deletion.';
COMMENT ON COLUMN learning_attempts.metadata IS
    'Narrative data: coaching hints given, alternative approaches considered, code quality '
    'observations, LLM transcript excerpts. Not queryable — stays in JSONB. '
    'If a field needs WHERE/JOIN/GROUP BY, promote to a column.';
COMMENT ON COLUMN learning_attempts.attempted_at IS
    'When this attempt occurred. May differ from created_at if backfilled.';

CREATE UNIQUE INDEX idx_learning_attempts_item_number ON learning_attempts (learning_target_id, attempt_number);
CREATE INDEX idx_learning_attempts_item_date ON learning_attempts (learning_target_id, attempted_at DESC);
CREATE INDEX idx_learning_attempts_session ON learning_attempts (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_learning_attempts_date ON learning_attempts (attempted_at DESC);

-- Attempt observations: weakness / improvement / mastery signals
--
-- The heart of learning analytics. Each observation connects
-- an attempt to a concept with a typed signal. Powers the
-- drill-down weakness UI and progression tracking.

CREATE TABLE learning_attempt_observations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attempt_id  UUID NOT NULL REFERENCES learning_attempts(id) ON DELETE CASCADE,
    concept_id  UUID NOT NULL REFERENCES concepts(id) ON DELETE RESTRICT,
    signal_type TEXT NOT NULL CHECK (signal_type IN ('weakness', 'improvement', 'mastery')),
    category    TEXT NOT NULL,
    severity    TEXT CHECK (severity IN ('minor', 'moderate', 'critical')),
    detail      TEXT,
    confidence  TEXT NOT NULL DEFAULT 'high' CHECK (confidence IN ('high', 'low')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_severity_weakness_only
        CHECK (signal_type = 'weakness' OR severity IS NULL)
);

COMMENT ON TABLE learning_attempt_observations IS
    'Micro-cognitive signals observed during a specific attempt on a specific concept. '
    'Powers weakness overview, progression tracking, and drill-down UI. '
    'Append-only — no updated_at. CASCADE from attempts, RESTRICT from concepts.';
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
    'Observation dimension. Go-validated convention, not DB ENUM — categories expand across '
    'domains. LeetCode: pattern-recognition, constraint-analysis, edge-cases, implementation, '
    'complexity-analysis, approach-selection. Japanese: conjugation-accuracy, particle-selection, '
    'listening-comprehension, vocabulary-recall. System Design: tradeoff-analysis, '
    'bottleneck-diagnosis, capacity-estimation.';
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
    'Directed graph of learning target relationships. Direction: anchor is the reference '
    'point, related is the other target, relation_type describes how related relates to '
    'anchor. Example: (anchor=42, related=167, easier_variant) means "167 is an easier '
    'variant of 42." CASCADE on both sides. Append-only — no updated_at. '
    'APPLICATION INVARIANT: contradictory pairs (e.g. same ordered pair with both '
    'easier_variant and harder_variant) and symmetric conflicts (e.g. mutual prerequisite) '
    'are not DDL-enforced — Go validation must prevent them during post-session analysis. '
    'Same-domain invariant: both targets must share the same domain — enforced by Go, not DB.';
COMMENT ON COLUMN learning_target_relations.anchor_id IS
    'The reference target (e.g. the one you struggled with). CASCADE on deletion. '
    'Renamed from source_item_id to avoid colliding with the table''s own "learning_target" semantics.';
COMMENT ON COLUMN learning_target_relations.related_id IS
    'The other target related to the anchor (e.g. the easier variant to try). CASCADE on deletion. '
    'Renamed from target_item_id for the same reason.';
COMMENT ON COLUMN learning_target_relations.relation_type IS
    'How the related target relates to the anchor. '
    'easier_variant: related is simpler (same concept, lower difficulty). '
    'harder_variant: related is more complex. '
    'prerequisite: related should be done before anchor '
    '(e.g. anchor=hard_problem, related=easy_problem, prerequisite = '
    '"do easy_problem before attempting hard_problem"). '
    'follow_up: related is a natural next step after anchor. '
    'same_pattern: related uses the same core pattern. '
    'similar_structure: related has structural similarity (different pattern).';

CREATE UNIQUE INDEX idx_learning_target_relations_triple
    ON learning_target_relations (anchor_id, related_id, relation_type);
CREATE INDEX idx_learning_target_relations_anchor ON learning_target_relations (anchor_id);
CREATE INDEX idx_learning_target_relations_related ON learning_target_relations (related_id);

-- ============================================================
-- Telemetry: tool_call_logs REMOVED (2026-04-04)
-- MCP tool call telemetry offloaded to Loki structured logging + Prometheus metrics.
-- Zero FK dependencies, unbounded append-only growth, views did full-table scans.
-- Grafana dashboards replace tool_usage_summary and tool_daily_trend views.
-- ============================================================

-- ============================================================
-- Reconciliation
-- ============================================================

CREATE TABLE drift_check_runs (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at          TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ,
    obsidian_missing    INT NOT NULL DEFAULT 0,
    obsidian_orphaned   INT NOT NULL DEFAULT 0,
    notion_proj_missing INT NOT NULL DEFAULT 0,
    notion_proj_orphan  INT NOT NULL DEFAULT 0,
    notion_goal_missing INT NOT NULL DEFAULT 0,
    notion_goal_orphan  INT NOT NULL DEFAULT 0,
    total_drift         INT NOT NULL DEFAULT 0,
    error_count         INT NOT NULL DEFAULT 0,
    errors              JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE drift_check_runs IS 'Weekly reconciliation run history for system health and drift trend analysis.';
COMMENT ON COLUMN drift_check_runs.started_at IS 'When the reconciliation run began.';
COMMENT ON COLUMN drift_check_runs.completed_at IS 'NULL until run finishes. NULL + old started_at = crashed run.';
COMMENT ON COLUMN drift_check_runs.obsidian_missing IS 'Notes in Obsidian vault but not yet synced to DB.';
COMMENT ON COLUMN drift_check_runs.obsidian_orphaned IS 'Notes in DB but file no longer exists in Obsidian vault.';
COMMENT ON COLUMN drift_check_runs.notion_proj_missing IS 'Projects in Notion but not yet synced to DB.';
COMMENT ON COLUMN drift_check_runs.notion_proj_orphan IS 'Projects in DB but no longer in Notion source.';
COMMENT ON COLUMN drift_check_runs.notion_goal_missing IS 'Goals in Notion but not yet synced to DB.';
COMMENT ON COLUMN drift_check_runs.notion_goal_orphan IS 'Goals in DB but no longer in Notion source.';
COMMENT ON COLUMN drift_check_runs.total_drift IS 'Sum of all missing+orphaned counts. Zero = fully consistent.';
COMMENT ON COLUMN drift_check_runs.error_count IS 'Number of errors encountered during the run. 0 = clean run.';
COMMENT ON COLUMN drift_check_runs.errors IS 'JSON array of error strings from the run. NULL when error_count=0.';

CREATE INDEX idx_drift_check_runs_started ON drift_check_runs(started_at DESC);

-- ============================================================
-- Agent schedule run history (was: schedule_runs)
--
-- Schedule DEFINITIONS now live in the Go BuiltinAgents() literal under
-- internal/agent/registry.go — the old participant_schedules table is dropped.
-- Only the run audit log remains, keyed by a string <agent_name>:<schedule_name>
-- pair produced by the Go dispatcher. There is no FK — Go validates the name
-- against the registry before insert.
-- ============================================================

CREATE TABLE agent_schedule_runs (
    id            BIGSERIAL PRIMARY KEY,
    schedule_name TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('success', 'failure', 'skipped')),
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at      TIMESTAMPTZ,
    error         TEXT,
    metadata      JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_agent_schedule_run_error_on_failure
        CHECK (status = 'failure' OR error IS NULL)
);

COMMENT ON TABLE agent_schedule_runs IS 'Append-only execution history for agent-owned schedules. Schedule definitions live in the Go registry (BuiltinAgents), not in a DB table — schedule_name here is the "<agent>:<schedule>" composite key produced by the dispatcher. No FK: Go validates the name against the registry before insert.';
COMMENT ON COLUMN agent_schedule_runs.schedule_name IS 'Composite key "<agent_name>:<schedule_name>" from the Go registry. Free text at the DB layer — historical rows survive registry edits without dangling.';
COMMENT ON COLUMN agent_schedule_runs.status IS 'success = run completed without execution error. failure = errored. skipped = missed-run policy decided to skip. Note: success does not guarantee expected outputs were produced — output completeness is a separate monitoring concern.';
COMMENT ON COLUMN agent_schedule_runs.started_at IS 'When the scheduled run began.';
COMMENT ON COLUMN agent_schedule_runs.ended_at IS
    'When the run finished. NULL = still running or crashed. '
    'NULL + old started_at = abandoned/crashed run (same pattern as sessions.ended_at).';
COMMENT ON COLUMN agent_schedule_runs.error IS 'Error details on failure. NULL on success/skip, enforced by chk_agent_schedule_run_error_on_failure.';
COMMENT ON COLUMN agent_schedule_runs.metadata IS 'Run-specific data: produced task IDs, execution duration, backend-specific info.';
COMMENT ON COLUMN agent_schedule_runs.created_at IS 'Row insertion timestamp.';

CREATE INDEX idx_agent_schedule_runs_name ON agent_schedule_runs (schedule_name, started_at DESC);
CREATE INDEX idx_agent_schedule_runs_status ON agent_schedule_runs (status, started_at DESC);

-- ============================================================
-- Learning plans: ordered, mutable curricula linking plans to items
-- ============================================================

CREATE TABLE learning_plans (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    domain       TEXT NOT NULL
                 CHECK (domain = lower(btrim(domain)) AND domain <> ''),
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
    'set of learning items. Plans serve aspirations (goals), not execution vehicles '
    '(projects). Status lifecycle: draft → active → completed/paused/abandoned. '
    'Draft = workspace/uncommitted. Active = committed curriculum being tracked '
    'against execution.';
COMMENT ON COLUMN learning_plans.id IS
    'Primary key. Auto-generated UUID.';
COMMENT ON COLUMN learning_plans.title IS
    'Display title (e.g., "LeetCode 200 題計畫"). Not unique — allows v1/v2 scenarios.';
COMMENT ON COLUMN learning_plans.description IS
    'Plan description, strategy notes. Empty string = no description.';
COMMENT ON COLUMN learning_plans.domain IS
    'Learning domain (same convention as concepts.domain). Go-validated, not DB-enforced.';
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
    CONSTRAINT chk_substituted_by_requires_status
        CHECK (substituted_by IS NULL OR status = 'substituted'),
    CONSTRAINT chk_completed_at_requires_status
        CHECK (completed_at IS NULL OR status = 'completed'),
    CONSTRAINT chk_completed_by_attempt_requires_status
        CHECK (completed_by_attempt_id IS NULL OR status = 'completed')
);

CREATE INDEX idx_learning_plan_entries_plan ON learning_plan_entries (plan_id, position);
CREATE INDEX idx_learning_plan_entries_target ON learning_plan_entries (learning_target_id);
CREATE INDEX idx_learning_plan_entries_phase ON learning_plan_entries (plan_id, phase) WHERE phase IS NOT NULL;
CREATE INDEX idx_learning_plan_entries_status ON learning_plan_entries (plan_id, status);
CREATE INDEX idx_learning_plan_entries_attempt ON learning_plan_entries (completed_by_attempt_id)
    WHERE completed_by_attempt_id IS NOT NULL;

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
    'Ordering within the plan (0-based). NOT unique in DB — application invariant '
    'maintains uniqueness. Follows milestones and daily_plan_items pattern.';
COMMENT ON COLUMN learning_plan_entries.status IS
    'Plan-item lifecycle: planned → completed (via explicit tool call after successful '
    'attempt) | skipped (plan decision to not do it) | substituted (replaced by another '
    'item). Distinct from attempt.outcome — plan_status is a plan-domain decision, not '
    'an execution result.';
COMMENT ON COLUMN learning_plan_entries.phase IS
    'Optional grouping label within the plan (e.g., "1-arrays", "phase-2-trees"). '
    'Free-text with kebab-case validation enforced in Go, not DB. NULL = no phase grouping.';
COMMENT ON COLUMN learning_plan_entries.substituted_by IS
    'If status=''substituted'', points to the plan_items.id of the replacement '
    'item WITHIN THE SAME PLAN. NULL for non-substituted items. SET NULL if replacement '
    'item is deleted.';
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
-- curate = publish (no editorial review), no editorial_queue,
-- different RSS output. See internal/bookmark package.

CREATE TABLE bookmarks (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url                  TEXT NOT NULL,
    url_hash             TEXT NOT NULL,
    slug                 TEXT NOT NULL,
    title                TEXT NOT NULL,
    excerpt              TEXT NOT NULL DEFAULT '',
    note                 TEXT NOT NULL DEFAULT '',
    source_type          TEXT NOT NULL
        CHECK (source_type IN ('rss', 'manual', 'shared')),
    source_feed_entry_id UUID REFERENCES feed_entries(id) ON DELETE SET NULL,
    curated_by           TEXT NOT NULL REFERENCES agents(name) ON DELETE RESTRICT,
    curated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_public            BOOLEAN NOT NULL DEFAULT true,
    published_at         TIMESTAMPTZ,
    embedding            vector(768),
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

COMMENT ON TABLE bookmarks IS 'External resources curated with personal commentary. Separate from contents because bookmarks skip editorial review (curate = publish), have an external canonical URL, and do not share the first-party publish workflow.';
COMMENT ON COLUMN bookmarks.url IS 'Canonical external URL of the bookmarked resource. Must use http(s) scheme (chk_bookmark_url_scheme). SEO canonical tag points to this value.';
COMMENT ON COLUMN bookmarks.url_hash IS 'SHA-256 hex digest of the canonical URL (chk_bookmark_url_hash_format — exactly 64 hex chars). Dedup identity. Computed in application code before INSERT — matches feed_entries.url_hash semantics.';
COMMENT ON COLUMN bookmarks.slug IS 'URL-safe internal identifier for bookmark permalinks on the koopa0.dev site (chk_bookmark_slug_format). Distinct from the external URL.';
COMMENT ON COLUMN bookmarks.title IS 'Display title. May override the source title if the curator edited it at capture time. Non-blank (chk_bookmark_title_not_blank).';
COMMENT ON COLUMN bookmarks.excerpt IS 'Short excerpt from the source, typically truncated to a few sentences. Empty string when the source provided none.';
COMMENT ON COLUMN bookmarks.note IS 'Curator''s personal commentary. The reason this bookmark is worth remembering. Empty string when no note.';
COMMENT ON COLUMN bookmarks.source_type IS 'How the bookmark entered the system: rss (curated from feed_entries), manual (pasted by curator), shared (received via external channel).';
COMMENT ON COLUMN bookmarks.source_feed_entry_id IS 'If source_type=rss, references the originating feed_entries row. NULL for manual/shared bookmarks. SET NULL on feed_entry deletion — bookmark survives independently.';
COMMENT ON COLUMN bookmarks.curated_by IS 'Agent that curated the bookmark. FK to agents with ON DELETE RESTRICT — historical curation references never dangle, matching the same FK strategy as todos.assignee, agent_notes.author, hypotheses.author, etc.';
COMMENT ON COLUMN bookmarks.curated_at IS 'When the bookmark was curated into koopa0.dev. Distinct from source publication date.';
COMMENT ON COLUMN bookmarks.is_public IS 'Whether this bookmark is visible on the public website. Private bookmarks are admin/MCP only.';
COMMENT ON COLUMN bookmarks.published_at IS 'When the bookmark became publicly visible. NULL = private or not yet published. Unlike contents, bookmarks typically have published_at = curated_at.';
COMMENT ON COLUMN bookmarks.embedding IS 'pgvector embedding (768d) for semantic search inclusion. Optional — backfill may leave NULL for rows whose source content was never embedded.';

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
