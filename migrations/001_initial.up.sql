-- koopa0.dev schema v2 — full rewrite (2026-04-02)
-- All naming, structure, and normalization decisions from:
--   docs/SCHEMA-AUDIT-2026-04-02.md
--   docs/Ipc protocol decision doc final.md
--
-- Three principles governing every column:
--   1. Raw ingestion vs canonical truth?
--      Raw = plain TEXT, no CHECK. Canonical = ENUM or FK or CHECK.
--      Quasi-canonical (raw input actively used for query/filter) = plain TEXT + COMMENT marking it.
--   2. Closed contract vs evolving taxonomy?
--      Closed (Go-defined, stable) = CREATE TYPE ENUM.
--      Evolving (may add values) = TEXT CHECK (...).
--      Open (external input) = plain TEXT.
--   3. Absence = NULL, never empty string.
--      NULL means "not set / not applicable". '' is never a valid absence marker.

CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================
-- Enums
-- ============================================================

CREATE TYPE content_type AS ENUM (
    'article', 'essay', 'build-log', 'til', 'note', 'bookmark', 'digest'
);

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
    'not-started', 'in-progress', 'done', 'abandoned'
);

CREATE TYPE project_status AS ENUM (
    'planned', 'in-progress', 'on-hold', 'completed', 'maintained', 'archived'
);

CREATE TYPE task_status AS ENUM (
    'todo', 'in-progress', 'done'
);

CREATE TYPE event_type AS ENUM (
    'note_created', 'note_updated',
    'push', 'pull_request',
    'project_update', 'task_status_change', 'book_progress', 'goal_update',
    'task_completed', 'content_published',
    'my_day_incomplete'
);

-- ============================================================
-- Identity model: platform → participant
-- ============================================================

CREATE TABLE platform (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE platform IS 'AI environment or human context. Each platform hosts one or more participants (projects/agents).';
COMMENT ON COLUMN platform.name IS 'Platform identifier: claude-cowork, claude-code, claude-web, human.';

INSERT INTO platform(name, description) VALUES
    ('claude-cowork', 'Claude Desktop Cowork — multi-project virtual studio'),
    ('claude-code', 'Claude Code CLI — development agent'),
    ('claude-web', 'Claude Web — general conversation'),
    ('human', 'Direct human operation');

CREATE TABLE participant (
    name        TEXT PRIMARY KEY,
    platform    TEXT NOT NULL REFERENCES platform(name),
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE participant IS 'An actor in the system — a Cowork project, a Claude Code project, or a human operator. Platform determines the context.';
COMMENT ON COLUMN participant.name IS 'Unique identifier used as source/target in messages and assignee in tasks.';
COMMENT ON COLUMN participant.platform IS 'Which platform this participant belongs to. Determines communication capabilities.';

INSERT INTO participant(name, platform, description) VALUES
    ('hq', 'claude-cowork', 'Studio HQ — CEO, decisions, delegation'),
    ('content-studio', 'claude-cowork', 'Content strategy, writing, publishing'),
    ('research-lab', 'claude-cowork', 'Deep research, structured reports'),
    ('learning-studio', 'claude-cowork', 'LeetCode coaching, spaced repetition'),
    ('koopa0.dev', 'claude-code', 'koopa0.dev development project'),
    ('go-spec', 'claude-code', 'Go spec configuration project'),
    ('claude', 'claude-web', 'General Claude Web session'),
    ('human', 'human', 'Koopa — direct manual operation');

-- ============================================================
-- Core domain: topics, tags, users
-- ============================================================

CREATE TABLE users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      TEXT NOT NULL UNIQUE,
    role       TEXT NOT NULL DEFAULT 'admin'
               CHECK (role IN ('admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON COLUMN users.role IS 'Single-value placeholder. Currently only admin exists. If no second role materializes by public API launch, delete this column. CHECK uses IN() syntax for easy extension.';

CREATE TABLE refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

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
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tags (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    parent_id   UUID REFERENCES tags(id) ON DELETE SET NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tags_parent ON tags(parent_id);

CREATE TABLE tag_aliases (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_tag      TEXT NOT NULL UNIQUE,
    tag_id       UUID REFERENCES tags(id) ON DELETE CASCADE,
    match_method TEXT NOT NULL DEFAULT 'manual'
                 CHECK (match_method IN ('manual', 'exact', 'case-insensitive', 'unmapped', 'rejected')),
    confirmed    BOOLEAN NOT NULL DEFAULT false,
    confirmed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tag_aliases_tag ON tag_aliases(tag_id);
CREATE INDEX idx_tag_aliases_confirmed ON tag_aliases(confirmed);
CREATE INDEX idx_tag_aliases_lower_raw_tag ON tag_aliases (LOWER(raw_tag));

-- ============================================================
-- Goals (before projects, projects FK to goals)
-- ============================================================

CREATE TABLE goals (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title          TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    status         goal_status NOT NULL DEFAULT 'not-started',
    area           TEXT,
    quarter        TEXT,
    deadline       TIMESTAMPTZ,
    notion_page_id TEXT UNIQUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON COLUMN goals.quarter IS 'Format: "Q1 2026" or "2026-Q1". No CHECK — values from Notion upstream.';
COMMENT ON COLUMN goals.area IS 'PARA methodology Area — long-term responsibility domain (e.g. Backend, Learning, Studio).';

CREATE INDEX idx_goals_lower_title ON goals (LOWER(title));

-- ============================================================
-- Projects (after goals, before contents)
-- ============================================================

CREATE TABLE projects (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug             TEXT NOT NULL UNIQUE,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    long_description TEXT,
    role             TEXT,
    tech_stack       TEXT[] NOT NULL DEFAULT '{}',
    highlights       TEXT[] NOT NULL DEFAULT '{}',
    problem          TEXT,
    solution         TEXT,
    architecture     TEXT,
    results          TEXT,
    github_url       TEXT,
    live_url         TEXT,
    featured         BOOLEAN NOT NULL DEFAULT false,
    is_public        BOOLEAN NOT NULL DEFAULT false,
    sort_order       INT NOT NULL DEFAULT 0,
    status           project_status NOT NULL DEFAULT 'in-progress',
    notion_page_id   TEXT UNIQUE,
    repo             TEXT,
    area             TEXT,
    goal_id          UUID REFERENCES goals(id) ON DELETE SET NULL,
    deadline         TIMESTAMPTZ,
    last_activity_at TIMESTAMPTZ,
    expected_cadence TEXT CHECK (expected_cadence IN ('daily', 'weekly', 'biweekly', 'monthly')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON COLUMN projects.role IS 'User role in this project (e.g. Lead Engineer, Sole Developer).';
COMMENT ON COLUMN projects.area IS 'PARA methodology Area — long-term responsibility domain (e.g. Backend, Learning, Studio).';
COMMENT ON COLUMN projects.repo IS 'GitHub repository full name (e.g. Koopa0/koopa0.dev). Used by activity event resolution.';
COMMENT ON COLUMN projects.github_url IS 'Full GitHub repository URL.';
COMMENT ON COLUMN projects.live_url IS 'Production deployment URL.';
COMMENT ON COLUMN projects.expected_cadence IS 'Expected development activity frequency. NULL = not set.';

CREATE INDEX idx_projects_featured ON projects(featured DESC, sort_order);
CREATE INDEX idx_projects_lower_title ON projects (LOWER(title));
CREATE INDEX idx_projects_repo ON projects (repo) WHERE repo IS NOT NULL;
CREATE INDEX idx_projects_status ON projects (status) WHERE status NOT IN ('completed', 'archived');
CREATE INDEX idx_projects_is_public ON projects (featured DESC, sort_order) WHERE is_public = true;
CREATE INDEX idx_projects_goal_id ON projects(goal_id) WHERE goal_id IS NOT NULL;

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
    source        TEXT,
    source_type   source_type,
    series_id     TEXT,
    series_order  INT,
    review_level  review_level NOT NULL DEFAULT 'standard',
    ai_metadata   JSONB,
    reading_time_min INT NOT NULL DEFAULT 0,
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
    )
);

COMMENT ON COLUMN contents.reading_time_min IS 'Estimated reading time in minutes. Computed from body word count. Always >= 0.';
COMMENT ON COLUMN contents.ai_metadata IS 'AI pipeline metadata (JSONB). Structure: {summary, keywords, quality_score, review_notes}. Set by Genkit flows.';
COMMENT ON COLUMN contents.is_public IS 'Whether this content is visible on the public website. Private content is admin/MCP only.';
COMMENT ON COLUMN contents.source IS 'Origin identifier — Obsidian file path, external URL, or NULL for manually created content.';
COMMENT ON COLUMN contents.source_type IS 'Origin system classification. Different dimension from participant — this is WHERE content came from, not WHO created it.';

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

CREATE TABLE review_queue (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content_id     UUID NOT NULL REFERENCES contents(id) ON DELETE CASCADE,
    review_level   review_level NOT NULL,
    status         review_status NOT NULL DEFAULT 'pending',
    reviewer_notes TEXT,
    submitted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at    TIMESTAMPTZ
);

COMMENT ON COLUMN review_queue.content_id IS 'References content under review. ON DELETE CASCADE — content deletion removes review record.';

CREATE INDEX idx_review_queue_status ON review_queue(status);
CREATE INDEX idx_review_queue_content_id ON review_queue(content_id);
CREATE UNIQUE INDEX idx_review_queue_pending_content ON review_queue (content_id) WHERE status = 'pending';

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
    etag                 TEXT NOT NULL DEFAULT '',
    last_modified        TEXT NOT NULL DEFAULT '',
    last_fetched_at      TIMESTAMPTZ,
    consecutive_failures INT NOT NULL DEFAULT 0,
    last_error           TEXT NOT NULL DEFAULT '',
    disabled_reason      TEXT NOT NULL DEFAULT '',
    filter_config        JSONB NOT NULL DEFAULT '{}',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON COLUMN feeds.filter_config IS 'Feed-specific filter rules (JSONB). Structure: {deny_paths, deny_title_patterns, deny_tags}. Empty {} = no filtering.';

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
    published_at       TIMESTAMPTZ
);

COMMENT ON TABLE feed_entries IS 'RSS feed items collected by the fetch pipeline. IMPORTANT SEMANTICS: topics are inherited from feed via feed_topics junction at QUERY TIME, not snapshot at ingestion. This means changing a feed''s topics retroactively changes all its entries'' topic associations. This is a deliberate product choice — topics represent current feed configuration, not historical classification. If historical topic tracking is needed, add feed_entry_topics snapshot table.';
COMMENT ON COLUMN feed_entries.url_hash IS 'Dedup identity — SHA256 of canonical source_url. NOT NULL — every entry must have dedup identity. Pipeline computes before INSERT.';
COMMENT ON COLUMN feed_entries.feed_id IS 'Source feed. NULL after feed deletion (SET NULL) — entries retained for curation.';
COMMENT ON COLUMN feed_entries.curated_content_id IS 'If curated into a bookmark/article, references the content record.';

CREATE INDEX idx_feed_entries_status ON feed_entries(status);
CREATE INDEX idx_feed_entries_relevance ON feed_entries(relevance_score DESC);
CREATE UNIQUE INDEX idx_feed_entries_url_hash ON feed_entries (url_hash);
CREATE INDEX idx_feed_entries_feed_id ON feed_entries (feed_id) WHERE feed_id IS NOT NULL;
CREATE INDEX idx_feed_entries_collected_at ON feed_entries (collected_at DESC);
CREATE INDEX idx_feed_entries_unread_at ON feed_entries (collected_at DESC) WHERE status = 'unread';

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
    UNIQUE(topic_id)
);

COMMENT ON TABLE topic_monitors IS 'Active monitoring rules per topic. Keywords drive web search, schedule controls frequency. One monitor per topic max.';
COMMENT ON COLUMN topic_monitors.keywords IS 'Search keywords for this topic. Used by monitoring pipeline to discover new content.';
COMMENT ON COLUMN topic_monitors.sources IS 'Specific source URLs or domains to monitor for this topic.';

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
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE flow_runs IS 'Genkit AI flow execution records. Each row = one run of a flow. Retryable via attempt/max_attempts.';

CREATE INDEX idx_flow_runs_status ON flow_runs (status);
CREATE INDEX idx_flow_runs_retry ON flow_runs (created_at) WHERE status = 'failed';
CREATE INDEX idx_flow_runs_created_at ON flow_runs (created_at DESC);
CREATE INDEX idx_flow_runs_content_id ON flow_runs (content_id) WHERE content_id IS NOT NULL;
CREATE INDEX idx_flow_runs_dedup ON flow_runs (content_id, flow_name, status) WHERE status IN ('pending', 'running');
CREATE INDEX idx_flow_runs_completed ON flow_runs (content_id, flow_name, ended_at DESC) WHERE status = 'completed';

-- ============================================================
-- Tasks
-- ============================================================

CREATE TABLE tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title           TEXT NOT NULL,
    status          task_status NOT NULL DEFAULT 'todo',
    due             DATE,
    project_id      UUID REFERENCES projects(id) ON DELETE SET NULL,
    notion_page_id  TEXT UNIQUE,
    completed_at    TIMESTAMPTZ,
    energy          TEXT CHECK (energy IN ('high', 'medium', 'low')),
    priority        TEXT CHECK (priority IN ('high', 'medium', 'low')),
    recur_interval  INT,
    recur_unit      TEXT CHECK (recur_unit IN ('days', 'weeks', 'months', 'years')),
    my_day          BOOLEAN NOT NULL DEFAULT false,
    description     TEXT NOT NULL DEFAULT '',
    assignee        TEXT NOT NULL DEFAULT 'human' REFERENCES participant(name),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_completed_at_consistency
        CHECK ((status = 'done' AND completed_at IS NOT NULL)
            OR (status <> 'done' AND completed_at IS NULL)),
    CONSTRAINT chk_recurrence_pair
        CHECK ((recur_interval IS NULL AND recur_unit IS NULL)
            OR (recur_interval IS NOT NULL AND recur_unit IS NOT NULL AND recur_interval > 0))
);

COMMENT ON COLUMN tasks.energy IS 'Required energy level. NULL = not set.';
COMMENT ON COLUMN tasks.priority IS 'Task priority. NULL = not set.';
COMMENT ON COLUMN tasks.recur_unit IS 'Recurrence unit. NULL = non-recurring task.';
COMMENT ON COLUMN tasks.assignee IS 'Who executes this task. FK to participant. Default human. Seed data in 001 must include participant(human).';
COMMENT ON COLUMN tasks.updated_at IS 'Set explicitly by application in UPDATE queries. No trigger — application-managed.';

CREATE INDEX idx_tasks_status ON tasks (status) WHERE status != 'done';
CREATE INDEX idx_tasks_project ON tasks (project_id) WHERE project_id IS NOT NULL;
CREATE INDEX idx_tasks_completed ON tasks (completed_at) WHERE status = 'done';
CREATE INDEX idx_tasks_my_day ON tasks (my_day) WHERE my_day = true AND status != 'done';

-- ============================================================
-- Task skips (was: task_skip_log)
-- ============================================================

CREATE TABLE task_skips (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id      UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    original_due DATE NOT NULL,
    skipped_date DATE NOT NULL,
    reason       TEXT NOT NULL DEFAULT 'auto-expired'
        CHECK (reason IN ('auto-expired', 'manual')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(task_id, skipped_date)
);

COMMENT ON TABLE task_skips IS 'Per-occurrence skip history for recurring tasks.';
COMMENT ON COLUMN task_skips.original_due IS 'Due date when skip was detected by cron.';
COMMENT ON COLUMN task_skips.skipped_date IS 'The occurrence date that was missed.';
COMMENT ON COLUMN task_skips.reason IS 'auto-expired (cron detected overdue) or manual (user skipped).';

-- ============================================================
-- Sources (was: notion_sources — platform-agnostic)
-- ============================================================

CREATE TABLE sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id     TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    provider        TEXT NOT NULL DEFAULT 'notion'
                    CHECK (provider IN ('notion', 'linear', 'github')),
    role            TEXT CHECK (role IN ('projects', 'tasks', 'books', 'goals')),
    sync_mode       TEXT NOT NULL DEFAULT 'full',
    property_map    JSONB NOT NULL DEFAULT '{}',
    poll_interval   TEXT NOT NULL DEFAULT '15 minutes',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_synced_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE sources IS 'External data source sync configuration. Platform-agnostic — provider column distinguishes Notion, Linear, etc.';
COMMENT ON COLUMN sources.provider IS 'Which external platform this source connects to.';
COMMENT ON COLUMN sources.property_map IS 'Maps external properties to local fields (JSONB). Structure varies by provider and role.';

CREATE INDEX idx_sources_role_enabled ON sources (role) WHERE enabled = true AND role IS NOT NULL;
CREATE INDEX idx_sources_ext_enabled ON sources (external_id) WHERE enabled = true;
CREATE UNIQUE INDEX idx_sources_role ON sources (role) WHERE role IS NOT NULL;

-- ============================================================
-- Notes (was: obsidian_notes — platform-agnostic)
-- ============================================================

CREATE TABLE notes (
    id              BIGSERIAL PRIMARY KEY,
    file_path       TEXT UNIQUE NOT NULL,
    title           TEXT,
    type            TEXT,
    source          TEXT,
    context         TEXT,
    maturity        TEXT NOT NULL DEFAULT 'seed'
                    CHECK (maturity IN ('seed', 'evergreen', 'stub', 'archived')),
    raw_tags        JSONB,
    difficulty      TEXT CHECK (difficulty IN ('easy', 'medium', 'hard')),
    leetcode_id     INT,
    book            TEXT,
    chapter         TEXT,
    notion_task_id  TEXT,
    content_text    TEXT,
    content_hash    TEXT,
    embedding       vector(768),
    search_vector   TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(left(content_text, 10000), '')), 'C')
    ) STORED,
    git_created_at  TIMESTAMPTZ,
    git_updated_at  TIMESTAMPTZ,
    synced_at       TIMESTAMPTZ DEFAULT now()
);

COMMENT ON TABLE notes IS 'Knowledge notes synced from external vaults. Platform-agnostic — source column indicates origin (obsidian, logseq, etc).';
COMMENT ON COLUMN notes.maturity IS 'Zettelkasten maturity: seed (new), stub (incomplete), evergreen (mature), archived.';
COMMENT ON COLUMN notes.raw_tags IS 'Raw frontmatter tags (JSONB array). Ingestion snapshot — canonical mapping via note_tags junction + tag_aliases pipeline.';
COMMENT ON COLUMN notes.type IS 'Note type from frontmatter (e.g. leetcode, book-note, dev-log, til, note). Open-ended — values defined by vault conventions.';
COMMENT ON COLUMN notes.source IS 'Knowledge source context (e.g. leetcode, claude, oreilly, ardanlabs). Not the sync platform — that is the vault system.';
COMMENT ON COLUMN notes.context IS 'Project or domain context (e.g. project slug). QUASI-CANONICAL — comes from frontmatter (raw), but actively used by MCP search filtering and morning_context. Not FK because vault may reference projects not yet in DB. Treat as soft reference, not pure raw field.';
COMMENT ON COLUMN notes.difficulty IS 'Problem difficulty. Primarily for LeetCode notes.';

CREATE INDEX idx_notes_type ON notes (type);
CREATE INDEX idx_notes_context ON notes (context);
CREATE INDEX idx_notes_search ON notes USING GIN(search_vector);
CREATE INDEX idx_notes_embedding ON notes USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);
CREATE INDEX idx_notes_synced_at ON notes(synced_at DESC);

-- Junction: notes ↔ tags (was: obsidian_note_tags)
CREATE TABLE note_tags (
    note_id  BIGINT NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
    tag_id   UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (note_id, tag_id)
);

CREATE INDEX idx_note_tags_tag ON note_tags(tag_id);

-- Note wikilink edges (knowledge graph)
CREATE TABLE note_links (
    id              BIGSERIAL PRIMARY KEY,
    source_note_id  BIGINT NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
    target_path     TEXT NOT NULL,
    link_text       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE note_links IS 'Wikilink edges between notes. Drives the knowledge graph API.';
COMMENT ON COLUMN note_links.target_path IS 'Wikilink target file path. May reference notes not yet synced — forward/broken links expected.';

CREATE INDEX idx_note_links_source ON note_links (source_note_id);
CREATE INDEX idx_note_links_target ON note_links (target_path);
CREATE UNIQUE INDEX idx_note_links_dedup ON note_links (source_note_id, target_path);

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
COMMENT ON COLUMN events.event_type IS 'Event classification. PostgreSQL ENUM — closed contract, all values defined in Go code. Adding a new event type requires ALTER TYPE + Go code change.';
COMMENT ON COLUMN events.source IS 'Origin system name (github, notion, obsidian, mcp, cron). NOT a participant — this is system-level.';
COMMENT ON COLUMN events.project IS 'Related project slug. Not FK — may reference projects not yet created or since renamed.';
COMMENT ON COLUMN events.repo IS 'GitHub repository full name (e.g. Koopa0/koopa0.dev).';
COMMENT ON COLUMN events.ref IS 'Git ref (branch name or tag).';

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

CREATE INDEX idx_event_tags_tag ON event_tags(tag_id);

-- ============================================================
-- Project aliases
-- ============================================================

CREATE TABLE project_aliases (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alias      TEXT NOT NULL UNIQUE,
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    source     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON COLUMN project_aliases.project_id IS 'References canonical project. CASCADE — aliases meaningless without project.';

CREATE INDEX idx_project_aliases_lower_alias ON project_aliases (LOWER(alias));

-- ============================================================
-- IPC: messages (was: session_notes WHERE note_type IN ('directive','report'))
-- ============================================================

CREATE TABLE messages (
    id              BIGSERIAL PRIMARY KEY,
    kind            TEXT NOT NULL CHECK (kind IN ('directive', 'report')),
    source          TEXT NOT NULL REFERENCES participant(name),
    target          TEXT REFERENCES participant(name),
    priority        TEXT CHECK (priority IN ('p0', 'p1', 'p2')),
    in_response_to  BIGINT REFERENCES messages(id),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT REFERENCES participant(name),
    content         TEXT NOT NULL,
    metadata        JSONB,
    note_date       DATE NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_directive_fields
        CHECK (kind <> 'directive' OR (target IS NOT NULL AND priority IS NOT NULL)),
    CONSTRAINT chk_report_no_priority
        CHECK (kind <> 'report' OR priority IS NULL),
    CONSTRAINT chk_no_self_target
        CHECK (target IS NULL OR source <> target),
    CONSTRAINT chk_response_only_report
        CHECK (in_response_to IS NULL OR kind = 'report'),
    CONSTRAINT chk_ack_pair
        CHECK ((acknowledged_at IS NULL AND acknowledged_by IS NULL)
            OR (acknowledged_at IS NOT NULL AND acknowledged_by IS NOT NULL)),
    CONSTRAINT chk_ack_only_directive
        CHECK (acknowledged_at IS NULL OR kind = 'directive'),
    CONSTRAINT chk_ack_must_be_target
        CHECK (acknowledged_by IS NULL OR acknowledged_by = target)
);

COMMENT ON TABLE messages IS 'IPC layer — cross-project directives and reports. PostgreSQL is the message bus.';
COMMENT ON COLUMN messages.kind IS 'directive = HQ instruction to department. report = department output back to HQ.';
COMMENT ON COLUMN messages.target IS 'Recipient participant. Required for directives. Go layer validates target.platform = claude-cowork (only Cowork projects can receive directives). Optional for reports.';
COMMENT ON COLUMN messages.priority IS 'p0 = immediate, p1 = today, p2 = this week. Required for directives.';
COMMENT ON COLUMN messages.in_response_to IS 'Causal link — which directive this report responds to. Nullable for self-initiated reports.';
COMMENT ON COLUMN messages.acknowledged_at IS 'When the target picked up this directive. NULL = unacknowledged. Only directives can be acknowledged (chk_ack_only_directive).';
COMMENT ON COLUMN messages.acknowledged_by IS 'Which participant acknowledged. Must equal target (chk_ack_must_be_target). Go layer validates platform = claude-cowork.';
COMMENT ON COLUMN messages.metadata IS 'Non-routing info: correlation_id (server-generated UUID for thread tracking), deadline, tags, context_refs.';

CREATE INDEX idx_messages_date ON messages (note_date DESC);
CREATE INDEX idx_messages_kind ON messages (note_date, kind);

-- ============================================================
-- IPC: journal (was: session_notes WHERE note_type IN ('plan','context','reflection','metrics'))
-- ============================================================

CREATE TABLE journal (
    id         BIGSERIAL PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('plan', 'context', 'reflection', 'metrics')),
    source     TEXT NOT NULL REFERENCES participant(name),
    content    TEXT NOT NULL,
    metadata   JSONB,
    note_date  DATE NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE journal IS 'Session log — plans, context snapshots, reflections, metrics. Self-directed, not cross-project.';
COMMENT ON COLUMN journal.kind IS 'plan = daily plan. context = end-of-session state. reflection = review. metrics = quantitative snapshot.';
COMMENT ON COLUMN journal.metadata IS 'plan: {reasoning, committed_task_ids, committed_items}. metrics: {tasks_planned, tasks_completed, adjustments}.';

CREATE INDEX idx_journal_date ON journal (note_date DESC);
CREATE INDEX idx_journal_kind ON journal (note_date, kind);

-- ============================================================
-- IPC: insights (was: session_notes WHERE note_type = 'insight')
-- ============================================================

CREATE TABLE insights (
    id                       BIGSERIAL PRIMARY KEY,
    source                   TEXT NOT NULL REFERENCES participant(name),
    content                  TEXT NOT NULL,
    status                   TEXT NOT NULL DEFAULT 'unverified'
                             CHECK (status IN ('unverified', 'verified', 'invalidated', 'archived')),
    hypothesis               TEXT NOT NULL,
    invalidation_condition   TEXT NOT NULL,
    metadata                 JSONB,
    note_date                DATE NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE insights IS 'Hypothesis tracking — AI spots patterns, records falsification conditions, system tracks evidence over time.';
COMMENT ON COLUMN insights.source IS 'Which participant generated this insight. FK to participant.';
COMMENT ON COLUMN insights.status IS 'Lifecycle: unverified → verified/invalidated → archived.';
COMMENT ON COLUMN insights.hypothesis IS 'The pattern or prediction being tracked.';
COMMENT ON COLUMN insights.invalidation_condition IS 'What would disprove this hypothesis.';
COMMENT ON COLUMN insights.metadata IS 'supporting_evidence, counter_evidence, conclusion, category, project, tags.';

CREATE INDEX idx_insights_status ON insights (status);
CREATE INDEX idx_insights_date ON insights (note_date DESC);

-- ============================================================
-- Spaced repetition: review_cards + review_logs (was: fsrs_*)
-- ============================================================

CREATE TABLE review_cards (
    id         BIGSERIAL PRIMARY KEY,
    content_id UUID NOT NULL REFERENCES contents(id) ON DELETE CASCADE,
    tag_id     UUID REFERENCES tags(id) ON DELETE SET NULL,
    card_state JSONB NOT NULL,
    due        TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE review_cards IS 'Spaced repetition card state. One row per (content, tag) pair. Algorithm-agnostic naming — currently FSRS.';
COMMENT ON COLUMN review_cards.tag_id IS 'Canonical tag for per-concept review. NULL = whole-content review. FK to tags table.';
COMMENT ON COLUMN review_cards.card_state IS 'Serialized algorithm state (Due, Stability, Difficulty, Reps, Lapses). Opaque to SQL.';
COMMENT ON COLUMN review_cards.due IS 'Denormalized from card_state for index-based due-date queries.';

CREATE UNIQUE INDEX idx_review_cards_content_tag ON review_cards (content_id, COALESCE(tag_id, '00000000-0000-0000-0000-000000000000'));
CREATE INDEX idx_review_cards_due ON review_cards (due);

CREATE TABLE review_logs (
    id             BIGSERIAL PRIMARY KEY,
    card_id        BIGINT NOT NULL REFERENCES review_cards(id) ON DELETE CASCADE,
    rating         INT NOT NULL CHECK (rating BETWEEN 1 AND 4),
    scheduled_days INT NOT NULL,
    elapsed_days   INT NOT NULL,
    state          INT NOT NULL,
    reviewed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE review_logs IS 'Append-only review history. One row per review event.';
COMMENT ON COLUMN review_logs.rating IS '1=Again (forgot), 2=Hard (partial), 3=Good (remembered), 4=Easy.';
COMMENT ON COLUMN review_logs.state IS 'Card state BEFORE this review: 0=New, 1=Learning, 2=Review, 3=Relearning.';

CREATE INDEX idx_review_logs_card ON review_logs (card_id, reviewed_at DESC);

-- ============================================================
-- Telemetry
-- ============================================================

CREATE TABLE tool_call_logs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_name    TEXT NOT NULL,
    called_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms  INTEGER,
    is_error     BOOLEAN NOT NULL DEFAULT false,
    is_empty     BOOLEAN NOT NULL DEFAULT false,
    input_bytes  INTEGER,
    output_bytes INTEGER
);

COMMENT ON COLUMN tool_call_logs.is_empty IS 'True when search/list tool returned 0 results — signals misuse or missing data.';
COMMENT ON COLUMN tool_call_logs.input_bytes IS 'Approximate JSON byte size of tool input.';
COMMENT ON COLUMN tool_call_logs.output_bytes IS 'Approximate JSON byte size of tool output.';

CREATE INDEX idx_tool_call_logs_name_time ON tool_call_logs (tool_name, called_at DESC);

CREATE VIEW tool_usage_summary AS
SELECT tool_name,
       COUNT(*)                                                               AS calls,
       AVG(duration_ms)::int                                                  AS avg_ms,
       MAX(duration_ms)                                                       AS max_ms,
       percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms)::int         AS p95_ms,
       COUNT(*) FILTER (WHERE is_error)                                       AS errors,
       ROUND(COUNT(*) FILTER (WHERE is_error)::numeric / NULLIF(COUNT(*), 0), 4) AS error_rate,
       COUNT(*) FILTER (WHERE is_empty)                                       AS empty_results,
       AVG(input_bytes)::int                                                  AS avg_input_bytes,
       AVG(output_bytes)::int                                                 AS avg_output_bytes,
       MIN(called_at)                                                         AS first_seen,
       MAX(called_at)                                                         AS last_seen
FROM tool_call_logs
GROUP BY tool_name
ORDER BY calls DESC;

CREATE VIEW tool_daily_trend AS
SELECT called_at::date AS day,
       COUNT(*)        AS calls,
       COUNT(*) FILTER (WHERE is_error) AS errors,
       COUNT(*) FILTER (WHERE is_empty) AS empty_results
FROM tool_call_logs
GROUP BY called_at::date
ORDER BY day DESC;

-- ============================================================
-- Reconciliation
-- ============================================================

CREATE TABLE reconcile_runs (
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

COMMENT ON TABLE reconcile_runs IS 'Weekly reconciliation run history for system health and drift trend analysis.';
COMMENT ON COLUMN reconcile_runs.completed_at IS 'NULL until run finishes. NULL + old started_at = crashed run.';
COMMENT ON COLUMN reconcile_runs.total_drift IS 'Sum of all missing+orphaned counts. Zero = fully consistent.';

CREATE INDEX idx_reconcile_runs_started ON reconcile_runs(started_at DESC);
