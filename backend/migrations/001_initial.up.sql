-- Phase A: Initial schema for koopa0.dev knowledge engine

CREATE EXTENSION IF NOT EXISTS vector;

-- === Enums ===

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

CREATE TYPE collected_status AS ENUM (
    'unread', 'read', 'curated', 'ignored'
);

CREATE TYPE project_status AS ENUM (
    'planned', 'in-progress', 'on-hold', 'completed', 'maintained', 'archived'
);

-- === Tables ===

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

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

CREATE TABLE contents (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          TEXT NOT NULL UNIQUE,
    title         TEXT NOT NULL,
    body          TEXT NOT NULL DEFAULT '',
    excerpt       TEXT NOT NULL DEFAULT '',
    type          content_type NOT NULL,
    status        content_status NOT NULL DEFAULT 'draft',
    tags          TEXT[] NOT NULL DEFAULT '{}',
    source        TEXT,
    source_type   source_type,
    series_id     TEXT,
    series_order  INT,
    review_level  review_level NOT NULL DEFAULT 'standard',
    ai_metadata   JSONB,
    reading_time  INT NOT NULL DEFAULT 0,
    cover_image   TEXT,
    published_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    embedding     vector(768),
    search_text   TEXT,
    search_vector TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(search_text, '')), 'C')
    ) STORED
);

CREATE INDEX idx_contents_status ON contents(status);
CREATE INDEX idx_contents_type ON contents(type);
CREATE INDEX idx_contents_published_at ON contents(published_at DESC NULLS LAST);
CREATE INDEX idx_contents_tags ON contents USING GIN(tags);
CREATE INDEX idx_contents_search ON contents USING GIN(search_vector);
CREATE INDEX idx_contents_series ON contents(series_id, series_order) WHERE series_id IS NOT NULL;
CREATE INDEX idx_contents_embedding_hnsw ON contents USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE TABLE content_topics (
    content_id UUID NOT NULL REFERENCES contents(id) ON DELETE CASCADE,
    topic_id   UUID NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    PRIMARY KEY (content_id, topic_id)
);

CREATE INDEX idx_content_topics_topic_id ON content_topics(topic_id);

CREATE TABLE projects (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug             TEXT NOT NULL UNIQUE,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    long_description TEXT,
    role             TEXT NOT NULL DEFAULT '',
    tech_stack       TEXT[] NOT NULL DEFAULT '{}',
    highlights       TEXT[] NOT NULL DEFAULT '{}',
    problem          TEXT,
    solution         TEXT,
    architecture     TEXT,
    results          TEXT,
    github_url       TEXT,
    live_url         TEXT,
    featured         BOOLEAN NOT NULL DEFAULT false,
    public           BOOLEAN NOT NULL DEFAULT false,
    sort_order       INT NOT NULL DEFAULT 0,
    status           project_status NOT NULL DEFAULT 'in-progress',
    notion_page_id   TEXT UNIQUE,
    repo             TEXT,
    area             TEXT NOT NULL DEFAULT '',
    deadline         TIMESTAMPTZ,
    last_activity_at TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_projects_featured ON projects(featured DESC, sort_order);
CREATE INDEX idx_projects_lower_title ON projects (LOWER(title));

CREATE TABLE review_queue (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content_id     UUID NOT NULL REFERENCES contents(id) ON DELETE CASCADE,
    review_level   review_level NOT NULL,
    status         review_status NOT NULL DEFAULT 'pending',
    reviewer_notes TEXT,
    submitted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at    TIMESTAMPTZ
);

CREATE INDEX idx_review_queue_status ON review_queue(status);
CREATE INDEX idx_review_queue_content_id ON review_queue(content_id);
CREATE UNIQUE INDEX idx_review_queue_pending_content
    ON review_queue (content_id) WHERE status = 'pending';

CREATE TABLE feeds (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url                  TEXT NOT NULL UNIQUE,
    name                 TEXT NOT NULL,
    schedule             TEXT NOT NULL,
    topics               TEXT[] NOT NULL DEFAULT '{}',
    enabled              BOOLEAN NOT NULL DEFAULT true,
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

CREATE INDEX idx_feeds_schedule ON feeds (schedule) WHERE enabled = true;

CREATE TABLE collected_data (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_url         TEXT NOT NULL,
    source_name        TEXT NOT NULL,
    title              TEXT NOT NULL,
    original_content   TEXT,
    relevance_score    REAL NOT NULL DEFAULT 0,
    topics             TEXT[] NOT NULL DEFAULT '{}',
    status             collected_status NOT NULL DEFAULT 'unread',
    curated_content_id UUID REFERENCES contents(id) ON DELETE SET NULL,
    collected_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    url_hash           TEXT NOT NULL DEFAULT '',
    user_feedback      TEXT,
    feedback_at        TIMESTAMPTZ,
    feed_id            UUID REFERENCES feeds(id) ON DELETE SET NULL
);

CREATE INDEX idx_collected_data_status ON collected_data(status);
CREATE INDEX idx_collected_data_relevance ON collected_data(relevance_score DESC);
CREATE UNIQUE INDEX idx_collected_data_url_hash ON collected_data (url_hash) WHERE url_hash != '';
CREATE INDEX idx_collected_data_feed_id ON collected_data (feed_id) WHERE feed_id IS NOT NULL;

CREATE TABLE tracking_topics (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    keywords   TEXT[] NOT NULL DEFAULT '{}',
    sources    TEXT[] NOT NULL DEFAULT '{}',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    schedule   TEXT NOT NULL DEFAULT '0 */6 * * *',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- === Flow Runs ===

CREATE TYPE flow_status AS ENUM ('pending', 'running', 'completed', 'failed');

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

CREATE INDEX idx_flow_runs_status ON flow_runs (status);
CREATE INDEX idx_flow_runs_retry ON flow_runs (created_at) WHERE status = 'failed';
CREATE INDEX idx_flow_runs_created_at ON flow_runs (created_at DESC);
CREATE INDEX idx_flow_runs_content_id ON flow_runs (content_id) WHERE content_id IS NOT NULL;
CREATE INDEX idx_flow_runs_dedup ON flow_runs (content_id, flow_name, status) WHERE status IN ('pending', 'running');

CREATE TYPE goal_status AS ENUM ('not-started', 'in-progress', 'done', 'abandoned');

CREATE TABLE goals (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title          TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    status         goal_status NOT NULL DEFAULT 'not-started',
    area           TEXT NOT NULL DEFAULT '',
    quarter        TEXT NOT NULL DEFAULT '',
    deadline       TIMESTAMPTZ,
    notion_page_id TEXT UNIQUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_goals_lower_title ON goals (LOWER(title));

-- === Tasks (synced from Notion) ===

CREATE TYPE task_status AS ENUM ('todo', 'in-progress', 'done');

CREATE TABLE tasks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title           TEXT NOT NULL,
    status          task_status NOT NULL DEFAULT 'todo',
    due             DATE,
    project_id      UUID REFERENCES projects(id) ON DELETE SET NULL,
    notion_page_id  TEXT UNIQUE,
    completed_at    TIMESTAMPTZ,
    energy          TEXT NOT NULL DEFAULT '',
    priority        TEXT NOT NULL DEFAULT '',
    recur_interval  INT,
    recur_unit      TEXT NOT NULL DEFAULT '',
    my_day          BOOLEAN NOT NULL DEFAULT false,
    description     TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tasks_status ON tasks (status) WHERE status != 'done';
CREATE INDEX idx_tasks_project ON tasks (project_id) WHERE project_id IS NOT NULL;
CREATE INDEX idx_tasks_completed ON tasks (completed_at) WHERE status = 'done';
CREATE INDEX idx_tasks_my_day ON tasks (my_day) WHERE my_day = true AND status != 'done';

-- Seed topics
INSERT INTO topics (slug, name, sort_order) VALUES
('go',             'Go',              1),
('rust',           'Rust',            2),
('angular',        'Angular',         3),
('flutter',        'Flutter',         4),
('dart',           'Dart',            5),
('frontend',       'Frontend',        6),
('mobile',         'Mobile',          7),
('ai',             'AI',              8),
('llm',            'LLM',             9),
('ml',             'Machine Learning', 10),
('claude',         'Claude',          11),
('kubernetes',     'Kubernetes',      12),
('docker',         'Docker',          13),
('infra',          'Infrastructure',  14),
('networking',     'Networking',      15),
('workers',        'Workers',         16),
('devops',         'DevOps',          17),
('system-design',  'System Design',   18),
('database',       'Database',        19),
('security',       'Security',        20),
('performance',    'Performance',     21),
('design',         'Design',          22),
('career',         'Career',          23),
('open-source',    'Open Source',     24)
ON CONFLICT (slug) DO NOTHING;

-- Seed feeds
INSERT INTO feeds (url, name, schedule, topics, filter_config) VALUES
('https://www.ardanlabs.com/index.xml', 'Ardan Labs', 'daily',
 '{"go","rust","kubernetes","ai","devops","design"}',
 '{"deny_paths":["/news","/events","/team-live-training-courses","/self-paced-courses","/training","/self-paced-teams","/self-paced-individuals"]}'),

('https://go.dev/blog/feed.atom', 'The Go Blog', 'daily',
 '{"go"}', '{}'),

('https://golangweekly.com/rss/', 'Golang Weekly', 'weekly',
 '{"go"}',
 '{"deny_title_patterns":["(?i)sponsored"]}'),

('https://www.alexedwards.net/static/feed.rss', 'Alex Edwards', 'daily',
 '{"go"}', '{}'),

('https://blog.rust-lang.org/feed.xml', 'Rust Blog', 'daily',
 '{"rust"}', '{}'),

('https://this-week-in-rust.org/atom.xml', 'This Week in Rust', 'weekly',
 '{"rust"}', '{}'),

('https://blog.angular.dev/feed', 'Angular Blog', 'daily',
 '{"angular","frontend"}', '{}'),

('https://blog.flutter.dev/feed', 'Flutter Blog', 'daily',
 '{"flutter","dart","mobile"}', '{}'),

('https://blog.cloudflare.com/rss/', 'Cloudflare Blog', 'daily',
 '{"infra","networking","workers"}',
 '{"deny_title_patterns":["(?i)birthday week","(?i)speed week","(?i)developer week","(?i)security week","(?i)innovation week","(?i)impact week","(?i)welcome to .* week","(?i)new pricing","(?i)announcing .* plan"],"deny_tags":["product-news","partners","case-study","legal"]}'),

('https://simonwillison.net/atom/everything/', 'Simon Willison''s Weblog', 'daily',
 '{"ai","llm"}', '{}'),

('https://research.google/blog/rss/', 'Google Research Blog', 'daily',
 '{"ai","ml"}',
 '{"deny_title_patterns":["(?i)health","(?i)medical","(?i)quantum","(?i)biology","(?i)climate","(?i)flood","(?i)wildfire"]}'),

('https://www.latent.space/feed', 'Latent Space', 'weekly',
 '{"ai","llm"}', '{}'),

('https://blog.google/technology/ai/rss/', 'Google AI Blog', 'daily',
 '{"ai","llm","ml"}',
 '{"deny_title_patterns":["(?i)health","(?i)medical","(?i)quantum"]}'),

('https://deepmind.google/blog/rss.xml', 'DeepMind Blog', 'weekly',
 '{"ai","ml"}', '{}'),

('https://developers.googleblog.com/feeds/posts/default', 'Google Developers Blog', 'daily',
 '{"go","angular","flutter","ai","mobile","frontend"}',
 '{"deny_title_patterns":["(?i)devfest","(?i)women techmakers","(?i)student"]}'),

('https://cloud.google.com/blog/rss', 'Google Cloud Blog', 'daily',
 '{"kubernetes","docker","infra","database","ai"}',
 '{"deny_title_patterns":["(?i)customer story","(?i)case study","(?i)partner","(?i)pricing","(?i)event recap"]}'),

('https://blog.google/technology/developers/rss/', 'Google Dev Updates', 'weekly',
 '{"go","angular","flutter","ai"}', '{}'),

('https://huggingface.co/blog/feed.xml', 'Hugging Face Blog', 'daily',
 '{"ai","llm","ml"}',
 '{"deny_title_patterns":["(?i)community update","(?i)partnership"],"deny_tags":["community","partnerships"]}'),

('https://blog.bytebytego.com/feed', 'ByteByteGo', 'weekly',
 '{"system-design"}',
 '{"deny_title_patterns":["(?i)black friday","(?i)discount","(?i)course launch"]}')

ON CONFLICT (url) DO NOTHING;

-- === Phase 1: Knowledge Engine ===

-- Activity events — unified event log from all sources
CREATE TABLE activity_events (
    id          BIGSERIAL PRIMARY KEY,
    source_id   TEXT,
    timestamp   TIMESTAMPTZ NOT NULL,
    event_type  TEXT NOT NULL,
    source      TEXT NOT NULL,
    project     TEXT,
    repo        TEXT,
    ref         TEXT,
    title       TEXT,
    body        TEXT,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_activity_events_timestamp ON activity_events (timestamp DESC);
CREATE INDEX idx_activity_events_project ON activity_events (project);
CREATE INDEX idx_activity_events_type ON activity_events (event_type);
CREATE UNIQUE INDEX idx_activity_events_dedup
    ON activity_events (source, event_type, source_id)
    WHERE source_id IS NOT NULL;

-- Obsidian notes — knowledge notes from vault
CREATE TABLE obsidian_notes (
    id              BIGSERIAL PRIMARY KEY,
    file_path       TEXT UNIQUE NOT NULL,
    title           TEXT,
    type            TEXT,
    source          TEXT,
    context         TEXT,
    status          TEXT DEFAULT 'seed',
    tags            JSONB,
    difficulty      TEXT,
    leetcode_id     INT,
    book            TEXT,
    chapter         TEXT,
    notion_task_id  TEXT,
    content_text    TEXT,
    search_text     TEXT,
    content_hash    TEXT,
    embedding       vector(768),
    search_vector   TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(search_text, '')), 'C')
    ) STORED,
    git_created_at  TIMESTAMPTZ,
    git_updated_at  TIMESTAMPTZ,
    synced_at       TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX idx_obsidian_notes_type ON obsidian_notes (type);
CREATE INDEX idx_obsidian_notes_context ON obsidian_notes (context);
CREATE INDEX idx_obsidian_notes_search ON obsidian_notes USING GIN(search_vector);
CREATE INDEX idx_obsidian_notes_embedding ON obsidian_notes
    USING hnsw (embedding vector_cosine_ops) WITH (m = 16, ef_construction = 64);

-- Tags — canonical tag registry with hierarchy
CREATE TABLE tags (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    parent_id   UUID REFERENCES tags(id),
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tags_parent ON tags(parent_id);

-- Tag aliases — maps raw tags to canonical tags
CREATE TABLE tag_aliases (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_tag       TEXT NOT NULL UNIQUE,
    tag_id        UUID REFERENCES tags(id),
    match_method  TEXT NOT NULL DEFAULT 'manual',
    confirmed     BOOLEAN NOT NULL DEFAULT false,
    confirmed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tag_aliases_tag ON tag_aliases(tag_id);
CREATE INDEX idx_tag_aliases_confirmed ON tag_aliases(confirmed);
CREATE INDEX idx_tag_aliases_lower_raw_tag ON tag_aliases (LOWER(raw_tag));

-- Junction: obsidian notes ↔ tags
CREATE TABLE obsidian_note_tags (
    note_id  BIGINT NOT NULL REFERENCES obsidian_notes(id) ON DELETE CASCADE,
    tag_id   UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (note_id, tag_id)
);

CREATE INDEX idx_obsidian_note_tags_tag ON obsidian_note_tags(tag_id);

-- Junction: activity events ↔ tags
CREATE TABLE activity_event_tags (
    event_id  BIGINT NOT NULL REFERENCES activity_events(id) ON DELETE CASCADE,
    tag_id    UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (event_id, tag_id)
);

CREATE INDEX idx_activity_event_tags_tag ON activity_event_tags(tag_id);

-- Project aliases — maps variant project names to canonical
CREATE TABLE project_aliases (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alias          TEXT NOT NULL UNIQUE,
    canonical_name TEXT NOT NULL,
    project_id     UUID REFERENCES projects(id) ON DELETE CASCADE,
    source         TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Partial indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_contents_published_at_pub
    ON contents (published_at DESC NULLS LAST)
    WHERE status = 'published';

CREATE INDEX IF NOT EXISTS idx_contents_source_obsidian
    ON contents (source_type)
    WHERE source_type = 'obsidian';

CREATE INDEX IF NOT EXISTS idx_flow_runs_completed
    ON flow_runs (content_id, flow_name, ended_at DESC)
    WHERE status = 'completed';

-- === Spaced Repetition ===

CREATE TABLE spaced_intervals (
    note_id         BIGINT PRIMARY KEY REFERENCES obsidian_notes(id) ON DELETE CASCADE,
    easiness_factor DOUBLE PRECISION NOT NULL DEFAULT 2.5,
    interval_days   INT NOT NULL DEFAULT 0,
    repetitions     INT NOT NULL DEFAULT 0,
    last_quality    INT,
    due_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_spaced_intervals_due ON spaced_intervals (due_at);

-- === Notion Source Registry ===

CREATE TABLE notion_sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    database_id     TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    role            TEXT CHECK (role IN ('projects', 'tasks', 'books', 'goals')),
    sync_mode       TEXT NOT NULL DEFAULT 'full',
    property_map    JSONB NOT NULL DEFAULT '{}',
    poll_interval   TEXT NOT NULL DEFAULT '15 minutes',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_synced_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_notion_sources_enabled ON notion_sources (id) WHERE enabled = true;
CREATE UNIQUE INDEX idx_notion_sources_role ON notion_sources (role) WHERE role IS NOT NULL;

-- === Wikilink Edges ===

CREATE TABLE note_links (
    id              BIGSERIAL PRIMARY KEY,
    source_note_id  BIGINT NOT NULL REFERENCES obsidian_notes(id) ON DELETE CASCADE,
    target_path     TEXT NOT NULL,
    link_text       TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_note_links_source ON note_links (source_note_id);
CREATE INDEX idx_note_links_target ON note_links (target_path);
CREATE UNIQUE INDEX idx_note_links_dedup ON note_links (source_note_id, target_path);
