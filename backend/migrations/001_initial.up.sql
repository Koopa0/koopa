-- Phase A: Initial schema for koopa0.dev knowledge engine

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
    'in-progress', 'completed', 'maintained', 'archived'
);

-- === Tables ===

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
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
    search_vector TSVECTOR GENERATED ALWAYS AS (
        setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('english', coalesce(excerpt, '')), 'B') ||
        setweight(to_tsvector('english', coalesce(body, '')), 'C')
    ) STORED
);

CREATE INDEX idx_contents_status ON contents(status);
CREATE INDEX idx_contents_type ON contents(type);
CREATE INDEX idx_contents_published_at ON contents(published_at DESC NULLS LAST);
CREATE INDEX idx_contents_tags ON contents USING GIN(tags);
CREATE INDEX idx_contents_search ON contents USING GIN(search_vector);
CREATE INDEX idx_contents_series ON contents(series_id, series_order) WHERE series_id IS NOT NULL;

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
    sort_order       INT NOT NULL DEFAULT 0,
    status           project_status NOT NULL DEFAULT 'in-progress',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_projects_featured ON projects(featured DESC, sort_order);

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

CREATE TABLE collected_data (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_url         TEXT NOT NULL,
    source_name        TEXT NOT NULL,
    title              TEXT NOT NULL,
    original_content   TEXT,
    ai_summary         TEXT,
    relevance_score    REAL NOT NULL DEFAULT 0,
    topics             TEXT[] NOT NULL DEFAULT '{}',
    status             collected_status NOT NULL DEFAULT 'unread',
    curated_content_id UUID REFERENCES contents(id) ON DELETE SET NULL,
    collected_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_collected_data_status ON collected_data(status);
CREATE INDEX idx_collected_data_relevance ON collected_data(relevance_score DESC);

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

-- === Seed admin user ===
-- Password: changeme (bcrypt cost 12)
INSERT INTO users (email, password_hash, role) VALUES (
    'admin@koopa0.dev',
    '$2a$12$e7t8rSNW4CvNhV5pX8E//O9ryDmmCE1SLubyj6cxSU8wuV/uNwHFe',
    'admin'
);
