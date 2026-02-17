-- Koopa Database Schema (consolidated)
-- All tables: sessions, messages, documents, memories

CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================================
-- Documents Table (RAG / Knowledge Store)
-- ============================================================================

CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    embedding vector(768) NOT NULL,
    source_type TEXT,
    metadata JSONB,
    owner_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_documents_embedding ON documents
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE INDEX IF NOT EXISTS idx_documents_source_type ON documents(source_type);

CREATE INDEX IF NOT EXISTS idx_documents_metadata_gin
    ON documents USING GIN (metadata jsonb_path_ops);

CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);

-- ============================================================================
-- Sessions Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT,
    owner_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_updated_at ON sessions(updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_owner_id ON sessions(owner_id, updated_at DESC);

-- ============================================================================
-- Messages Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    content JSONB NOT NULL,
    sequence_number INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_message_sequence UNIQUE (session_id, sequence_number),
    CONSTRAINT message_role_check CHECK (role IN ('user', 'assistant', 'system', 'tool'))
);

-- ============================================================================
-- Memories Table (user memory with vector search, decay, dedup)
-- ============================================================================

CREATE TABLE IF NOT EXISTS memories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id TEXT NOT NULL,
    content TEXT NOT NULL,
    embedding vector(768) NOT NULL,
    category TEXT NOT NULL DEFAULT 'contextual'
        CHECK (category IN ('identity', 'preference', 'project', 'contextual')),
    source_session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    importance SMALLINT NOT NULL DEFAULT 5
        CHECK (importance BETWEEN 1 AND 10),
    access_count INTEGER NOT NULL DEFAULT 0,
    last_accessed_at TIMESTAMPTZ,
    decay_score REAL NOT NULL DEFAULT 1.0
        CHECK (decay_score BETWEEN 0.0 AND 1.0),
    superseded_by UUID REFERENCES memories(id) ON DELETE SET NULL,
    CONSTRAINT memories_no_self_supersede
        CHECK (superseded_by IS NULL OR superseded_by != id),
    expires_at TIMESTAMPTZ,
    search_text tsvector
        GENERATED ALWAYS AS (to_tsvector('english', content)) STORED
);

CREATE INDEX idx_memories_embedding ON memories
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE INDEX idx_memories_owner ON memories(owner_id);

CREATE INDEX idx_memories_owner_active_category
    ON memories(owner_id, active, category);

CREATE UNIQUE INDEX idx_memories_owner_content_unique
    ON memories(owner_id, md5(content)) WHERE active = true;

CREATE INDEX idx_memories_search_text ON memories USING gin (search_text);

CREATE INDEX idx_memories_decay_candidates
    ON memories (owner_id, updated_at)
    WHERE active = true AND superseded_by IS NULL;

CREATE INDEX idx_memories_superseded_by ON memories (superseded_by)
    WHERE superseded_by IS NOT NULL;

CREATE INDEX idx_memories_expires_at
    ON memories (expires_at)
    WHERE expires_at IS NOT NULL AND active = true;
