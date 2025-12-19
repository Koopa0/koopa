-- Koopa Database Schema v2
-- Consolidated migration for sessions, messages, artifacts, and documents

-- Enable pgvector extension (required for vector search)
CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================================
-- Documents Table (for RAG / Knowledge Store)
-- Used by Genkit PostgreSQL Plugin with custom column names
-- ============================================================================

CREATE TABLE documents (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    embedding vector(768) NOT NULL,  -- text-embedding-004 dimension
    source_type TEXT,                 -- Metadata column for filtering
    metadata JSONB                    -- Additional metadata in JSON format
);

-- HNSW index for fast vector similarity search
CREATE INDEX idx_documents_embedding ON documents
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- Index for filtering by source_type
CREATE INDEX idx_documents_source_type ON documents(source_type);

-- ============================================================================
-- Helper Functions
-- ============================================================================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Sessions Table
-- ============================================================================

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    model_name TEXT,
    system_prompt TEXT,
    message_count INTEGER DEFAULT 0,
    canvas_mode BOOLEAN NOT NULL DEFAULT FALSE
);

COMMENT ON COLUMN sessions.canvas_mode IS 'When true, AI outputs artifacts to Canvas panel';

CREATE INDEX idx_sessions_updated_at ON sessions(updated_at DESC);

CREATE TRIGGER update_sessions_updated_at
    BEFORE UPDATE ON sessions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Messages Table
-- ============================================================================

CREATE TABLE message (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    content JSONB NOT NULL,
    sequence_number INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    branch TEXT NOT NULL DEFAULT 'main',
    status TEXT NOT NULL DEFAULT 'completed'
        CHECK (status IN ('streaming', 'completed', 'failed')),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT unique_message_branch_sequence UNIQUE (session_id, branch, sequence_number)
);

CREATE INDEX idx_message_session_id ON message(session_id);
CREATE INDEX idx_message_branch ON message(session_id, branch, sequence_number);

-- Index for querying failed/streaming messages
CREATE INDEX idx_message_status ON message(session_id, status)
    WHERE status != 'completed';

-- Partial index for incomplete messages (timeout detection)
CREATE INDEX idx_incomplete_messages ON message(session_id, branch, updated_at)
    WHERE status IN ('streaming', 'failed');

CREATE TRIGGER update_message_updated_at
    BEFORE UPDATE ON message
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Artifacts Table
-- ============================================================================

CREATE TABLE artifact (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    message_id UUID REFERENCES message(id) ON DELETE SET NULL,

    -- Artifact metadata
    type TEXT NOT NULL CHECK (type IN ('code', 'markdown', 'html')),
    language TEXT,           -- Programming language for code artifacts
    title TEXT NOT NULL,     -- Display title
    filename TEXT NOT NULL,  -- Unique filename within session

    -- Content
    content TEXT NOT NULL,

    -- Versioning (for future interactive editing)
    version INTEGER NOT NULL DEFAULT 1,

    -- Ordering (multiple artifacts per session)
    sequence_number INTEGER NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Safety constraint to prevent path traversal attacks
    CONSTRAINT artifact_filename_safe CHECK (
        filename !~ '^\.\.$' AND
        filename !~ '^\.$' AND
        filename !~ '/' AND
        filename !~ '\\' AND
        char_length(filename) <= 255 AND
        char_length(filename) > 0
    )
);

COMMENT ON COLUMN artifact.filename IS 'Unique filename within session (e.g., main.go, report.md)';

CREATE INDEX idx_artifact_session ON artifact(session_id, sequence_number DESC);
CREATE INDEX idx_artifact_message ON artifact(message_id) WHERE message_id IS NOT NULL;
CREATE UNIQUE INDEX idx_artifact_session_filename ON artifact(session_id, filename);

CREATE TRIGGER update_artifact_updated_at
    BEFORE UPDATE ON artifact
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
