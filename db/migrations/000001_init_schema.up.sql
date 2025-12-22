-- Koopa Database Schema
-- Consolidated migration for sessions, messages, and documents

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

-- Enables fast queries like: WHERE metadata @> '{"key": "value"}'
CREATE INDEX idx_documents_metadata_gin
    ON documents USING GIN (metadata jsonb_path_ops);

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
    message_count INTEGER DEFAULT 0
);

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
    status TEXT NOT NULL DEFAULT 'completed'
        CHECK (status IN ('streaming', 'completed', 'failed')),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    CONSTRAINT unique_message_sequence UNIQUE (session_id, sequence_number),
    CONSTRAINT message_role_check CHECK (role IN ('user', 'assistant', 'system', 'tool'))
);

CREATE INDEX idx_message_session_id ON message(session_id);
CREATE INDEX idx_message_session_seq ON message(session_id, sequence_number);
CREATE INDEX idx_incomplete_messages ON message(session_id, updated_at)
    WHERE status IN ('streaming', 'failed');

-- Index for querying failed/streaming messages
CREATE INDEX idx_message_status ON message(session_id, status)
    WHERE status != 'completed';

-- Index for message.content (ai.Part array stored as JSONB)
-- Enables fast queries like: WHERE content @> '[{"text": "search term"}]'
CREATE INDEX idx_message_content_gin
        ON message USING GIN (content jsonb_path_ops);

CREATE TRIGGER update_message_updated_at
    BEFORE UPDATE ON message
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
