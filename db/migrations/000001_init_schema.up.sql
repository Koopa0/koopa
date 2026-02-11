-- Koopa Database Schema
-- Consolidated migration for sessions, messages, and documents
-- NOTE: All CREATE statements use IF NOT EXISTS for idempotent execution

-- Enable pgvector extension (required for vector search)
CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================================
-- Documents Table (for RAG / Knowledge Store)
-- Used by Genkit PostgreSQL Plugin with custom column names
-- ============================================================================

CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    embedding vector(768) NOT NULL,  -- gemini-embedding-001 truncated via OutputDimensionality
    source_type TEXT,                 -- Metadata column for filtering
    metadata JSONB                    -- Additional metadata in JSON format
);

-- HNSW index for fast vector similarity search
CREATE INDEX IF NOT EXISTS idx_documents_embedding ON documents
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- Index for filtering by source_type
CREATE INDEX IF NOT EXISTS idx_documents_source_type ON documents(source_type);

-- Enables fast queries like: WHERE metadata @> '{"key": "value"}'
CREATE INDEX IF NOT EXISTS idx_documents_metadata_gin
    ON documents USING GIN (metadata jsonb_path_ops);

-- ============================================================================
-- Sessions Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_updated_at ON sessions(updated_at DESC);

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

    -- UNIQUE constraint automatically creates index on (session_id, sequence_number)
    CONSTRAINT unique_message_sequence UNIQUE (session_id, sequence_number),
    CONSTRAINT message_role_check CHECK (role IN ('user', 'assistant', 'system', 'tool'))
);
