-- Complete schema migration for koopa
-- Documents table with pgvector support for RAG

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- Documents table (pgvector)
CREATE TABLE IF NOT EXISTS documents (
    id            TEXT PRIMARY KEY,
    content       TEXT NOT NULL,
    embedding     vector(768),  -- text-embedding-004 dimension
    metadata      JSONB,
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for documents
CREATE INDEX IF NOT EXISTS embedding_hnsw_idx ON documents
USING hnsw (embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

CREATE INDEX IF NOT EXISTS metadata_gin_idx ON documents
USING gin (metadata);

CREATE INDEX IF NOT EXISTS metadata_source_type_idx ON documents
((metadata->>'source_type'));

CREATE INDEX IF NOT EXISTS metadata_session_id_idx ON documents
((metadata->>'session_id'));

-- Trigger for auto-update timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_documents_updated_at
    BEFORE UPDATE ON documents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
