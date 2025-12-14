-- Migration: Add canvas_mode to sessions and create artifacts table
-- Canvas Mode Comprehensive Fixes

-- Add canvas_mode column to sessions table
ALTER TABLE sessions
ADD COLUMN canvas_mode BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN sessions.canvas_mode IS 'When true, AI outputs artifacts to Canvas panel';

-- Create artifacts table for Canvas content persistence
CREATE TABLE session_artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    message_id UUID REFERENCES session_messages(id) ON DELETE SET NULL,

    -- Artifact metadata
    type TEXT NOT NULL CHECK (type IN ('code', 'markdown', 'html')),
    language TEXT,           -- Programming language for code artifacts
    title TEXT NOT NULL,     -- Filename or description

    -- Content
    content TEXT NOT NULL,

    -- Versioning (for future interactive editing)
    version INTEGER NOT NULL DEFAULT 1,

    -- Ordering (multiple artifacts per session)
    sequence_number INTEGER NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for loading artifacts by session (Canvas panel display)
CREATE INDEX idx_session_artifacts_session
ON session_artifacts(session_id, sequence_number DESC);

-- Index for finding artifact by message (traceability)
CREATE INDEX idx_session_artifacts_message
ON session_artifacts(message_id)
WHERE message_id IS NOT NULL;

-- Trigger for auto-updating updated_at
CREATE TRIGGER update_session_artifacts_updated_at
    BEFORE UPDATE ON session_artifacts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
