-- Migration 000004: Add status tracking for streaming messages
-- Adds status and updated_at columns to track message lifecycle

ALTER TABLE session_messages
ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'
    CHECK (status IN ('streaming', 'completed', 'failed')),
ADD COLUMN updated_at TIMESTAMPTZ DEFAULT NOW();

-- NOTE: sequence_number already exists since migration 000002, not added here

-- Index for querying failed/streaming messages
CREATE INDEX idx_session_messages_status
ON session_messages(session_id, status)
WHERE status != 'completed';

-- Partial index for incomplete messages (timeout detection)
CREATE INDEX idx_incomplete_messages
ON session_messages(session_id, branch, updated_at)
WHERE status IN ('streaming', 'failed');

-- Trigger for auto-updating updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_session_messages_updated_at
    BEFORE UPDATE ON session_messages
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
