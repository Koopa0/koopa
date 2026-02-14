-- Add owner_id to sessions for multi-session support.
-- Each session is owned by a user identified by a persistent uid cookie.
-- Existing sessions get empty owner_id (orphaned — invisible to new users).
ALTER TABLE sessions ADD COLUMN owner_id TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_sessions_owner_id ON sessions(owner_id, updated_at DESC);
