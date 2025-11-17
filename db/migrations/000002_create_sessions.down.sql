-- Wrap in transaction for atomicity
BEGIN;

-- Drop triggers
DROP TRIGGER IF EXISTS update_sessions_updated_at ON sessions;

-- Drop indexes
DROP INDEX IF EXISTS idx_session_messages_sequence;
DROP INDEX IF EXISTS idx_session_messages_session_id;
DROP INDEX IF EXISTS idx_sessions_updated_at;

-- Drop tables (session_messages first due to foreign key constraint)
DROP TABLE IF EXISTS session_messages;
DROP TABLE IF EXISTS sessions;

COMMIT;
