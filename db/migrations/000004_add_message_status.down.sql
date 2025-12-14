-- Rollback migration 000004

DROP TRIGGER IF EXISTS update_session_messages_updated_at ON session_messages;
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP INDEX IF EXISTS idx_incomplete_messages;
DROP INDEX IF EXISTS idx_session_messages_status;
-- NOTE: sequence_number existed before this migration, do not drop
ALTER TABLE session_messages DROP COLUMN IF EXISTS updated_at;
ALTER TABLE session_messages DROP COLUMN IF EXISTS status;
