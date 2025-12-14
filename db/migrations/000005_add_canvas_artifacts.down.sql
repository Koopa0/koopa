-- Rollback: Remove canvas_mode and artifacts table
-- Per Proposal 028 v4: Canvas Mode Comprehensive Fixes

DROP TRIGGER IF EXISTS update_session_artifacts_updated_at ON session_artifacts;
DROP INDEX IF EXISTS idx_session_artifacts_message;
DROP INDEX IF EXISTS idx_session_artifacts_session;
DROP TABLE IF EXISTS session_artifacts;
ALTER TABLE sessions DROP COLUMN IF EXISTS canvas_mode;
