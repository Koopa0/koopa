DROP INDEX IF EXISTS idx_sessions_owner_id;
ALTER TABLE sessions DROP COLUMN IF EXISTS owner_id;
