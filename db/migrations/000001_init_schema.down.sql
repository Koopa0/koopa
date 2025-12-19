-- Koopa Database Schema v2 - Rollback
-- Drop all tables and functions

-- Drop triggers first
DROP TRIGGER IF EXISTS update_artifact_updated_at ON artifact;
DROP TRIGGER IF EXISTS update_message_updated_at ON message;
DROP TRIGGER IF EXISTS update_sessions_updated_at ON sessions;

-- Drop tables (order matters due to foreign keys)
DROP TABLE IF EXISTS artifact;
DROP TABLE IF EXISTS message;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS documents;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Note: pgvector extension is NOT dropped as it may be shared
