-- Koopa Database Schema - Down Migration
-- Drops all objects created by 000001_init_schema.up.sql in reverse order

-- ============================================================================
-- Drop Messages Table (including triggers and indexes)
-- ============================================================================

DROP TRIGGER IF EXISTS update_message_updated_at ON message;
DROP INDEX IF EXISTS idx_message_content_gin;
DROP INDEX IF EXISTS idx_message_status;
DROP INDEX IF EXISTS idx_incomplete_messages;
DROP INDEX IF EXISTS idx_message_session_seq;
DROP INDEX IF EXISTS idx_message_session_id;
DROP TABLE IF EXISTS message;

-- ============================================================================
-- Drop Sessions Table (including triggers and indexes)
-- ============================================================================

DROP TRIGGER IF EXISTS update_sessions_updated_at ON sessions;
DROP INDEX IF EXISTS idx_sessions_updated_at;
DROP TABLE IF EXISTS sessions;

-- ============================================================================
-- Drop Helper Functions
-- ============================================================================

DROP FUNCTION IF EXISTS update_updated_at_column();

-- ============================================================================
-- Drop Documents Table (including indexes)
-- ============================================================================

DROP INDEX IF EXISTS idx_documents_metadata_gin;
DROP INDEX IF EXISTS idx_documents_source_type;
DROP INDEX IF EXISTS idx_documents_embedding;
DROP TABLE IF EXISTS documents;

-- ============================================================================
-- Drop Extensions
-- Note: Only drop if no other schemas depend on it
-- ============================================================================

DROP EXTENSION IF EXISTS vector;
