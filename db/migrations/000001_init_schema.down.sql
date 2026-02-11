-- Koopa Database Schema - Down Migration
-- Drops all objects created by 000001_init_schema.up.sql in reverse order

-- ============================================================================
-- Drop Messages Table
-- ============================================================================

DROP TABLE IF EXISTS messages;

-- ============================================================================
-- Drop Sessions Table (including indexes)
-- ============================================================================

DROP INDEX IF EXISTS idx_sessions_updated_at;
DROP TABLE IF EXISTS sessions;

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
