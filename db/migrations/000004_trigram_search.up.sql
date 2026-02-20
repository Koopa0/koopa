-- Enable pg_trgm extension for trigram-based text search (CJK support).
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- CONCURRENTLY avoids locking the table during index creation.
-- NOTE: CONCURRENTLY cannot run inside a transaction block.
-- golang-migrate runs each file in a transaction by default;
-- the operator must run this migration manually with:
--   psql -f 000004_trigram_search.up.sql
-- or disable transactions in the migration tool.

-- GIN trigram index on messages.text_content for ILIKE fallback search.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_text_content_trgm
    ON messages USING gin (text_content gin_trgm_ops);

-- GIN trigram index on memories.content for similarity() scoring.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_memories_content_trgm
    ON memories USING gin (content gin_trgm_ops);
