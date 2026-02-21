-- Enable pg_trgm extension for trigram-based text search (CJK support).
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- GIN trigram index on messages.text_content for ILIKE fallback search.
-- NOTE: For large production tables with existing data, create these indexes
-- manually with CONCURRENTLY before running this migration (they will be
-- no-ops due to IF NOT EXISTS):
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_messages_text_content_trgm
--       ON messages USING gin (text_content gin_trgm_ops);
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_memories_content_trgm
--       ON memories USING gin (content gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_messages_text_content_trgm
    ON messages USING gin (text_content gin_trgm_ops);

-- GIN trigram index on memories.content for similarity() scoring.
CREATE INDEX IF NOT EXISTS idx_memories_content_trgm
    ON memories USING gin (content gin_trgm_ops);
