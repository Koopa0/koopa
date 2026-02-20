DROP INDEX IF EXISTS idx_memories_content_trgm;
DROP INDEX IF EXISTS idx_messages_text_content_trgm;
-- Do not drop pg_trgm extension; other schemas may use it.
