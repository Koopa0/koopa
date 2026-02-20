-- Add text_content for full-text search on messages.
-- content is JSONB ([]*ai.Part), not directly searchable.
-- text_content is application-maintained, populated in AddMessage.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS text_content TEXT;

-- Generated tsvector for FTS.
-- to_tsvector handles NULL natively (returns empty tsvector), no COALESCE needed.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS search_text tsvector
    GENERATED ALWAYS AS (to_tsvector('english', text_content)) STORED;

-- GIN index for fast full-text search.
CREATE INDEX IF NOT EXISTS idx_messages_search_text ON messages USING gin(search_text);

-- Backfill existing messages: extract text from JSONB parts.
UPDATE messages SET text_content = (
    SELECT string_agg(elem->>'text', ' ')
    FROM jsonb_array_elements(content) AS elem
    WHERE elem->>'text' IS NOT NULL AND elem->>'text' != ''
) WHERE text_content IS NULL;
