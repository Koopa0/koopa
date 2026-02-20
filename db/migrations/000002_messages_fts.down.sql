DROP INDEX IF EXISTS idx_messages_search_text;
ALTER TABLE messages DROP COLUMN IF EXISTS search_text;
ALTER TABLE messages DROP COLUMN IF EXISTS text_content;
