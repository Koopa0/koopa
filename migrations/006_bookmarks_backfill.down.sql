-- Reverse of 006_bookmarks_backfill.up.sql.
--
-- Reversal order:
--   1. Strip the migrated_to_bookmark_id tombstone from contents.ai_metadata
--      for every row whose migrated bookmark we are about to drop.
--   2. DELETE bookmarks WHERE legacy_content_id IS NOT NULL — this catches
--      exactly the rows produced by the backfill. ON DELETE CASCADE takes
--      care of bookmark_topics and bookmark_tags.
--
-- This migration is safe to run even if bookmarks were added after the
-- backfill (e.g. via the new Create endpoint). Such rows have
-- legacy_content_id IS NULL and are left alone.

-- Strip tombstone first — after the bookmarks row is gone, the
-- legacy_content_id join we rely on disappears.
UPDATE contents c
SET ai_metadata = c.ai_metadata - 'migrated_to_bookmark_id',
    updated_at  = now()
FROM bookmarks b
WHERE b.legacy_content_id = c.id
  AND c.ai_metadata ? 'migrated_to_bookmark_id';

DELETE FROM bookmarks
WHERE legacy_content_id IS NOT NULL;
