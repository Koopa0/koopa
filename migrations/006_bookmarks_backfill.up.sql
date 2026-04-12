-- Track B M2: backfill bookmarks from contents WHERE type='bookmark'.
--
-- Prerequisites:
--   - 005_bookmarks_schema.up.sql has run. bookmarks / bookmark_topics /
--     bookmark_tags exist.
--   - contents.type='bookmark' rows still exist. This migration does NOT
--     delete them — M3 cutover (future Wave) is responsible for that.
--
-- What this migration does:
--   1. INSERT one bookmark per contents.type='bookmark' row, joining on
--      feed_entries.curated_content_id to recover the external URL.
--   2. Backfill bookmark_topics from content_topics.
--   3. Backfill bookmark_tags from content_tags.
--   4. Write a tombstone marker into contents.ai_metadata pointing at
--      the new bookmark id, so downstream readers that still hit the
--      old row know where it moved.
--   5. RAISE NOTICE with before/after counts for manual verification.
--
-- Orphan handling:
--   Bookmarks that have no corresponding feed_entries row (manual captures,
--   if any) cannot recover url/url_hash without parsing the body markdown.
--   The single existing write path (manage_content.bookmark_rss) always
--   links a feed_entries row, so in practice the orphan set is empty. If
--   any are found, they are logged via NOTICE and left in contents for
--   M3 to handle.
--
-- Reversal: 006_bookmarks_backfill.down.sql reverses all five steps.

DO $$
DECLARE
    total_bookmark_contents INT;
    backfilled_count        INT;
    orphan_count            INT;
BEGIN
    SELECT COUNT(*) INTO total_bookmark_contents
    FROM contents WHERE type = 'bookmark';

    -- Step 1: insert feed-sourced bookmarks.
    --
    -- DISTINCT ON (c.id) picks exactly one feed_entry per content row in
    -- the unlikely case that two feed_entries point at the same content.
    -- Ordering by fe.collected_at ASC means the earliest curation wins,
    -- which matches the historical "first to curate" intent.
    WITH inserted AS (
        INSERT INTO bookmarks (
            url, url_hash, slug, title, excerpt, note,
            source_type, source_feed_entry_id,
            curated_by, curated_at, is_public, published_at,
            embedding, legacy_content_id,
            created_at, updated_at
        )
        SELECT DISTINCT ON (c.id)
            fe.source_url                              AS url,
            fe.url_hash                                AS url_hash,
            c.slug                                     AS slug,
            c.title                                    AS title,
            c.excerpt                                  AS excerpt,
            c.body                                     AS note,
            'rss'::text                                AS source_type,
            fe.id                                      AS source_feed_entry_id,
            'human'::text                              AS curated_by,
            c.created_at                               AS curated_at,
            c.is_public                                AS is_public,
            c.published_at                             AS published_at,
            c.embedding                                AS embedding,
            c.id                                       AS legacy_content_id,
            c.created_at                               AS created_at,
            c.updated_at                               AS updated_at
        FROM contents c
        JOIN feed_entries fe ON fe.curated_content_id = c.id
        WHERE c.type = 'bookmark'
        ORDER BY c.id, fe.collected_at ASC
        ON CONFLICT (url_hash) DO NOTHING
        RETURNING legacy_content_id
    )
    SELECT COUNT(*) INTO backfilled_count FROM inserted;

    -- Step 2: backfill bookmark_topics from content_topics.
    INSERT INTO bookmark_topics (bookmark_id, topic_id)
    SELECT b.id, ct.topic_id
    FROM bookmarks b
    JOIN content_topics ct ON ct.content_id = b.legacy_content_id
    WHERE b.legacy_content_id IS NOT NULL
    ON CONFLICT DO NOTHING;

    -- Step 3: backfill bookmark_tags from content_tags.
    INSERT INTO bookmark_tags (bookmark_id, tag_id)
    SELECT b.id, ct.tag_id
    FROM bookmarks b
    JOIN content_tags ct ON ct.content_id = b.legacy_content_id
    WHERE b.legacy_content_id IS NOT NULL
    ON CONFLICT DO NOTHING;

    -- Step 4: tombstone the legacy contents row. jsonb_set creates the
    -- top-level object if ai_metadata is NULL. The marker points at the
    -- new bookmark id so M3 cutover (and any interim reader) can follow
    -- it if needed.
    UPDATE contents c
    SET ai_metadata = jsonb_set(
            COALESCE(c.ai_metadata, '{}'::jsonb),
            '{migrated_to_bookmark_id}',
            to_jsonb(b.id::text),
            true
        ),
        updated_at = now()
    FROM bookmarks b
    WHERE b.legacy_content_id = c.id;

    -- Step 5: report counts. orphan_count = bookmark-typed contents rows
    -- that the JOIN did not match. Expected to be zero in practice; any
    -- nonzero value is logged for manual M3 follow-up.
    orphan_count := total_bookmark_contents - backfilled_count;

    RAISE NOTICE 'bookmark backfill: % total contents.type=bookmark, % backfilled, % orphans (no feed_entry match)',
        total_bookmark_contents, backfilled_count, orphan_count;

    IF orphan_count > 0 THEN
        RAISE NOTICE 'orphan bookmark contents (no feed_entry, left in contents for M3): %',
            (SELECT array_agg(id) FROM contents c
             WHERE c.type = 'bookmark'
               AND NOT EXISTS (SELECT 1 FROM bookmarks b WHERE b.legacy_content_id = c.id));
    END IF;
END $$;
