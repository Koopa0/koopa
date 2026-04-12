-- Track B M1: bookmarks split — additive schema only.
--
-- Context:
--   Bookmarks currently live as contents.type='bookmark' rows. That
--   polymorphism is the single decision most likely to become future
--   regret: first-party content (article/essay/build-log/til/note/
--   digest) and externally captured bookmarks share publish workflow,
--   review_queue semantics, RSS output, and SEO conventions that do
--   NOT actually match. See design pass in conversation history.
--
-- Scope of this migration:
--   CREATE the bookmarks table and its topic/tag junctions. Do NOT
--   touch contents, feed_entries, or review_queue. Do NOT backfill —
--   that is migration 006. This migration is fully reversible via
--   005_bookmarks_schema.down.sql.
--
-- What is intentionally NOT here:
--   - No content-type enum modification — bookmark remains valid in
--     contents.type until M3 cutover.
--   - No change to feed_entries.curated_content_id — both forward
--     (feed_entry → content) and reverse (bookmark → feed_entry) FKs
--     will coexist through M2. M3 decides which survives.
--   - No bookmarks.review_queue link — bookmarks skip editorial review
--     by design (curate = publish).

CREATE TABLE bookmarks (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url                  TEXT NOT NULL,
    url_hash             TEXT NOT NULL,
    slug                 TEXT NOT NULL,
    title                TEXT NOT NULL,
    excerpt              TEXT NOT NULL DEFAULT '',
    note                 TEXT NOT NULL DEFAULT '',
    source_type          TEXT NOT NULL
        CHECK (source_type IN ('rss', 'manual', 'shared')),
    source_feed_entry_id UUID REFERENCES feed_entries(id) ON DELETE SET NULL,
    curated_by           TEXT NOT NULL,
    curated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_public            BOOLEAN NOT NULL DEFAULT true,
    published_at         TIMESTAMPTZ,
    embedding            vector(768),
    legacy_content_id    UUID REFERENCES contents(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uniq_bookmarks_url_hash UNIQUE (url_hash),
    CONSTRAINT uniq_bookmarks_slug UNIQUE (slug),
    CONSTRAINT uniq_bookmarks_legacy_content_id UNIQUE (legacy_content_id)
);

COMMENT ON TABLE bookmarks IS 'External resources curated with personal commentary. Separate from contents because bookmarks skip editorial review (curate = publish), have an external canonical URL, and do not share the first-party publish workflow. Populated by M2 backfill from contents.type=bookmark; new writes go here once M3 cuts over.';

COMMENT ON COLUMN bookmarks.url IS 'Canonical external URL of the bookmarked resource. SEO canonical tag points to this value.';
COMMENT ON COLUMN bookmarks.url_hash IS 'SHA-256 hex digest of the canonical URL. Dedup identity. Computed in application code before INSERT — matches feed_entries.url_hash semantics.';
COMMENT ON COLUMN bookmarks.slug IS 'URL-safe internal identifier for bookmark permalinks on the koopa0.dev site. Distinct from the external URL.';
COMMENT ON COLUMN bookmarks.title IS 'Display title. May override the source title if the curator edited it at capture time.';
COMMENT ON COLUMN bookmarks.excerpt IS 'Short excerpt from the source, typically truncated to a few sentences. Empty string when the source provided none.';
COMMENT ON COLUMN bookmarks.note IS 'Curator''s personal commentary. The reason this bookmark is worth remembering. Empty string when no note.';
COMMENT ON COLUMN bookmarks.source_type IS 'How the bookmark entered the system: rss (curated from feed_entries), manual (pasted by curator), shared (received via external channel).';
COMMENT ON COLUMN bookmarks.source_feed_entry_id IS 'If source_type=rss, references the originating feed_entries row. NULL for manual/shared bookmarks. SET NULL on feed_entry deletion — bookmark survives independently.';
COMMENT ON COLUMN bookmarks.curated_by IS 'Participant id that curated the bookmark (e.g. "hq", "human"). Not an FK — participants may be renamed without rewriting history.';
COMMENT ON COLUMN bookmarks.curated_at IS 'When the bookmark was curated into koopa0.dev. Distinct from source publication date.';
COMMENT ON COLUMN bookmarks.is_public IS 'Whether this bookmark is visible on the public website. Private bookmarks are admin/MCP only.';
COMMENT ON COLUMN bookmarks.published_at IS 'When the bookmark became publicly visible. NULL = private or not yet published. Unlike contents, bookmarks typically have published_at = curated_at.';
COMMENT ON COLUMN bookmarks.embedding IS 'pgvector embedding (768d) for semantic search inclusion. Optional — backfill may leave NULL for rows whose source content was never embedded.';
COMMENT ON COLUMN bookmarks.legacy_content_id IS 'Bridge to the contents row this bookmark was backfilled from. Populated in M2 only. UNIQUE enforces 1:1 mapping during the migration window. Stays NULL for bookmarks created after M3 cutover. SET NULL if the legacy content row is ever deleted.';

CREATE INDEX idx_bookmarks_published_at ON bookmarks(published_at DESC NULLS LAST)
    WHERE is_public = true;
CREATE INDEX idx_bookmarks_curated_at ON bookmarks(curated_at DESC);
CREATE INDEX idx_bookmarks_source_feed_entry ON bookmarks(source_feed_entry_id)
    WHERE source_feed_entry_id IS NOT NULL;
CREATE INDEX idx_bookmarks_embedding_hnsw ON bookmarks USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- ============================================================
-- Junction: bookmarks ↔ topics, bookmarks ↔ tags
-- ============================================================
-- Mirrors content_topics / content_tags shape. Separate tables
-- rather than a shared taggable polymorphism because polymorphic
-- junctions would require either a type column (loses FK integrity)
-- or a STI pattern (fights Postgres). Two small tables cost little.

CREATE TABLE bookmark_topics (
    bookmark_id UUID NOT NULL REFERENCES bookmarks(id) ON DELETE CASCADE,
    topic_id    UUID NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    PRIMARY KEY (bookmark_id, topic_id)
);

COMMENT ON TABLE bookmark_topics IS 'Junction: bookmark ↔ topic. Many-to-many. Topics are curated knowledge domain categories (same taxonomy as content_topics).';

CREATE INDEX idx_bookmark_topics_topic_id ON bookmark_topics(topic_id);

CREATE TABLE bookmark_tags (
    bookmark_id UUID NOT NULL REFERENCES bookmarks(id) ON DELETE CASCADE,
    tag_id      UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (bookmark_id, tag_id)
);

COMMENT ON TABLE bookmark_tags IS 'Junction: bookmark ↔ tag. References canonical tags resolved through the tag_aliases pipeline.';

CREATE INDEX idx_bookmark_tags_tag_id ON bookmark_tags(tag_id);
