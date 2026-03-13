-- Partial index for published content queries (PublishedContents, PublishedForRSS,
-- AllPublishedSlugs, SearchContents, PublishedContentsByDateRange, etc.)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_contents_published_at_pub
    ON contents (published_at DESC NULLS LAST)
    WHERE status = 'published';

-- Partial index for Obsidian sync slug lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_contents_source_obsidian
    ON contents (source_type)
    WHERE source_type = 'obsidian';

-- Partial index for latest completed flow run lookups
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_flow_runs_completed
    ON flow_runs (content_id, flow_name, ended_at DESC)
    WHERE status = 'completed';
