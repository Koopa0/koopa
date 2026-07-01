-- name: FeedEntriesList :many
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
LEFT JOIN feeds f ON cd.feed_id = f.id
WHERE (sqlc.narg('status')::feed_entry_status IS NULL OR cd.status = sqlc.narg('status'))
ORDER BY COALESCE(cd.published_at, cd.collected_at) DESC
LIMIT $1 OFFSET $2;

-- name: FeedEntriesCount :one
SELECT COUNT(*) FROM feed_entries
WHERE (sqlc.narg('status')::feed_entry_status IS NULL OR status = sqlc.narg('status'));

-- name: CreateFeedEntries :many
-- Batch-inserts new feed entries for one feed in a single round trip.
-- ON CONFLICT (url_hash) DO NOTHING deduplicates against existing rows;
-- RETURNING yields only the ids that were actually inserted — conflicted
-- (already-collected) rows are silently absent — replacing the old
-- per-item dedup-SELECT-then-INSERT pattern with one statement.
--
-- published_at is per-item optional (a feed item may omit it), but a
-- Postgres array parameter can't carry a NULL element as a plain non-
-- nullable timestamptz[] without an sqlc type override affecting every
-- other nullable timestamptz column project-wide. @has_published sidesteps
-- that: the caller sends a real (dummy) timestamp plus a same-index
-- boolean, and the CASE converts it to a true SQL NULL here.
INSERT INTO feed_entries (source_url, title, original_content, url_hash, feed_id, published_at)
SELECT x.source_url, x.title, x.original_content, x.url_hash, sqlc.narg('feed_id')::uuid,
       CASE WHEN x.has_published THEN x.published_at ELSE NULL END
FROM ROWS FROM (
    unnest(@source_urls::text[]),
    unnest(@titles::text[]),
    unnest(@original_contents::text[]),
    unnest(@url_hashes::text[]),
    unnest(@published_ats::timestamptz[]),
    unnest(@has_published::bool[])
) AS x(source_url, title, original_content, url_hash, published_at, has_published)
ON CONFLICT (url_hash) DO NOTHING
RETURNING id;

-- name: CurateFeedEntry :one
UPDATE feed_entries SET status = 'curated', curated_content_id = sqlc.narg('curated_content_id')
WHERE id = $1
RETURNING id, source_url, title, original_content,
          status, curated_content_id, collected_at,
          url_hash, feed_id, published_at;

-- name: IgnoreFeedEntry :exec
UPDATE feed_entries SET status = 'ignored' WHERE id = $1;

-- name: HighPriorityRecentFeedEntries :many
-- Get unread collected data from high-priority feeds in the past N hours.
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
JOIN feeds f ON cd.feed_id = f.id
WHERE f.priority = 'high'
  AND cd.status = 'unread'
  AND cd.collected_at >= @since
ORDER BY COALESCE(cd.published_at, cd.collected_at) DESC
LIMIT @max_results;
