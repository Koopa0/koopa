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

-- name: FeedEntryByURLHash :one
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
LEFT JOIN feeds f ON cd.feed_id = f.id
WHERE cd.url_hash = $1;

-- name: CreateFeedEntry :one
INSERT INTO feed_entries (source_url, title, original_content, url_hash, feed_id, published_at)
VALUES ($1, $2, $3, $4, sqlc.narg('feed_id'), sqlc.narg('published_at'))
RETURNING id, source_url, title, original_content,
          status, curated_content_id, collected_at,
          url_hash, feed_id, published_at;

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
