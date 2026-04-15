-- name: CollectedData :many
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.relevance_score, cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.user_feedback, cd.feedback_at, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
LEFT JOIN feeds f ON cd.feed_id = f.id
WHERE (sqlc.narg('status')::feed_entry_status IS NULL OR cd.status = sqlc.narg('status'))
ORDER BY COALESCE(cd.published_at, cd.collected_at) DESC
LIMIT $1 OFFSET $2;

-- name: CollectedDataCount :one
SELECT COUNT(*) FROM feed_entries
WHERE (sqlc.narg('status')::feed_entry_status IS NULL OR status = sqlc.narg('status'));

-- name: CollectedDataByID :one
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.relevance_score, cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.user_feedback, cd.feedback_at, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
LEFT JOIN feeds f ON cd.feed_id = f.id
WHERE cd.id = $1;

-- name: CollectedDataByURLHash :one
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.relevance_score, cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.user_feedback, cd.feedback_at, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
LEFT JOIN feeds f ON cd.feed_id = f.id
WHERE cd.url_hash = $1;

-- name: CreateCollectedData :one
INSERT INTO feed_entries (source_url, title, original_content, url_hash, feed_id, relevance_score, published_at)
VALUES ($1, $2, $3, $4, sqlc.narg('feed_id'), @relevance_score, sqlc.narg('published_at'))
RETURNING id, source_url, title, original_content,
          relevance_score, status, curated_content_id, collected_at,
          url_hash, user_feedback, feedback_at, feed_id, published_at;

-- name: UpdateCollectedFeedback :exec
UPDATE feed_entries SET user_feedback = $2, feedback_at = now() WHERE id = $1;

-- name: CurateCollected :one
UPDATE feed_entries SET status = 'curated', curated_content_id = sqlc.narg('curated_content_id')
WHERE id = $1
RETURNING id, source_url, title, original_content,
          relevance_score, status, curated_content_id, collected_at,
          url_hash, user_feedback, feedback_at, feed_id, published_at;

-- name: IgnoreCollected :exec
UPDATE feed_entries SET status = 'ignored' WHERE id = $1;

-- name: RecentCollectedData :many
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.relevance_score, cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.user_feedback, cd.feedback_at, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
LEFT JOIN feeds f ON cd.feed_id = f.id
WHERE cd.collected_at >= $1 AND cd.collected_at < $2
ORDER BY COALESCE(cd.published_at, cd.collected_at) DESC
LIMIT $3;

-- name: LatestCollectedData :many
-- Get latest collected data, optionally filtered by time range.
-- When days is NULL, returns the latest N items regardless of time.
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.relevance_score, cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.user_feedback, cd.feedback_at, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
LEFT JOIN feeds f ON cd.feed_id = f.id
WHERE (sqlc.narg('since')::timestamptz IS NULL OR cd.collected_at >= sqlc.narg('since'))
ORDER BY COALESCE(cd.published_at, cd.collected_at) DESC
LIMIT @max_results;

-- name: CollectedDataByRelevance :many
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.relevance_score, cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.user_feedback, cd.feedback_at, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
LEFT JOIN feeds f ON cd.feed_id = f.id
WHERE (sqlc.narg('status')::feed_entry_status IS NULL OR cd.status = sqlc.narg('status'))
ORDER BY cd.relevance_score DESC, COALESCE(cd.published_at, cd.collected_at) DESC
LIMIT $1 OFFSET $2;

-- name: TopRelevantCollected :many
-- Get top unread collected data since a given time.
-- Score filter removed: scoring pipeline not yet active, all items have score=0.
-- When scoring is implemented, restore relevance_score > 0.5 threshold.
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.relevance_score, cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.user_feedback, cd.feedback_at, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
LEFT JOIN feeds f ON cd.feed_id = f.id
WHERE cd.collected_at >= @since
  AND cd.status = 'unread'
ORDER BY COALESCE(cd.published_at, cd.collected_at) DESC
LIMIT @max_results;

-- name: LatestCollectedByRecency :many
-- Get latest collected data ordered by recency (collected_at DESC), optionally filtered by time.
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.relevance_score, cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.user_feedback, cd.feedback_at, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
LEFT JOIN feeds f ON cd.feed_id = f.id
WHERE (sqlc.narg('since')::timestamptz IS NULL OR cd.collected_at >= sqlc.narg('since'))
ORDER BY cd.collected_at DESC
LIMIT @max_results;

-- name: HighPriorityRecentCollected :many
-- Get unread collected data from high-priority feeds in the past N hours.
SELECT cd.id, cd.source_url, cd.title, cd.original_content,
       cd.relevance_score, cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.user_feedback, cd.feedback_at, cd.feed_id, cd.published_at,
       COALESCE(f.name, '') AS feed_name
FROM feed_entries cd
JOIN feeds f ON cd.feed_id = f.id
WHERE f.priority = 'high'
  AND cd.status = 'unread'
  AND cd.collected_at >= @since
ORDER BY COALESCE(cd.published_at, cd.collected_at) DESC
LIMIT @max_results;

-- name: DeleteOldIgnored :execrows
-- Cleanup: delete ignored collected data older than the given cutoff.
DELETE FROM feed_entries WHERE status = 'ignored' AND collected_at < @cutoff;

-- name: CollectionStatsByFeed :many
-- Per-feed aggregation since cutoff. Optional feed_id filter via narg.
-- last_collected_at returns zero-time for feeds that have never been
-- collected (LEFT JOIN with no matches → MAX is NULL → COALESCE to
-- epoch). Caller checks IsZero() to distinguish "never collected".
SELECT f.id, f.name,
       COUNT(cd.id)::int AS total_items,
       COALESCE(AVG(cd.relevance_score), 0)::float8 AS avg_score,
       COALESCE(MAX(cd.collected_at), '0001-01-01'::timestamptz)::timestamptz AS last_collected_at
FROM feeds f
LEFT JOIN feed_entries cd ON cd.feed_id = f.id AND cd.collected_at >= @cutoff
WHERE (sqlc.narg('feed_id')::uuid IS NULL OR f.id = sqlc.narg('feed_id'))
GROUP BY f.id, f.name
ORDER BY total_items DESC;

-- name: CollectionStatsGlobal :one
-- Global aggregation since cutoff. Optional feed_id filter via narg.
SELECT COUNT(*)::int AS total_items,
       COUNT(DISTINCT feed_id)::int AS total_feeds,
       COALESCE(AVG(relevance_score), 0)::float8 AS avg_score,
       COUNT(*) FILTER (WHERE status = 'unread')::int AS unread_count,
       COUNT(*) FILTER (WHERE status = 'curated')::int AS curated_count
FROM feed_entries
WHERE collected_at >= @cutoff
  AND (sqlc.narg('feed_id')::uuid IS NULL OR feed_id = sqlc.narg('feed_id'));
