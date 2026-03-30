-- name: CollectedData :many
SELECT id, source_url, source_name, title, original_content,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, user_feedback, feedback_at, feed_id
FROM collected_data
WHERE (sqlc.narg('status')::collected_status IS NULL OR status = sqlc.narg('status'))
ORDER BY collected_at DESC
LIMIT $1 OFFSET $2;

-- name: CollectedDataCount :one
SELECT COUNT(*) FROM collected_data
WHERE (sqlc.narg('status')::collected_status IS NULL OR status = sqlc.narg('status'));

-- name: CollectedDataByID :one
SELECT id, source_url, source_name, title, original_content,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, user_feedback, feedback_at, feed_id
FROM collected_data WHERE id = $1;

-- name: CollectedDataByURLHash :one
SELECT id, source_url, source_name, title, original_content,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, user_feedback, feedback_at, feed_id
FROM collected_data WHERE url_hash = $1;

-- name: CreateCollectedData :one
INSERT INTO collected_data (source_url, source_name, title, original_content, topics, url_hash, feed_id, relevance_score)
VALUES ($1, $2, $3, $4, $5, $6, sqlc.narg('feed_id'), @relevance_score)
RETURNING id, source_url, source_name, title, original_content,
          relevance_score, topics, status, curated_content_id, collected_at,
          url_hash, user_feedback, feedback_at, feed_id;

-- name: UpdateCollectedFeedback :exec
UPDATE collected_data SET user_feedback = $2, feedback_at = now() WHERE id = $1;

-- name: CurateCollected :one
UPDATE collected_data SET status = 'curated', curated_content_id = sqlc.narg('curated_content_id')
WHERE id = $1
RETURNING id, source_url, source_name, title, original_content,
          relevance_score, topics, status, curated_content_id, collected_at,
          url_hash, user_feedback, feedback_at, feed_id;

-- name: IgnoreCollected :exec
UPDATE collected_data SET status = 'ignored' WHERE id = $1;

-- name: RecentCollectedData :many
SELECT id, source_url, source_name, title, original_content,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, user_feedback, feedback_at, feed_id
FROM collected_data
WHERE collected_at >= $1 AND collected_at < $2
ORDER BY relevance_score DESC, collected_at DESC
LIMIT $3;

-- name: LatestCollectedData :many
-- Get latest collected data, optionally filtered by time range.
-- When days is NULL, returns the latest N items regardless of time.
SELECT id, source_url, source_name, title, original_content,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, user_feedback, feedback_at, feed_id
FROM collected_data
WHERE (sqlc.narg('since')::timestamptz IS NULL OR collected_at >= sqlc.narg('since'))
ORDER BY relevance_score DESC, collected_at DESC
LIMIT @max_results;

-- name: CollectedDataByRelevance :many
SELECT id, source_url, source_name, title, original_content,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, user_feedback, feedback_at, feed_id
FROM collected_data
WHERE (sqlc.narg('status')::collected_status IS NULL OR status = sqlc.narg('status'))
ORDER BY relevance_score DESC, collected_at DESC
LIMIT $1 OFFSET $2;

-- name: TopRelevantCollected :many
-- Get top unread collected data since a given time.
-- Score filter removed: scoring pipeline not yet active, all items have score=0.
-- When scoring is implemented, restore relevance_score > 0.5 threshold.
SELECT id, source_url, source_name, title, original_content,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, user_feedback, feedback_at, feed_id
FROM collected_data
WHERE collected_at >= @since
  AND status = 'unread'
ORDER BY collected_at DESC
LIMIT @max_results;

-- name: LatestCollectedByRecency :many
-- Get latest collected data ordered by recency (collected_at DESC), optionally filtered by time.
SELECT id, source_url, source_name, title, original_content,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, user_feedback, feedback_at, feed_id
FROM collected_data
WHERE (sqlc.narg('since')::timestamptz IS NULL OR collected_at >= sqlc.narg('since'))
ORDER BY collected_at DESC
LIMIT @max_results;

-- name: HighPriorityRecentCollected :many
-- Get unread collected data from high-priority feeds in the past N hours.
SELECT cd.id, cd.source_url, cd.source_name, cd.title, cd.original_content,
       cd.relevance_score, cd.topics, cd.status, cd.curated_content_id, cd.collected_at,
       cd.url_hash, cd.user_feedback, cd.feedback_at, cd.feed_id
FROM collected_data cd
JOIN feeds f ON cd.feed_id = f.id
WHERE f.priority = 'high'
  AND cd.status = 'unread'
  AND cd.collected_at >= @since
ORDER BY cd.collected_at DESC
LIMIT @max_results;

-- name: DeleteOldIgnored :execrows
-- Cleanup: delete ignored collected data older than the given cutoff.
DELETE FROM collected_data WHERE status = 'ignored' AND collected_at < @cutoff;
