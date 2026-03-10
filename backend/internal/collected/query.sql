-- name: CollectedData :many
SELECT id, source_url, source_name, title, original_content, ai_summary,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, ai_score, ai_score_reason, ai_summary_zh, ai_title_zh,
       user_feedback, feedback_at, feed_id
FROM collected_data
WHERE (sqlc.narg('status')::collected_status IS NULL OR status = sqlc.narg('status'))
ORDER BY collected_at DESC
LIMIT $1 OFFSET $2;

-- name: CollectedDataCount :one
SELECT COUNT(*) FROM collected_data
WHERE (sqlc.narg('status')::collected_status IS NULL OR status = sqlc.narg('status'));

-- name: CollectedDataByID :one
SELECT id, source_url, source_name, title, original_content, ai_summary,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, ai_score, ai_score_reason, ai_summary_zh, ai_title_zh,
       user_feedback, feedback_at, feed_id
FROM collected_data WHERE id = $1;

-- name: CollectedDataByURLHash :one
SELECT id, source_url, source_name, title, original_content, ai_summary,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, ai_score, ai_score_reason, ai_summary_zh, ai_title_zh,
       user_feedback, feedback_at, feed_id
FROM collected_data WHERE url_hash = $1;

-- name: CreateCollectedData :one
INSERT INTO collected_data (source_url, source_name, title, original_content, topics, url_hash, feed_id)
VALUES ($1, $2, $3, $4, $5, $6, sqlc.narg('feed_id'))
RETURNING id, source_url, source_name, title, original_content, ai_summary,
          relevance_score, topics, status, curated_content_id, collected_at,
          url_hash, ai_score, ai_score_reason, ai_summary_zh, ai_title_zh,
          user_feedback, feedback_at, feed_id;

-- name: UpdateCollectedScoring :exec
UPDATE collected_data
SET ai_score = $2, ai_score_reason = $3, ai_summary_zh = $4, ai_title_zh = $5, status = $6
WHERE id = $1;

-- name: UpdateCollectedFeedback :exec
UPDATE collected_data SET user_feedback = $2, feedback_at = now() WHERE id = $1;

-- name: CurateCollected :one
UPDATE collected_data SET status = 'curated', curated_content_id = sqlc.narg('curated_content_id')
WHERE id = $1
RETURNING id, source_url, source_name, title, original_content, ai_summary,
          relevance_score, topics, status, curated_content_id, collected_at,
          url_hash, ai_score, ai_score_reason, ai_summary_zh, ai_title_zh,
          user_feedback, feedback_at, feed_id;

-- name: IgnoreCollected :exec
UPDATE collected_data SET status = 'ignored' WHERE id = $1;

-- name: HighScoreCollectedData :many
SELECT id, source_url, source_name, title, original_content, ai_summary,
       relevance_score, topics, status, curated_content_id, collected_at,
       url_hash, ai_score, ai_score_reason, ai_summary_zh, ai_title_zh,
       user_feedback, feedback_at, feed_id
FROM collected_data
WHERE ai_score >= $1 AND collected_at >= $2 AND collected_at < $3
ORDER BY ai_score DESC;
