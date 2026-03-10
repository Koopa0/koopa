-- name: CollectedData :many
SELECT id, source_url, source_name, title, original_content, ai_summary,
       relevance_score, topics, status, curated_content_id, collected_at
FROM collected_data
WHERE (sqlc.narg('status')::collected_status IS NULL OR status = sqlc.narg('status'))
ORDER BY collected_at DESC
LIMIT $1 OFFSET $2;

-- name: CollectedDataCount :one
SELECT COUNT(*) FROM collected_data
WHERE (sqlc.narg('status')::collected_status IS NULL OR status = sqlc.narg('status'));

-- name: CollectedDataByID :one
SELECT id, source_url, source_name, title, original_content, ai_summary,
       relevance_score, topics, status, curated_content_id, collected_at
FROM collected_data WHERE id = $1;

-- name: CurateCollected :one
UPDATE collected_data SET status = 'curated', curated_content_id = sqlc.narg('curated_content_id')
WHERE id = $1
RETURNING id, source_url, source_name, title, original_content, ai_summary,
          relevance_score, topics, status, curated_content_id, collected_at;

-- name: IgnoreCollected :exec
UPDATE collected_data SET status = 'ignored' WHERE id = $1;
