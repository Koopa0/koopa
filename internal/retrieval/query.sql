-- name: InsertAttempt :one
INSERT INTO retrieval_attempts (content_id, tag, quality, interval_days, ease_factor, next_due)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, content_id, tag, quality, interval_days, ease_factor, next_due, created_at;

-- name: LatestAttempt :one
-- Most recent attempt for a (content_id, tag) pair.
-- tag IS NULL matches rows where tag is NULL (whole-content retrieval).
SELECT id, content_id, tag, quality, interval_days, ease_factor, next_due, created_at
FROM retrieval_attempts
WHERE content_id = @content_id
  AND ((sqlc.narg('tag')::text IS NULL AND tag IS NULL) OR tag = sqlc.narg('tag'))
ORDER BY created_at DESC
LIMIT 1;

-- name: DueItems :many
-- Items where the most recent attempt's next_due has arrived.
-- Uses DISTINCT ON to get the latest attempt per (content_id, tag) pair.
WITH current_retrieval_state AS (
    SELECT DISTINCT ON (content_id, tag)
        content_id, tag, quality, interval_days, ease_factor, next_due, created_at
    FROM retrieval_attempts
    ORDER BY content_id, tag, created_at DESC
)
SELECT
    s.content_id, s.tag, s.quality AS last_quality,
    s.interval_days, s.ease_factor, s.next_due, s.created_at AS last_attempt_at,
    c.slug, c.title, c.ai_metadata
FROM current_retrieval_state s
JOIN contents c ON c.id = s.content_id
LEFT JOIN projects p ON p.id = c.project_id
WHERE s.next_due <= CURRENT_DATE + 1
  AND (sqlc.narg('project_slug')::text IS NULL OR p.slug = sqlc.narg('project_slug'))
ORDER BY s.next_due ASC, s.ease_factor ASC
LIMIT @lim;

-- name: NeverRetrievedItems :many
-- Recent TIL entries (1-7 days old) that have never been tested.
SELECT c.id, c.slug, c.title, c.tags, c.ai_metadata, c.created_at
FROM contents c
LEFT JOIN projects p ON p.id = c.project_id
WHERE c.type = 'til'
  AND (sqlc.narg('project_slug')::text IS NULL OR p.slug = sqlc.narg('project_slug'))
  AND c.created_at >= now() - interval '7 days'
  AND c.created_at <= now() - interval '1 day'
  AND NOT EXISTS (
      SELECT 1 FROM retrieval_attempts ra WHERE ra.content_id = c.id
  )
ORDER BY c.created_at ASC
LIMIT @lim;
