-- name: GetCard :one
-- Get the current FSRS card for a (content_id, tag) pair.
-- tag IS NULL matches rows where tag is NULL (whole-content review).
SELECT id, content_id, tag, card_state, due, created_at, updated_at
FROM fsrs_cards
WHERE content_id = @content_id
  AND ((sqlc.narg('tag')::text IS NULL AND tag IS NULL) OR tag = sqlc.narg('tag'));

-- name: UpsertCard :one
-- Create or update a card's FSRS state and due date.
INSERT INTO fsrs_cards (content_id, tag, card_state, due)
VALUES (@content_id, @tag, @card_state, @due)
ON CONFLICT (content_id, COALESCE(tag, '')) DO UPDATE SET
    card_state = EXCLUDED.card_state,
    due        = EXCLUDED.due,
    updated_at = now()
RETURNING id;

-- name: InsertReviewLog :exec
INSERT INTO fsrs_review_logs (card_id, rating, scheduled_days, elapsed_days, state, reviewed_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: DueCards :many
-- Cards where due <= now, ordered by most urgent first.
SELECT
    fc.id AS card_id,
    fc.content_id,
    fc.tag,
    fc.card_state,
    fc.due,
    c.slug,
    c.title,
    c.ai_metadata
FROM fsrs_cards fc
JOIN contents c ON c.id = fc.content_id
LEFT JOIN projects p ON p.id = c.project_id
WHERE fc.due <= @now
  AND (sqlc.narg('project_id')::uuid IS NULL OR c.project_id = sqlc.narg('project_id'))
ORDER BY fc.due ASC
LIMIT @lim;

-- name: NeverReviewedTILs :many
-- Recent TIL entries (1-7 days old) that have no fsrs_card yet.
SELECT c.id, c.slug, c.title, c.ai_metadata, c.created_at
FROM contents c
LEFT JOIN projects p ON p.id = c.project_id
WHERE c.type = 'til'
  AND (sqlc.narg('project_id')::uuid IS NULL OR c.project_id = sqlc.narg('project_id'))
  AND c.created_at >= now() - interval '7 days'
  AND c.created_at <= now() - interval '1 day'
  AND NOT EXISTS (
      SELECT 1 FROM fsrs_cards fc WHERE fc.content_id = c.id
  )
ORDER BY c.created_at ASC
LIMIT @lim;
