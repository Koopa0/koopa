-- name: PendingReviewExistsForContent :one
SELECT EXISTS(
    SELECT 1 FROM review_queue
    WHERE content_id = $1 AND status = 'pending'
) AS exists;

-- name: CreateReview :one
INSERT INTO review_queue (content_id, review_level, reviewer_notes)
VALUES ($1, $2, $3)
RETURNING id, content_id, review_level::text AS rq_review_level,
          status::text AS rq_status, reviewer_notes, submitted_at, reviewed_at;

-- name: PendingReviews :many
SELECT rq.id, rq.content_id, rq.review_level::text AS rq_review_level,
       rq.status::text AS rq_status, rq.reviewer_notes, rq.submitted_at, rq.reviewed_at,
       c.title AS content_title, c.slug AS content_slug, c.type::text AS content_type
FROM review_queue rq
JOIN contents c ON c.id = rq.content_id
WHERE rq.status = 'pending'
  AND c.status != 'published'
ORDER BY rq.submitted_at;

-- name: ReviewByID :one
SELECT id, content_id, review_level::text AS rq_review_level,
       status::text AS rq_status, reviewer_notes, submitted_at, reviewed_at
FROM review_queue WHERE id = $1;

-- name: ApproveReview :exec
UPDATE review_queue SET status = 'approved', reviewed_at = now() WHERE id = $1;

-- name: RejectReview :exec
UPDATE review_queue SET status = 'rejected', reviewer_notes = $2, reviewed_at = now() WHERE id = $1;
