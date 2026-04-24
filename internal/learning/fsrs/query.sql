-- name: CardByLearningTarget :one
-- Get the review card for a learning target.
SELECT * FROM review_cards WHERE learning_target_id = @learning_target_id;

-- name: CreateCardForLearningTarget :one
-- Create a new FSRS review card for a learning target.
INSERT INTO review_cards (learning_target_id, card_state, due)
VALUES (@learning_target_id, @card_state, @due)
RETURNING *;

-- name: UpdateCardState :one
-- Update card state and due date after a review. Clears drift markers since
-- a successful review reconciles the card with the attempt history.
UPDATE review_cards
SET card_state         = @card_state,
    due                = @due,
    last_sync_drift_at = NULL,
    last_drift_reason  = NULL,
    updated_at         = now()
WHERE id = @id
RETURNING *;

-- name: MarkCardDrift :execrows
-- Stamp a drift event on a card when an attempt-driven review cannot be
-- applied cleanly. Consumers of the retrieval view compare last_sync_drift_at
-- against recent attempt timestamps to decide whether to surface a
-- drift_suspect flag on each due item. Both columns are paired by
-- chk_review_card_drift_pair. Returns the number of rows affected so callers
-- can log when a target has no card yet (drift signal silently lost).
UPDATE review_cards
SET last_sync_drift_at = now(),
    last_drift_reason  = @reason,
    updated_at         = now()
WHERE learning_target_id = @learning_target_id;

-- name: InsertReviewLog :exec
-- Append a review log entry after rating a card.
INSERT INTO review_logs (card_id, rating, scheduled_days, elapsed_days, state, reviewed_at)
VALUES (@card_id, @rating, @scheduled_days, @elapsed_days, @state, @reviewed_at);

-- name: DueReviewCount :one
-- Count of review cards due before a given time (for needs_attention badge).
SELECT count(*)::int FROM review_cards WHERE due <= @due_before;

-- name: LearningTargetByCardID :one
-- Resolve a review card's learning_target_id for the wire-contract case where
-- the caller (REST handler) addresses the card directly but the scheduler
-- logic is target-scoped. Returns pgx.ErrNoRows when the card id is unknown.
SELECT learning_target_id FROM review_cards WHERE id = @id;
