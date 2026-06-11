-- Queries for the reading package. See migrations/004_readings.up.sql for
-- the readings + reading_reflections tables. status is TEXT + CHECK (not an
-- ENUM); the Go layer validates before writing so the constraint never
-- surfaces as a 500. No audit triggers fire on these tables — single human
-- writer, diary stays out of activity feeds (rationale in the migration).

-- name: CreateReading :one
INSERT INTO readings (
    title, author, status, started_on
) VALUES (
    $1, $2, $3, $4
)
RETURNING id, title, author, status, started_on, finished_on, is_public,
          created_at, updated_at;

-- name: ReadingByID :one
SELECT id, title, author, status, started_on, finished_on, is_public,
       created_at, updated_at
FROM readings
WHERE id = $1;

-- name: Readings :many
-- Shelf list with optional status filter. Ordered by recency of edit —
-- status-group ordering for the shelf view is the frontend's concern.
SELECT id, title, author, status, started_on, finished_on, is_public,
       created_at, updated_at
FROM readings
WHERE (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status'))
ORDER BY updated_at DESC;

-- name: UpdateReading :one
-- Partial update — omitted (NULL) args leave the column unchanged, so
-- nullable dates cannot be cleared back to NULL through this query.
-- finished_on resolution order: explicit caller value wins, then the
-- existing value, then the convenience auto-stamp — CURRENT_DATE when this
-- update sets status to finished. The existing-value guard means a repeat
-- "finished" update never silently moves an already-recorded finish date.
UPDATE readings SET
    title = COALESCE(sqlc.narg('title'), title),
    author = COALESCE(sqlc.narg('author'), author),
    status = COALESCE(sqlc.narg('status')::text, status),
    started_on = COALESCE(sqlc.narg('started_on')::date, started_on),
    finished_on = COALESCE(
        sqlc.narg('finished_on')::date,
        finished_on,
        CASE WHEN sqlc.narg('status')::text = 'finished' THEN CURRENT_DATE END
    ),
    is_public = COALESCE(sqlc.narg('is_public')::boolean, is_public),
    updated_at = now()
WHERE id = @id
RETURNING id, title, author, status, started_on, finished_on, is_public,
          created_at, updated_at;

-- name: DeleteReading :execrows
-- ON DELETE CASCADE removes the book's entire diary with it.
DELETE FROM readings WHERE id = $1;

-- name: CreateReflection :one
-- A NULL entry_date defaults to today. COALESCE here rather than relying
-- on the column DEFAULT so the "today" clock is the same (the database's
-- CURRENT_DATE) whether the handler passes a date or not — and the same
-- clock the finished auto-stamp in UpdateReading uses.
INSERT INTO reading_reflections (
    reading_id, entry_date, body
) VALUES (
    $1, COALESCE(sqlc.narg('entry_date')::date, CURRENT_DATE), $2
)
RETURNING id, reading_id, entry_date, body, created_at, updated_at;

-- name: ReflectionsForReading :many
-- The diary thread for one book: diary-date order, creation order as the
-- same-day tiebreak. Served by idx_reading_reflections_thread.
SELECT id, reading_id, entry_date, body, created_at, updated_at
FROM reading_reflections
WHERE reading_id = $1
ORDER BY entry_date ASC, created_at ASC;

-- name: UpdateReflection :one
-- Partial update of a diary entry, bound to its parent reading: the WHERE
-- clause enforces membership, so a {reading_id, id} mismatch is a no-row
-- miss (404) rather than a cross-book write.
UPDATE reading_reflections SET
    body = COALESCE(sqlc.narg('body'), body),
    entry_date = COALESCE(sqlc.narg('entry_date')::date, entry_date),
    updated_at = now()
WHERE id = @id AND reading_id = @reading_id
RETURNING id, reading_id, entry_date, body, created_at, updated_at;

-- name: DeleteReflection :execrows
-- Delete a diary entry, bound to its parent reading (same membership guard
-- as UpdateReflection).
DELETE FROM reading_reflections WHERE id = @id AND reading_id = @reading_id;
