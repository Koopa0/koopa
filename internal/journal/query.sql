-- name: CreateEntry :one
-- Insert a journal entry.
INSERT INTO journal (kind, source, content, metadata, entry_date)
VALUES (@kind, @source, @content, @metadata, @entry_date)
RETURNING id, kind, source, content, metadata, entry_date, created_at;

-- name: EntryByID :one
-- Get a single journal entry by ID.
SELECT id, kind, source, content, metadata, entry_date, created_at
FROM journal
WHERE id = @id;

-- name: EntriesByDateRange :many
-- List journal entries in a date range, optionally filtered by kind and/or source.
SELECT id, kind, source, content, metadata, entry_date, created_at
FROM journal
WHERE entry_date >= @start_date
  AND entry_date <= @end_date
  AND (sqlc.narg('kind')::text IS NULL OR kind = sqlc.narg('kind'))
  AND (sqlc.narg('source')::text IS NULL OR source = sqlc.narg('source'))
ORDER BY entry_date DESC, created_at DESC;

-- name: LatestEntryByKind :one
-- Get the most recent journal entry of a specific kind.
SELECT id, kind, source, content, metadata, entry_date, created_at
FROM journal
WHERE kind = @kind
ORDER BY entry_date DESC, created_at DESC
LIMIT 1;

-- name: ReflectionForDate :many
-- Get reflection journal entries for a specific date.
SELECT id, kind, source, content, metadata, entry_date, created_at
FROM journal
WHERE kind = 'reflection' AND entry_date = @entry_date
ORDER BY created_at DESC;
