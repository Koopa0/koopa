-- name: CreateNote :one
-- Insert a session note (plan, reflection, context, or metrics).
INSERT INTO session_notes (note_date, note_type, source, content, metadata)
VALUES (@note_date, @note_type, @source, @content, @metadata)
RETURNING id, note_date, note_type, source, content, metadata, created_at;

-- name: NotesByDate :many
-- List session notes for a date range, optionally filtered by type.
SELECT id, note_date, note_type, source, content, metadata, created_at
FROM session_notes
WHERE note_date >= @start_date
  AND note_date <= @end_date
  AND (sqlc.narg('note_type')::text IS NULL OR note_type = sqlc.narg('note_type'))
ORDER BY created_at DESC;

-- name: LatestNoteByType :one
-- Get the most recent note of a specific type (e.g., latest reflection).
SELECT id, note_date, note_type, source, content, metadata, created_at
FROM session_notes
WHERE note_type = @note_type
ORDER BY note_date DESC, created_at DESC
LIMIT 1;

-- name: MetricsHistory :many
-- Get metrics notes for the last N days (for planning_history).
SELECT id, note_date, note_type, source, content, metadata, created_at
FROM session_notes
WHERE note_type = 'metrics'
  AND note_date >= @since_date
ORDER BY note_date DESC;

-- name: DeleteOldNotes :execrows
-- Cleanup: delete session notes older than the given cutoff.
DELETE FROM session_notes WHERE note_date < @cutoff;
