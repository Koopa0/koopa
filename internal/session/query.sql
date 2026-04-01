-- name: CreateNote :one
-- Insert a session note (plan, reflection, context, or metrics).
INSERT INTO session_notes (note_date, note_type, source, content, metadata)
VALUES (@note_date, @note_type, @source, @content, @metadata)
RETURNING id, note_date, note_type, source, content, metadata, created_at;

-- name: NotesByDate :many
-- List session notes for a date range, optionally filtered by type and/or source.
SELECT id, note_date, note_type, source, content, metadata, created_at
FROM session_notes
WHERE note_date >= @start_date
  AND note_date <= @end_date
  AND (sqlc.narg('note_type')::text IS NULL OR note_type = sqlc.narg('note_type'))
  AND (sqlc.narg('source')::text IS NULL OR source = sqlc.narg('source'))
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

-- name: NoteByID :one
-- Get a single session note by ID.
SELECT id, note_date, note_type, source, content, metadata, created_at
FROM session_notes
WHERE id = @id;

-- name: InsightsByStatus :many
-- Get insight notes, optionally filtered by status and project in metadata.
-- When filtering for 'unverified', also match empty string or NULL status
-- (insights saved before status was enforced).
SELECT id, note_date, note_type, source, content, metadata, created_at
FROM session_notes
WHERE note_type = 'insight'
  AND (
    sqlc.narg('status')::text IS NULL
    OR metadata->>'status' = sqlc.narg('status')
    OR (sqlc.narg('status') = 'unverified' AND (metadata->>'status' IS NULL OR metadata->>'status' = ''))
  )
  AND (sqlc.narg('project')::text IS NULL OR metadata->>'project' = sqlc.narg('project'))
ORDER BY created_at DESC
LIMIT @limit_val;

-- name: CountInsightsByStatus :one
-- Count insight notes by status in metadata.
-- Matches empty/NULL status as 'unverified' (same logic as InsightsByStatus).
SELECT count(*) FROM session_notes
WHERE note_type = 'insight'
  AND (
    sqlc.narg('status')::text IS NULL
    OR metadata->>'status' = sqlc.narg('status')
    OR (sqlc.narg('status') = 'unverified' AND (metadata->>'status' IS NULL OR metadata->>'status' = ''))
  );

-- name: UpdateNoteMetadata :one
-- Update metadata (and optionally content) of a session note.
UPDATE session_notes
SET metadata = @metadata
WHERE id = @id
RETURNING id, note_date, note_type, source, content, metadata, created_at;

-- name: ArchiveStaleInsights :execrows
-- Archive verified/invalidated insights older than the cutoff by setting metadata status to 'archived'.
UPDATE session_notes
SET metadata = jsonb_set(metadata, '{status}', '"archived"')
WHERE note_type = 'insight'
  AND metadata->>'status' IN ('verified', 'invalidated')
  AND created_at < @cutoff;

-- name: LatestNoteBySource :one
-- Get the most recent note from a specific source (e.g., "claude" for session gap calculation).
SELECT id, note_date, note_type, source, content, metadata, created_at
FROM session_notes
WHERE source = @source
ORDER BY note_date DESC, created_at DESC
LIMIT 1;

-- name: InsightsByCategory :many
-- Get insight notes filtered by status and category in metadata.
SELECT id, note_date, note_type, source, content, metadata, created_at
FROM session_notes
WHERE note_type = 'insight'
  AND metadata->>'status' = @status::text
  AND metadata->>'category' = @category::text
ORDER BY created_at DESC
LIMIT @max_results;

-- name: InsightsSince :many
-- Get all insight notes created since a given date (for session delta).
SELECT id, note_date, note_type, source, content, metadata, created_at
FROM session_notes
WHERE note_type = 'insight'
  AND note_date >= @since_date
ORDER BY created_at DESC;

-- name: DeleteOldNotes :execrows
-- Cleanup: delete short-lived notes (plan/reflection/context) after short_cutoff,
-- and long-lived notes (metrics/insight/directive/report) after long_cutoff.
DELETE FROM session_notes
WHERE (note_type NOT IN ('metrics', 'insight', 'directive', 'report') AND note_date < @short_cutoff)
   OR (note_type IN ('metrics', 'insight', 'directive', 'report') AND note_date < @long_cutoff);
