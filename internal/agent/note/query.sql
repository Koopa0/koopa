-- name: CreateAgentNote :one
-- Insert an agent note entry.
INSERT INTO agent_notes (kind, author, content, metadata, entry_date)
VALUES (@kind::agent_note_kind, @author, @content, @metadata, @entry_date)
RETURNING id, kind, author, content, metadata, entry_date, created_at;

-- name: AgentNoteByID :one
-- Get a single agent note by ID.
SELECT id, kind, author, content, metadata, entry_date, created_at
FROM agent_notes
WHERE id = @id;

-- name: AgentNotesByDateRange :many
-- List agent notes in a date range, optionally filtered by kind and/or author.
SELECT id, kind, author, content, metadata, entry_date, created_at
FROM agent_notes
WHERE entry_date >= @start_date
  AND entry_date <= @end_date
  AND (sqlc.narg('kind')::agent_note_kind IS NULL OR kind = sqlc.narg('kind')::agent_note_kind)
  AND (sqlc.narg('author')::text IS NULL OR author = sqlc.narg('author'))
ORDER BY entry_date DESC, created_at DESC;

-- name: LatestAgentNoteByKind :one
-- Get the most recent agent note of a specific kind.
SELECT id, kind, author, content, metadata, entry_date, created_at
FROM agent_notes
WHERE kind = @kind::agent_note_kind
ORDER BY entry_date DESC, created_at DESC
LIMIT 1;

-- name: ReflectionNotesForDate :many
-- Get reflection notes for a specific date.
SELECT id, kind, author, content, metadata, entry_date, created_at
FROM agent_notes
WHERE kind = 'reflection' AND entry_date = @entry_date
ORDER BY created_at DESC;
