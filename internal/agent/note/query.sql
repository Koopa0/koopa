-- name: CreateAgentNote :one
-- Insert an agent note entry.
INSERT INTO agent_notes (kind, created_by, content, metadata, entry_date)
VALUES (@kind::agent_note_kind, @created_by, @content, @metadata, @entry_date)
RETURNING id, kind, created_by, content, metadata, entry_date, created_at;

-- name: AgentNoteByID :one
-- Get a single agent note by ID.
SELECT id, kind, created_by, content, metadata, entry_date, created_at
FROM agent_notes
WHERE id = @id;

-- name: AgentNotesByDateRange :many
-- List agent notes in a date range, optionally filtered by kind and/or created_by.
SELECT id, kind, created_by, content, metadata, entry_date, created_at
FROM agent_notes
WHERE entry_date >= @start_date
  AND entry_date <= @end_date
  AND (sqlc.narg('kind')::agent_note_kind IS NULL OR kind = sqlc.narg('kind')::agent_note_kind)
  AND (sqlc.narg('created_by')::text IS NULL OR created_by = sqlc.narg('created_by'))
ORDER BY entry_date DESC, created_at DESC;

-- name: LatestAgentNoteByKind :one
-- Get the most recent agent note of a specific kind.
SELECT id, kind, created_by, content, metadata, entry_date, created_at
FROM agent_notes
WHERE kind = @kind::agent_note_kind
ORDER BY entry_date DESC, created_at DESC
LIMIT 1;

-- name: ReflectionNotesForDate :many
-- Get reflection notes for a specific date.
SELECT id, kind, created_by, content, metadata, entry_date, created_at
FROM agent_notes
WHERE kind = 'reflection' AND entry_date = @entry_date
ORDER BY created_at DESC;

-- name: SearchAgentNotes :many
-- Full-text search over agent_notes.content using websearch_to_tsquery on
-- the simple tsvector config (GIN-indexed). Ordering is recency-first with
-- ts_rank as tiebreaker — an agent asking "what did I write about X?"
-- almost always wants the most recent mention, not the most lexically
-- relevant old one. Matches are still filtered by the FTS predicate, so
-- relevance determines inclusion; recency determines position.
-- Optional filters: kind, created_by. Date range is mandatory to bound the scan.
SELECT id, kind, created_by, content, metadata, entry_date, created_at
FROM agent_notes
WHERE search_vector @@ websearch_to_tsquery('simple', @query::text)
  AND entry_date >= @start_date
  AND entry_date <= @end_date
  AND (sqlc.narg('kind')::agent_note_kind IS NULL OR kind = sqlc.narg('kind')::agent_note_kind)
  AND (sqlc.narg('created_by')::text IS NULL OR created_by = sqlc.narg('created_by'))
ORDER BY entry_date DESC,
         created_at DESC,
         ts_rank(search_vector, websearch_to_tsquery('simple', @query::text)) DESC
LIMIT @row_limit::int;
