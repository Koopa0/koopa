-- Queries for the note package. See migrations/001_initial.up.sql for the
-- notes table. slug uniqueness is enforced by the UNIQUE constraint on
-- notes.slug; callers rely on pgerrcode 23505 → ErrConflict mapping.
-- note_kind / note_maturity are PostgreSQL ENUMs.

-- name: CreateNote :one
INSERT INTO notes (
    slug, title, body, kind, maturity, created_by, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $7
)
RETURNING id, slug, title, body, kind, maturity, created_by,
          metadata, created_at, updated_at;

-- name: NoteByID :one
SELECT id, slug, title, body, kind, maturity, created_by,
       metadata, created_at, updated_at
FROM notes
WHERE id = $1;

-- name: NoteBySlug :one
SELECT id, slug, title, body, kind, maturity, created_by,
       metadata, created_at, updated_at
FROM notes
WHERE slug = $1;

-- name: Notes :many
SELECT id, slug, title, body, kind, maturity, created_by,
       metadata, created_at, updated_at
FROM notes
WHERE (sqlc.narg('kind')::note_kind IS NULL OR kind = sqlc.narg('kind'))
  AND (sqlc.narg('maturity')::note_maturity IS NULL OR maturity = sqlc.narg('maturity'))
  AND (sqlc.narg('created_by')::text IS NULL OR created_by = sqlc.narg('created_by'))
ORDER BY updated_at DESC
LIMIT $1 OFFSET $2;

-- name: NotesCount :one
SELECT COUNT(*) FROM notes
WHERE (sqlc.narg('kind')::note_kind IS NULL OR kind = sqlc.narg('kind'))
  AND (sqlc.narg('maturity')::note_maturity IS NULL OR maturity = sqlc.narg('maturity'))
  AND (sqlc.narg('created_by')::text IS NULL OR created_by = sqlc.narg('created_by'));

-- name: UpdateNote :one
-- Editable fields only. Maturity is intentionally separated — use
-- UpdateNoteMaturity so maturity transitions are distinct from body/title
-- edits.
UPDATE notes SET
    slug = COALESCE(sqlc.narg('slug'), slug),
    title = COALESCE(sqlc.narg('title'), title),
    body = COALESCE(sqlc.narg('body'), body),
    kind = COALESCE(sqlc.narg('kind')::note_kind, kind),
    metadata = COALESCE(sqlc.narg('metadata'), metadata),
    updated_at = now()
WHERE id = $1
RETURNING id, slug, title, body, kind, maturity, created_by,
          metadata, created_at, updated_at;

-- name: UpdateNoteMaturity :one
-- Transitions maturity explicitly. Any transition is permitted (including
-- → archived and recovery from archived); maturity is not a one-way state
-- machine at the schema level.
UPDATE notes SET
    maturity = @maturity::note_maturity,
    updated_at = now()
WHERE id = @id
RETURNING id, slug, title, body, kind, maturity, created_by,
          metadata, created_at, updated_at;

-- name: DeleteNote :execrows
DELETE FROM notes WHERE id = $1;

-- name: SearchNotes :many
-- FTS over notes.search_vector (title weight A, body weight C). Returns
-- relevance-ranked rows capped by LIMIT. Query terms are websearch-style —
-- quotes and OR/- operators work. Used by the MCP search_knowledge tool to
-- union note hits with content hits.
SELECT id, slug, title, body, kind, maturity, created_by,
       metadata, created_at, updated_at,
       ts_rank(search_vector, websearch_to_tsquery('simple', @query)) AS rank
FROM notes
WHERE search_vector @@ websearch_to_tsquery('simple', @query)
ORDER BY rank DESC
LIMIT @max_results;

-- name: InternalSemanticSearchNotes :many
-- Semantic search over notes via pgvector cosine distance — the vector
-- counterpart of SearchNotes, feeding the hybrid RRF merge in
-- search_knowledge. No maturity filter: every note (archived included)
-- is reachable through FTS, and the semantic branch mirrors that
-- visibility. Notes without embeddings are skipped.
SELECT id, slug, title, body, kind, maturity, created_by,
       metadata, created_at, updated_at,
       (1 - (embedding <=> @target_embedding::vector))::float8 AS similarity
FROM notes
WHERE embedding IS NOT NULL
ORDER BY embedding <=> @target_embedding::vector
LIMIT @max_results;

-- name: NotesMissingEmbedding :many
-- Rows the embedding reconciler still has to process. No maturity filter —
-- archived notes stay searchable (SearchNotes does not exclude them), so
-- they get embeddings too. Oldest first so a backfill progresses
-- deterministically.
SELECT id, title, body
FROM notes
WHERE embedding IS NULL
ORDER BY created_at
LIMIT $1;

-- name: SetNoteEmbedding :exec
-- Persist a derived embedding. updated_at is deliberately untouched: the
-- embedding derives from title/body and carries no edit, and the admin
-- notes list orders by updated_at — a background re-embed must not make
-- notes look freshly edited. The notes audit trigger fires only on
-- INSERT, so this write produces no activity_events row.
UPDATE notes SET embedding = $2 WHERE id = $1;
